// Package boxsync moves credentials between this machine's vault and the vault
// on another dev box, over SSH.
//
// SSH authenticates the box and encrypts the hop. On top of it the two
// blindfold processes run their own exchange, so the remote helper's stdout
// never carries plaintext: an agent that runs `ssh box blindfold sync-serve`
// sees only ciphertext.
//
//	client (this machine)                       server (the box)
//	  hello {proto, version, X25519 pub}  ──▶
//	                                      ◀──  hello {proto, version, X25519 pub}
//	  keys = HKDF-SHA256(X25519 shared, salt = client pub ‖ server pub)
//	       → client→server key, server→client key, digest key
//	  sealed frame (XChaCha20-Poly1305, AAD = sequence number)  ◀──▶
package boxsync

import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ProtocolVersion changes whenever either end would misread the other.
const ProtocolVersion = 1

// hkdfInfo separates these keys from any other use of the same exchange.
const hkdfInfo = "blindfold sync v1"

// maxFrameSize bounds one line on the stream. A vault's worth of credentials
// is kilobytes; a box sending more is refused before it is buffered.
const maxFrameSize = 16 << 20

// ErrNoAnswer means the other end closed, or was never there, before the
// handshake finished. On a box it most often means blindfold is not where a
// non-interactive ssh session looks. Whether that shows as EOF or a broken
// pipe depends on timing; both are this.
var ErrNoAnswer = errors.New("no answer from blindfold sync-serve")

// hello is the one message sent in the clear: nothing in it is secret.
type hello struct {
	Proto   int    `json:"proto"`
	Version string `json:"version"`
	Pub     []byte `json:"pub"`
}

// Channel carries sealed JSON messages, one per line, over one stream.
//
// Each direction has its own key and its own sequence number, bound into every
// frame: a frame altered, replayed, reordered or sent back to its sender fails
// to open, and the session ends.
type Channel struct {
	r *bufio.Reader
	w io.Writer

	send, recv       cipher.AEAD
	sendSeq, recvSeq uint64
	digestKey        []byte
	// failed is the first frame that would not open; the session is over.
	failed error

	// PeerVersion is the blindfold version at the other end.
	PeerVersion string
}

// Open starts a session as the client: it speaks first.
func Open(r io.Reader, w io.Writer, version string) (*Channel, error) {
	return handshake(r, w, version, true)
}

// Accept answers a session as the server.
func Accept(r io.Reader, w io.Writer, version string) (*Channel, error) {
	return handshake(r, w, version, false)
}

func handshake(r io.Reader, w io.Writer, version string, client bool) (*Channel, error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(private); err != nil {
		return nil, err
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	c := &Channel{r: bufio.NewReader(r), w: w}
	mine := hello{Proto: ProtocolVersion, Version: version, Pub: public}
	var theirs hello
	// The client speaks first, so a server that never answers is the only wait.
	if client {
		err = c.exchange(mine, &theirs)
	} else {
		err = c.answer(mine, &theirs)
	}
	if err != nil {
		return nil, err
	}
	if theirs.Proto != ProtocolVersion {
		return nil, fmt.Errorf("sync protocol mismatch: this blindfold is %s (protocol %d), the other is %s (protocol %d); "+
			"install the same version on both", version, ProtocolVersion, theirs.Version, theirs.Proto)
	}
	c.PeerVersion = theirs.Version

	// X25519 refuses a low-order public key, which would fix the shared secret.
	shared, err := curve25519.X25519(private, theirs.Pub)
	if err != nil {
		return nil, fmt.Errorf("sync handshake: %w", err)
	}
	clientPub, serverPub := public, theirs.Pub
	if !client {
		clientPub, serverPub = theirs.Pub, public
	}
	if err := c.deriveKeys(shared, clientPub, serverPub, client); err != nil {
		return nil, err
	}
	return c, nil
}

// exchange sends our hello, then reads theirs.
func (c *Channel) exchange(mine hello, theirs *hello) error {
	if err := c.writeJSON(mine); err != nil {
		return err
	}
	return c.readJSON(theirs)
}

// answer reads their hello, then sends ours — even on a version mismatch, so
// the client can name both versions.
func (c *Channel) answer(mine hello, theirs *hello) error {
	if err := c.readJSON(theirs); err != nil {
		return err
	}
	return c.writeJSON(mine)
}

func (c *Channel) deriveKeys(shared, clientPub, serverPub []byte, client bool) error {
	salt := append(append([]byte{}, clientPub...), serverPub...)
	kdf := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo))
	keys := make([][]byte, 3) // client→server, server→client, digest
	for i := range keys {
		keys[i] = make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(kdf, keys[i]); err != nil {
			return err
		}
	}
	toServer, err := chacha20poly1305.NewX(keys[0])
	if err != nil {
		return err
	}
	toClient, err := chacha20poly1305.NewX(keys[1])
	if err != nil {
		return err
	}
	c.send, c.recv = toServer, toClient
	if !client {
		c.send, c.recv = toClient, toServer
	}
	c.digestKey = keys[2]
	return nil
}

// Send seals one message.
func (c *Channel) Send(v any) error {
	if c.failed != nil {
		return c.failed
	}
	plaintext, err := json.Marshal(v)
	if err != nil {
		return err
	}
	nonce := make([]byte, c.send.NonceSize(), c.send.NonceSize()+len(plaintext)+c.send.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	frame := c.send.Seal(nonce, nonce, plaintext, sequenceAAD(c.sendSeq))
	line := base64.StdEncoding.EncodeToString(frame) + "\n"
	if len(line) > maxFrameSize {
		return errTooLargeToSend
	}
	c.sendSeq++
	_, err = io.WriteString(c.w, line)
	return err
}

// errFrame ends a session whose next frame does not open. Its contents are
// never quoted.
var errFrame = errors.New("sync: a frame failed to authenticate; the session was altered in transit")

var errFrameTooLarge = fmt.Errorf("sync: a frame is larger than %d bytes; the session was ended", maxFrameSize)

// errTooLargeToSend refuses a message the other end would refuse, before any
// of it is written. Values are base64 twice over, so ~9 MiB of them fill one.
var errTooLargeToSend = fmt.Errorf("sync: this request is over %d bytes once encoded; send fewer or smaller entries",
	maxFrameSize)

// Receive opens the next message into v. A frame that will not open ends the
// session: every later Send and Receive returns the same error.
func (c *Channel) Receive(v any) error {
	if c.failed != nil {
		return c.failed
	}
	line, err := c.readLine()
	if errors.Is(err, errFrameTooLarge) {
		c.failed = err
	}
	if err != nil {
		return err
	}
	frame, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(line, "\n"))
	if err != nil || len(frame) < c.recv.NonceSize() {
		c.failed = errFrame
		return errFrame
	}
	nonce, sealed := frame[:c.recv.NonceSize()], frame[c.recv.NonceSize():]
	plaintext, err := c.recv.Open(nil, nonce, sealed, sequenceAAD(c.recvSeq))
	if err != nil {
		c.failed = errFrame
		return errFrame
	}
	c.recvSeq++
	return json.Unmarshal(plaintext, v)
}

// Digest is a keyed hash of data under this session's digest key. Both ends
// compute the same digest of the same bytes, so secrets compare without
// crossing; a digest says nothing outside its session.
func (c *Channel) Digest(data []byte) []byte {
	mac := hmac.New(sha256.New, c.digestKey)
	mac.Write(data)
	return mac.Sum(nil)
}

func sequenceAAD(seq uint64) []byte { return binary.BigEndian.AppendUint64(nil, seq) }

// readLine reads one line, refusing it once it outgrows maxFrameSize.
func (c *Channel) readLine() (string, error) {
	var line strings.Builder
	for {
		chunk, err := c.r.ReadSlice('\n')
		if line.Len()+len(chunk) > maxFrameSize {
			return "", errFrameTooLarge
		}
		line.Write(chunk)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		return line.String(), nil
	}
}

func (c *Channel) writeJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("%w (%v)", ErrNoAnswer, err)
	}
	return nil
}

func (c *Channel) readJSON(v any) error {
	line, err := c.readLine()
	if errors.Is(err, errFrameTooLarge) {
		return err
	}
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrNoAnswer, err)
	}
	// A shell startup file that prints is the usual culprit: its text arrives
	// where the hello should.
	if err := json.Unmarshal([]byte(line), v); err != nil {
		return errors.New("sync handshake: the other end did not answer as blindfold sync-serve; " +
			"if it is a box, check that its shell startup files print nothing in a non-interactive session")
	}
	return nil
}
