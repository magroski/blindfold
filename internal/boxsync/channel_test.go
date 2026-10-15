package boxsync

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

const testSecret = "sk-live-not-for-the-wire"

type message struct {
	Text string `json:"text"`
}

// connect runs both ends of a handshake over in-memory pipes and returns the
// client and server channels, with every byte the client sent recorded.
func connect(t *testing.T, clientVersion, serverVersion string) (*Channel, *Channel, *bytes.Buffer) {
	t.Helper()
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	var wire bytes.Buffer
	clientOut := io.MultiWriter(&wire, fromClient) // recorded before the server can read it

	type result struct {
		ch  *Channel
		err error
	}
	server := make(chan result, 1)
	go func() {
		ch, err := Accept(toServer, fromServer, serverVersion)
		server <- result{ch, err}
	}()
	client, err := Open(toClient, clientOut, clientVersion)
	s := <-server
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if s.err != nil {
		t.Fatalf("server handshake: %v", s.err)
	}
	t.Cleanup(func() { fromClient.Close(); fromServer.Close() })
	return client, s.ch, &wire
}

func TestChannelRoundTrip(t *testing.T) {
	client, server, wire := connect(t, "v1", "v1")

	go func() { _ = client.Send(message{Text: testSecret}) }()
	var got message
	if err := server.Receive(&got); err != nil || got.Text != testSecret {
		t.Fatalf("server received %+v, %v", got, err)
	}
	go func() { _ = server.Send(message{Text: "reply"}) }()
	if err := client.Receive(&got); err != nil || got.Text != "reply" {
		t.Fatalf("client received %+v, %v", got, err)
	}
	if strings.Contains(wire.String(), testSecret) {
		t.Error("the value crossed the wire in plaintext")
	}
}

// frames captures what one end sends, so a test can deliver it altered.
func frames(t *testing.T, ch *Channel, msgs ...message) []string {
	t.Helper()
	var buf bytes.Buffer
	ch.w = &buf
	for _, m := range msgs {
		if err := ch.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	return strings.SplitAfter(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

// deliver makes ch read exactly these lines next.
func deliver(ch *Channel, lines ...string) {
	ch.r = bufio.NewReader(strings.NewReader(strings.Join(lines, "")))
}

func TestChannelRejectsAlteredFrames(t *testing.T) {
	cases := map[string]func(client, server *Channel) []string{
		"tampered": func(client, _ *Channel) []string {
			f := []byte(frames(t, client, message{Text: testSecret})[0])
			f[10] ^= 'A' ^ 'B'
			return []string{string(f)}
		},
		"replayed": func(client, _ *Channel) []string {
			f := frames(t, client, message{Text: "once"})[0]
			return []string{f, f}
		},
		"reordered": func(client, _ *Channel) []string {
			f := frames(t, client, message{Text: "first"}, message{Text: "second"})
			return []string{f[1], f[0]}
		},
		"reflected": func(_, server *Channel) []string {
			return frames(t, server, message{Text: "server's own"})
		},
	}
	for name, altered := range cases {
		t.Run(name, func(t *testing.T) {
			client, server, _ := connect(t, "v1", "v1")
			lines := altered(client, server)
			deliver(server, lines...)

			var got message
			var err error
			for range lines {
				if err = server.Receive(&got); err != nil {
					break
				}
			}
			if err == nil {
				t.Errorf("every frame was accepted; last: %+v", got)
			}
		})
	}
}

// A frame that fails to open ends the session: a valid frame after it is
// refused, and nothing more is sent.
func TestChannelEndsAfterABadFrame(t *testing.T) {
	client, server, _ := connect(t, "v1", "v1")
	good := frames(t, client, message{Text: "after garbage"})[0]
	deliver(server, "garbage\n", good)

	var got message
	if err := server.Receive(&got); err == nil {
		t.Fatal("garbage was accepted")
	}
	if err := server.Receive(&got); err == nil {
		t.Errorf("a frame after a bad one was accepted: %+v", got)
	}
	server.w = &bytes.Buffer{} // nothing reads the pipe: a send must not block
	if err := server.Send(message{Text: "still here"}); err == nil {
		t.Error("the session sent after a bad frame")
	}
}

// Both ends derive the same digest of the same bytes; another session derives
// a different one, so a digest read off one session says nothing elsewhere.
func TestChannelDigest(t *testing.T) {
	client, server, _ := connect(t, "v1", "v1")
	if !bytes.Equal(client.Digest([]byte("x")), server.Digest([]byte("x"))) {
		t.Error("the two ends disagree on a digest")
	}
	if bytes.Equal(client.Digest([]byte("x")), client.Digest([]byte("y"))) {
		t.Error("different inputs share a digest")
	}
	other, _, _ := connect(t, "v1", "v1")
	if bytes.Equal(client.Digest([]byte("x")), other.Digest([]byte("x"))) {
		t.Error("two sessions share a digest key")
	}
}

func TestChannelProtocolMismatch(t *testing.T) {
	toServer, fromClient := io.Pipe()
	toClient, fromServer := io.Pipe()
	defer fromClient.Close()
	defer fromServer.Close()

	go func() {
		// A future server that speaks another protocol.
		_, _ = bufio.NewReader(toServer).ReadString('\n')
		_, _ = fromServer.Write([]byte(`{"proto":99,"version":"v9","pub":"AAAA"}` + "\n"))
	}()
	_, err := Open(toClient, fromClient, "v1")
	if err == nil || !strings.Contains(err.Error(), "v9") || !strings.Contains(err.Error(), "v1") {
		t.Errorf("Open = %v, want a mismatch naming both versions", err)
	}
}
