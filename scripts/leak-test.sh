#!/usr/bin/env bash
#
# The test that proves the product claim.
#
# Everything else — unit tests, quoting checks, validation — verifies a
# mechanism. This verifies the outcome: after a real agent session that really
# used a credential, the credential is nowhere in the transcript that session
# wrote to disk.
#
# It deliberately checks the transcript rather than the command output, because
# the transcript is what persists, what gets grepped months later, and what was
# sent to a model provider.
#
# Usage: scripts/leak-test.sh
# Requires: docker, psql, claude, and blindfold on PATH.

set -euo pipefail

readonly PASSWORD='ro-agent-passw0rd!'
readonly PORT=55439
readonly CONTAINER=sa-leak-test
readonly PROJECT_SLUG="${HOME}/.claude/projects/$(pwd | tr '/.' '--')"

WORKDIR="$(mktemp -d)"
export BLINDFOLD_DIR="${WORKDIR}/vault"
export BLINDFOLD_KEK_FILE="${WORKDIR}/vault/kek"

cleanup() {
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT

echo "==> starting a disposable postgres"
docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
docker run -d --name "${CONTAINER}" \
  -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=analytics \
  -p "${PORT}:5432" postgres:16-alpine >/dev/null

for _ in $(seq 1 60); do
  docker exec "${CONTAINER}" pg_isready -U postgres >/dev/null 2>&1 && break
  sleep 1
done

docker exec "${CONTAINER}" psql -U postgres -d analytics -q -c "
  create table candidates(id bigserial primary key, email text);
  insert into candidates(email) select 'user'||g||'@example.com' from generate_series(1,42) g;
  create role ro_agent login password '${PASSWORD}';
  grant connect on database analytics to ro_agent;
  grant usage on schema public to ro_agent;
  grant select on all tables in schema public to ro_agent;"

echo "==> storing the credential"
blindfold init >/dev/null
printf '%s' "postgres://ro_agent:${PASSWORD}@127.0.0.1:${PORT}/analytics?sslmode=disable" |
  blindfold add pg-leak-test --secret DATABASE_URL \
    --describe "Read-only replica used by the leak test." >/dev/null

echo "==> running a real agent session against it"
# A known session id scopes the check to this run: other live sessions in the
# project hold this script, password included, and would read as leaks.
session_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"

claude --session-id "${session_id}" --plugin-dir . -p \
  "How many rows are in the candidates table, and what columns does it have?
   Use the pg-leak-test credential from blindfold." \
  --allowedTools "Bash" \
  >/dev/null

# The session's transcript, and its subagents' under <session>/subagents/.
transcripts=()
while IFS= read -r -d '' file; do
  transcripts+=("${file}")
done < <(find "${PROJECT_SLUG}" -name '*.jsonl' \( -path "${PROJECT_SLUG}/${session_id}.jsonl" \
  -o -path "${PROJECT_SLUG}/${session_id}/*" \) -print0 2>/dev/null)

if (( ${#transcripts[@]} == 0 )); then
  echo "FAIL: no new transcript was written, so there is nothing to check." >&2
  exit 1
fi

echo "==> checking ${#transcripts[@]} transcript(s)"
printf '    %s\n' "${transcripts[@]}"
python3 - "${PASSWORD}" "${transcripts[@]}" <<'PY'
import base64, json, sys, urllib.parse

password, paths = sys.argv[1], sys.argv[2:]
blob = "".join(open(path, "rb").read().decode("utf-8", "replace") for path in paths)

# A test that passes because the agent never used the credential proves nothing.
if "blindfold exec" not in blob and "blindfold env" not in blob:
    sys.exit("FAIL: the session never loaded the credential, so this run proves nothing.")

variants = {
    "literal":        password,
    "url-quoted":     urllib.parse.quote(password, safe=""),
    "url-quote-plus": urllib.parse.quote_plus(password),
    "base64":         base64.b64encode(password.encode()).decode(),
    "base64-url":     base64.urlsafe_b64encode(password.encode()).decode(),
    "json-escaped":   json.dumps(password)[1:-1],
}

leaked = False
for name, value in variants.items():
    hits = blob.count(value)
    if hits:
        leaked = True
    print(f"  {name:16} {'LEAK' if hits else 'clean':6} ({hits} hits)")

if leaked:
    sys.exit("\nFAIL: the credential reached the transcript.")
print("\nPASS: the agent used the credential; it appears nowhere in the transcript.")
PY
