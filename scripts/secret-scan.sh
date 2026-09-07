#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

files=$(git ls-files --cached --others --exclude-standard | grep -v '^scripts/secret-scan.sh$')
test -n "$files"
tracked_files=$(git ls-files)
if printf '%s\n' "$tracked_files" | grep -Eq '^(outputs|credentials|account|rollback|state|release|dist)(/|$)|\.(db|db-wal|db-shm|sqlite|sqlite3|pem|key|csr|p12|pfx|log)$'; then
	echo 'secret-scan: forbidden runtime or release artifact is tracked' >&2
	exit 1
fi
non_test_files=$(printf '%s\n' "$files" | grep -Ev '(^|/).*_test\.go$')
test -n "$non_test_files"

if printf '%s\n' "$files" | xargs grep -nE -- \
  'AKIA[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{30,}|sk-(proj-)?[A-Za-z0-9_-]{24,}|mysql://[^[:space:]]+:[^[:space:]@]+@|[A-Za-z0-9_.-]+:[A-Za-z0-9+/_.-]{8,}@tcp\(|X-Edge-Access-Token:[[:space:]]*[A-Za-z0-9+/_.-]{12,}'; then
	echo 'secret-scan: possible credential material found' >&2
	exit 1
fi

if printf '%s\n' "$non_test_files" | xargs grep -nE -- \
  '-----BEGIN ([A-Z0-9 ]*PRIVATE KEY|CERTIFICATE|CERTIFICATE REQUEST)-----'; then
	echo 'secret-scan: unexpected PEM material found' >&2
	exit 1
fi

if printf '%s\n' "$files" | grep -Ev '(^|/)(go.sum|.*_test.go)$|^docs/SECURITY.md$' | \
  xargs grep -nE -- '[A-Za-z0-9+/]{120,}={0,2}'; then
  echo 'secret-scan: unexpected high-entropy blob found' >&2
  exit 1
fi

if printf '%s\n' "$non_test_files" | xargs grep -nE -- '/Users/[^/[:space:]]+|/home/[^/[:space:]]+'; then
	echo 'secret-scan: local absolute path found' >&2
	exit 1
fi

echo 'secret-scan: PASS'
