#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="v1.0.0"

python3 scripts/prepare-v1.0.0.py

grep -F 'readonly RELEASE_TAG="v1.0.0"' install.sh >/dev/null
grep -F 'const version = "v1.0.0"' cmd/goedge-ip-cert/main.go >/dev/null
grep -F 'prerelease == false' install.sh >/dev/null
grep -F '点击一次「保存」（无需提前选择证书）' install.sh >/dev/null
if grep -q 'Status: Preview' README.md; then
  echo 'Preview status remained in README' >&2
  exit 1
fi

go mod verify
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...

if ! command -v shellcheck >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq shellcheck
fi
shellcheck -S warning install.sh tests/installer_test.sh scripts/secret-scan.sh
bash tests/installer_test.sh
sh scripts/secret-scan.sh

go install golang.org/x/vuln/cmd/govulncheck@latest
"$(go env GOPATH)/bin/govulncheck" ./...

# Keep the stable source clean: remove one-shot release automation/helpers before committing/tagging.
git rm -f \
  .github/workflows/release-v1.0.0.yml \
  .github/workflows/release-v1-stable.yml \
  .github/workflows/smoke.yml \
  .release-v1.0.0-trigger \
  scripts/prepare-v1.0.0.py \
  scripts/release-v1.0.0.sh

git add cmd/goedge-ip-cert/main.go install.sh README.md docs/INSTALL.md CHANGELOG.md tests/installer_test.sh
git diff --cached --check

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git commit -m 'release: v1.0.0 stable'
git push origin HEAD:main

rm -rf dist
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/goedge-ip-cert-linux-amd64 ./cmd/goedge-ip-cert
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/goedge-ip-cert-linux-arm64 ./cmd/goedge-ip-cert
cp install.sh dist/install.sh
chmod 0755 dist/install.sh dist/goedge-ip-cert-linux-amd64 dist/goedge-ip-cert-linux-arm64

test "$(dist/goedge-ip-cert-linux-amd64 version)" = "$VERSION"
test "$(GOEDGE_IP_CERT_SOURCE_ONLY=0 dist/install.sh --version)" = "$VERSION"
(
  cd dist
  sha256sum goedge-ip-cert-linux-amd64 goedge-ip-cert-linux-arm64 install.sh > SHA256SUMS
  sha256sum -c SHA256SUMS
)

if git rev-parse "refs/tags/$VERSION" >/dev/null 2>&1; then
  echo "$VERSION already exists; refusing to rewrite it" >&2
  exit 1
fi

git tag -a "$VERSION" -m "GoEdge IPv4 Cert Manager $VERSION"
git push origin "$VERSION"

cat > /tmp/goedge-ip-cert-v1-release-notes.md <<'EOF'
GoEdge IPv4 Cert Manager v1.0.0 is the first Stable release.

Highlights:
- Let's Encrypt public IPv4 certificates using the ACME `ip` identifier, `shortlived` profile and HTTP-01.
- Same-Cert-ID automatic renewal through GoEdge REST.
- Production unattended natural renewal proven with unchanged SSL Policy, isolated Node refresh and no order storm.
- First-issuance failures pause in `NEEDS_ATTENTION`; the hourly timer does not repeat first-issuance orders.
- Menu 2 now explains that a newly created GoEdge IP website may need HTTPS / 443 saved once before discovery; no certificate needs to be selected before that save.
- Stable updater ignores prereleases.

Scope remains IPv4-only. First certificate binding to the GoEdge SSL Policy is manual by design; Cert Manager keeps the Policy boundary read-only.
EOF

gh release create "$VERSION" \
  dist/goedge-ip-cert-linux-amd64 \
  dist/goedge-ip-cert-linux-arm64 \
  dist/install.sh \
  dist/SHA256SUMS \
  --repo "$GITHUB_REPOSITORY" \
  --title 'v1.0.0 - Stable' \
  --notes-file /tmp/goedge-ip-cert-v1-release-notes.md \
  --latest

summary=$(gh release view "$VERSION" --repo "$GITHUB_REPOSITORY" --json isPrerelease,isDraft,tagName --jq '.tagName + " " + (.isPrerelease|tostring) + " " + (.isDraft|tostring)')
test "$summary" = 'v1.0.0 false false'

rm -rf /tmp/goedge-ip-cert-v1-assets
mkdir -p /tmp/goedge-ip-cert-v1-assets
gh release download "$VERSION" --repo "$GITHUB_REPOSITORY" --dir /tmp/goedge-ip-cert-v1-assets
(
  cd /tmp/goedge-ip-cert-v1-assets
  sha256sum -c SHA256SUMS
)

echo "V1_0_0_STABLE_RELEASE_PASS"
