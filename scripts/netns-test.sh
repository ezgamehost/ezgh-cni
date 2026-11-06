#!/usr/bin/env bash
# Runs the kernel tests (build tag netns) as root in a throwaway Debian with iproute2, nftables, procps:
# Apple container on a Mac, Docker elsewhere. CI's netns job runs the same tests with sudo instead.
# EZGH_CNI_KERNEL_TESTS=required turns a test that would skip into a failure. After
# databases-stack's deploy/node/test.sh.
#   scripts/netns-test.sh [packages...]   (default ./internal/cni/...; FLAGS="-test.run X" passes flags)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
pkgs=("$@"); [ ${#pkgs[@]} -gt 0 ] || pkgs=(./internal/cni/...)
case $(uname -m) in arm64|aarch64) arch=arm64 ;; *) arch=amd64 ;; esac
out=$(mktemp -d .netns-test.XXXXXX); trap 'rm -rf "$out"' EXIT
list=()
for pkg in $(go list -tags netns "${pkgs[@]}"); do
  [ -n "$(go list -tags netns -f '{{.TestGoFiles}}{{.XTestGoFiles}}' "$pkg" | tr -d '[]')" ] || continue
  rel=${pkg#github.com/ezgamehost/ezgh-cni/}
  bin=$(echo "$rel" | tr / _).test
  GOOS=linux GOARCH=$arch CGO_ENABLED=0 go test -tags netns -c -o "$out/$bin" "$pkg"
  list+=("$rel:$bin")
done
[ ${#list[@]} -gt 0 ] || { echo "no test packages in ${pkgs[*]}" >&2; exit 2; }
# Upstream portmap at go.mod's plugins version, for the hostPort test (the vpc-cni image ships it).
plugins=$(go list -m -f '{{.Version}}' github.com/containernetworking/plugins)
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go install -trimpath "github.com/containernetworking/plugins/plugins/meta/portmap@$plugins"
gobin=$(go env GOPATH)/bin; [ "$(go env GOOS)/$(go env GOARCH)" = "linux/$arch" ] || gobin=$gobin/linux_$arch
cp "$gobin/portmap" "$out/portmap"
script='set -e
apt-get update -qq && apt-get install -y -qq --no-install-recommends iproute2 nftables procps >/dev/null 2>&1
mount -o remount,rw /proc/sys  # the container mounts it read-only; the namespaces need their sysctls
# Apple container'"'"'s kernel has no dummy links: those tests skip here and run in CI.
if ip link add ezgh-probe type dummy 2>/dev/null; then ip link del ezgh-probe; else export EZGH_CNI_NO_DUMMY=1; fi
rc=0
for e in "$@"; do
  dir=${e%%:*}; bin=${e##*:}
  echo "== $dir"
  (cd "/src/$dir" && exec "/src/'"$out"'/$bin" -test.timeout 5m $FLAGS) || rc=1
done
exit $rc'
if command -v container >/dev/null; then run=(container run --cap-add ALL); else run=(docker run --privileged); fi
"${run[@]}" --rm --user root -e EZGH_CNI_KERNEL_TESTS=required -e FLAGS="${FLAGS:-}" -e EZGH_CNI_PORTMAP="/src/$out/portmap" -v "$PWD:/src" \
  --entrypoint sh mirror.gcr.io/library/debian:13-slim -c "$script" sh "${list[@]}"
