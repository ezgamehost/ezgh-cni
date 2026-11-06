# ezgh-cni

The VPC CNI for EZGH Kubernetes, the counterpart of amazon-vpc-cni-k8s: every pod gets a real
IPv4 and IPv6 address from the node's VPC subnet, out of prefixes delegated to the node's private
network interface, so pods are reachable from the VPC with no overlay and no NAT. It also enforces
Kubernetes NetworkPolicy on each node with nftables.

One binary, `ezgh-vpc-cni`, in the `vpc-cni` image, run by the vpc-cni add-on's DaemonSet:

| Mode | Job |
| --- | --- |
| CNI plugin (containerd runs it with `CNI_COMMAND` set and no arguments) | Pod veths with fixed MACs, routes and rules; addresses from ipamd |
| `install` | Init container: copies `ezgh-vpc-cni` and upstream `portmap` (hostPort) to the node's CNI directory |
| `ipamd` | Address management: assigns and releases delegated prefixes through the EZGH network API with the node's instance credentials (from the metadata service), writes the conflist, keeps table `inet ezgh_cni`, holds the pod identity agent's link-local address |
| `policy` | NetworkPolicy agent: watches Pods, Namespaces and NetworkPolicies and keeps table `inet ezgh_policy` |

It reads the node's join facts from `/etc/kubernetes/ezgh/join.json`. Logs are JSON lines through
the vendored kit (`internal/kit/logging`).

## Build and test

Go 1.27.1 (`go.mod`).

| Check | Command |
| --- | --- |
| Build | `CGO_ENABLED=0 GOOS=linux go build ./cmd/ezgh-vpc-cni` |
| Image | `docker build .` (Debian with nftables, plus upstream portmap at the containernetworking/plugins version `go.mod` pins) |
| Tests | `go test -race $(go list ./... \| grep -v /internal/kit/)` |
| Kernel tests | `scripts/netns-test.sh` (build tag `netns`: veths, routes, rules, dummy links and nftables in throwaway network namespaces, as root in a Debian container: Apple `container` on a Mac, Docker elsewhere) |
| Lint | `gofmt -l .`, `go vet ./...`, `go vet -tags netns ./internal/cni/...`, `go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...` |
| Logging | `scripts/check-logging.sh` |

CI (`.github/workflows/ci.yml`) runs them, the kernel tests as root on a GitHub-hosted runner with
`EZGH_CNI_KERNEL_TESTS=required` (a skipped kernel test fails), and builds the image without pushing
it, on every pull request and push to main.

## Releases

Push a tag `vX.Y.Z` on main. `.github/workflows/release.yml` publishes the GitHub release
(`ezgh-vpc-cni-linux-{amd64,arm64}`, `SHA256SUMS`) and pushes the linux/amd64 image to the
kubernetes-addons Registry as `<host>/kubernetes/vpc-cni:<tag>`. That needs repository secret
`KUBERNETES_ADDONS_REGISTRY_KEY` (a platform-organization Bot key that can push to project
kubernetes-addons) and variable `KUBERNETES_ADDONS_REGISTRY_HOST` (`<hostId>.registry.ezghcloud.com`).
A published tag never moves: a fix ships as a new version.

kubernetes-stack's `vpc-cni` add-on bundle pins the image in its `images.json` (`vpc-cni`).

## Copied code

Other repositories' code is copied in, not imported, each copy with its own sync:

| Path | Source | Sync |
| --- | --- | --- |
| `internal/kit` | ezgamehost/service-template `kit/go` (commit in `internal/kit/KIT_VERSION`) | `scripts/sync-kit.sh` |
| `internal/nodeauth/{join.go,imds}` (the node's join facts and the metadata service client) | ezgamehost/kubernetes-stack (commit in `COPIES`) | `scripts/sync-copies.sh kubernetes-stack` |

## License

Apache-2.0 ([LICENSE](LICENSE)). Security reports: [SECURITY.md](SECURITY.md).
