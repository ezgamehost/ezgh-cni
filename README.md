# ezgh-cni

Pod networking for [EZGH Kubernetes](https://docs.ezghcloud.com). Every pod gets its own IPv4 and
IPv6 address from the node's VPC subnet, so pods are directly reachable inside the VPC with no
overlay network and no address translation. The plugin also enforces Kubernetes NetworkPolicy on
every node.

EZGH Kubernetes installs and upgrades this component as the `vpc-cni` add-on. This repository holds
its source code; you don't need to deploy it yourself.

## Features

- **VPC-native addresses.** Pod addresses come from IPv4 /28 and IPv6 /80 prefixes delegated to the
  node's private network interface, assigned and released as pods come and go.
- **Internet egress.** IPv4 traffic leaving the VPC is translated to the node's address. IPv6 pod
  traffic stays within the VPC.
- **Metadata isolation.** Pods can't reach the instance metadata service.
- **NetworkPolicy.** Ingress and egress policies are compiled into nftables on each node.
- **hostPort.** Supported through the upstream `portmap` plugin.

## Components

One binary, `ezgh-vpc-cni`, runs in four modes:

| Mode | Purpose |
| --- | --- |
| CNI plugin | Invoked by containerd for each pod: creates the pod's interface, addresses and routes |
| `install` | Init container that installs `ezgh-vpc-cni` and `portmap` into the node's CNI directory |
| `ipamd` | Node daemon that manages delegated prefixes through the EZGH network API using the node's instance credentials, and writes the CNI configuration |
| `policy` | Node daemon that watches Pods, Namespaces and NetworkPolicies and keeps the node's nftables rules current |

The node's cluster details are read from `/etc/kubernetes/ezgh/join.json`. Logs are structured JSON.

## Container image and binaries

| Artifact | Location |
| --- | --- |
| Container image (linux/amd64) | `q5zljyjh52il.registry.ezghcloud.com/kubernetes/vpc-cni:<version>` |
| Binaries (linux/amd64, linux/arm64) with `SHA256SUMS` | [GitHub Releases](https://github.com/ezgamehost/ezgh-cni/releases) |

## Building from source

Requires Go 1.27.1 or later.

```sh
CGO_ENABLED=0 GOOS=linux go build ./cmd/ezgh-vpc-cni
docker build .
```

## Testing

| Check | Command |
| --- | --- |
| Unit tests | `go test -race $(go list ./... \| grep -v /internal/kit/)` |
| Kernel tests | `scripts/netns-test.sh` (runs as root in a Linux container, using throwaway network namespaces) |
| Lint | `gofmt -l .`, `go vet` and `staticcheck` |
| Logging | `scripts/check-logging.sh` |

Continuous integration runs all of these, including the kernel tests, on every pull request and
push to `main`.

## Releases

Releases follow semantic versioning. Pushing a `vX.Y.Z` tag on `main` publishes the container image
and then the binaries. Published versions are immutable; fixes ship as new versions.

## Vendored code

`internal/kit` and `internal/nodeauth` are vendored from shared EZGH libraries and refreshed with
`scripts/sync-kit.sh` and `scripts/sync-copies.sh`. Changes to them are made upstream.

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
