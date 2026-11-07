# The vpc-cni add-on's image (kubernetes-addons kubernetes/vpc-cni:<version>): ezgh-vpc-cni on
# Debian with nftables, which ipamd's base table and the policy agent load through `nft`, and
# upstream portmap (hostPort) at the containernetworking/plugins release go.mod pins, static.
# The install init container copies both to the node's /opt/cni/bin.
# Build context: the repository root.
FROM mirror.gcr.io/library/golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ezgh-vpc-cni ./cmd/ezgh-vpc-cni
RUN v=$(go list -m -f '{{.Version}}' github.com/containernetworking/plugins) \
 && CGO_ENABLED=0 GOBIN=/out go install -trimpath -ldflags="-s -w" github.com/containernetworking/plugins/plugins/meta/portmap@$v

FROM mirror.gcr.io/library/debian:13-slim
# ca-certificates: ipamd calls network-api over HTTPS (--no-install-recommends would leave the roots out).
RUN apt-get update && apt-get install -y --no-install-recommends nftables ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ezgh-vpc-cni /out/portmap /
ENTRYPOINT ["/ezgh-vpc-cni"]
