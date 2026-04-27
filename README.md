# tcp-brutal

`tcp-brutal` is a Go package for loading the TCP Brutal eBPF congestion control program. It embeds a BPF object and installs the `brutal` TCP congestion control algorithm with a cgroup `setsockopt` hook. The Go loader uses only the standard library and raw `bpf(2)` syscalls.

## Requirements

- Linux 6.10 or newer with kernel BTF at `/sys/kernel/btf/vmlinux`
- BPF `struct_ops` TCP congestion control support
- cgroup v2 mounted at `/sys/fs/cgroup`
- socket local storage and cgroup sockopt hook support
- `clang`, `bpftool`, Linux 6.10+ kernel headers and Go

## Build

Generate `vmlinux.h`, compile the little-endian BPF object, then build the Go package or optional CLI:

```bash
apt install bpftool libbpf-dev clang

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -g -O2 -Wall -Werror -Wno-missing-declarations -target bpfel \
  -I"/lib/modules/$(uname -r)/build/tools/bpf/resolve_btfids/libbpf/include" \
  -I"/lib/modules/$(uname -r)/build/include/generated/uapi" \
  -I"/lib/modules/$(uname -r)/build/include/uapi" \
  -c brutal.c -o "brutal_linux_bpfel.o"

go build -trimpath -o brutal ./cmd/brutal
```

Use `-target bpfeb` and output `brutal_linux_bpfeb.o` instead when building for a big-endian Linux target. The Go package loads `brutal_linux_bpfel.o` or `brutal_linux_bpfeb.o` according to the host byte order. The matching object must exist before building any package or binary that imports `github.com/phuslu/tcp-brutal`; build it against kernel BTF that contains the TCP structures and callbacks used by `brutal.c`. The loader applies CO-RE field relocations against the target kernel BTF at runtime.

## Package API

```go
package main

import (
	"log"

	brutal "github.com/phuslu/tcp-brutal"
)

func main() {
	if err := brutal.Load(); err != nil {
		log.Fatal(err)
	}
}
```

`Load()` reads `/proc/sys/net/ipv4/tcp_available_congestion_control`. If `brutal` is already available, it returns nil without touching existing BPF state. Otherwise, it loads and pins the eBPF programs with the default cgroup and fixed bpffs pin paths.

Advanced callers can use:

```go
err := brutal.Options{
	CgroupPath: "/sys/fs/cgroup",
	Force:      true,
}.Load()
```

The loader pins BPF objects at `/sys/fs/bpf/brutal_cc` and `/sys/fs/bpf/brutal_setsockopt`. `Force` only cleans stale pins when `brutal` is not already available. `Unload()` and `UnloadWithOptions()` remove the BPF state pinned by this package.

## CLI

Load:

```bash
sudo ./brutal load --force
```

Unload:

```bash
sudo ./brutal unload
```

Options:

```text
load   [--cgroup PATH] [--force] [--foreground]
unload [--cgroup PATH]
```

Check registration with `/proc/sys/net/ipv4/tcp_available_congestion_control`. `/proc/sys/net/ipv4/tcp_congestion_control` is only the system default algorithm and does not change just because `brutal` was loaded.

## Application API

Enable TCP Brutal on a socket:

```python
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, b"brutal")
```

Set the target send rate and CWND gain:

```python
import socket
import struct

TCP_BRUTAL_PARAMS = 23301

rate = 2_000_000
cwnd_gain = 15
s.setsockopt(socket.IPPROTO_TCP, TCP_BRUTAL_PARAMS, struct.pack("QI", rate, cwnd_gain))
```

`rate` is bytes per second. `cwnd_gain` is expressed in tenths, so `15` means `1.5x`.
