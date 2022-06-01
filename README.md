# BPF PortScan

There are three parts to this project:

- `bpf_kern_bloc.c` is the BPF(XDP) program 
  - performs limited parsing of incoming network packet metadata
  - for TCP packets, stores up to 3 distinct ports in a BPF map `pscan_ip_reg`
  - DROPs the packets if more than 3 distinct ports are present in the `pscan_ip_reg` for particular IP address
  - tracks stats, like counters for various actions and size of the registry, in BPF map `pscan_stats`
- `main.go` / `cmd/main.go` is a small go program that exposes `pscan_stats` BPF map as Prometheus endpoint 
- `portscan_expire_registry.sh` runs in userspace and evicts non-blocked IP addresses from `pscan_ip_reg` that are older than 60 seconds
  - BTF allows exposure of maps output in JSON from `bpftool`
  - but CRUD-ish operations get tricky since map keys are expected to be encoded

Other things in the repo:
- `Dockerfile` to assemble the entire project into a docker container
- `test/` contains integration tests
- `config/` contains the prometheuis metrics exporter config

### Installation

Tested/developed on fresh install of Ubuntu Server 22.04. BPF part requires specific kernel headers, so currently compilation
of BPF part has been tested on Linux.

- Install make `sudo apt install make`
- clone the repo `git clone https://github.com/dilchenko/bpf_portscan.git`\
- `cd bpf_portscan`
- `sudo make linux_deps`

To compile the BPF part:
- `make clean`
- `make all`

To compile Golang part:
- `make pscan_stats`

### Test

To run tests, a `veth` interface is created. The BPF program is then compiled and attached as XDP on the `veth` device. The tests generate some TCP traffic to `veth` and inspect the state of `pscan_ip_reg` BPF map using `bpftool`.

You can invoke `sudo make test` to perform the compilation, `veth` setup and run go tests. Or `sudo make run_tests` to just invoke go tests.

### Build docker

To build docker image, you need docker locally. As configured, the docker build invokes compilation of BPF and Golang parts.
Invoke `make docker_build` on a linux host to compile everything and build the image. Depending on your system config, you might need to run with sudo, e.g. `sudo make docker_build`.

### Run docker

Since we need access to BPF maps, host IP net namespace, etc., running docker container requires specific arguments.
Docker container loads BFP into XDP on the host system. It also attaches it to an interface on the host system,
`veth-pscan-test` by default.

Invoke `sudo make docker_run` on a linux host to run the container. 

To override the interface name that it attaches to, pass `NET_IF_NAME` to the `make` command (e.g. `make docker_run NET_IF_NAME=eth0`).  **WARNING**: attaching on a real interface could lock you out of the host if you are SSHed via the same network interface.  

Docker container exposes custom prometheus endpoint via `:7979`. Once the container is running, run `curl "http://localhost:7979/probe?module=default"` to access prometheus endpoint.

`portscan_expire_registry.sh` runs as a crontask every minute inside the docker container. 

#### Various bits

As it stands, XDP is compiled with debug, which means debug traces are written into ringbuffer. It can be accessed like this:

```shell
# to enable tracing: sudo trace-cmd restart
# <load and attach the XDP>
sudo trace-cmd show
# to clear: sudo trace-cmd clear
# to disable tracing: sudo trace-smd stop
```

To stress-test the setup, `hping3` can be used (WARNING: this generates A LOT of packets with spoofed IPs):

```shell
ip netns exec veth-pscan-test hping3 -S 10.11.1.1 --rand-source -p ++1024 -c 100 --flood -V
```

You can dump bpf maps in usersapce in JSON (because maps have BTF):

```shell
# to see encoded keys/values, add "-p"
bpftool map dump name pscan_ip_reg
bpftool map dump name pscan_stats
```

Unblock an IP by removing the key from the `pscan_ip_reg`:

```shell
# bpftool map dump name pscan_ip_reg -p
[{
        "key": ["0x0a","0xd3","0x37","0x04"   <<-----------------------
        ],
        "value": ["0x00","0x00","0x00","0x00","0x01","0x47","0x5d","0x20","0xb2","0x81","0xde","0x15","0x6b","0x0a","0x00","0x00","0x01","0x28","0x00","0x00","0x16","0x00","0x00","0x00","0x02","0x28","0x00","0x00","0x20","0x65","0x78","0x73"
        ],
        "formatted": {
            "key": 70767370,
            "value": {
                "bpf_lock": {
                    "val": 0
                },
                "blocked": 1,
                "packet_timestamp": 11455044682162,
                "port1": 10241,
                "port2": 22,
                "port3": 10242
            }
        }
    },{
...
```

```shell
bpftool map delete name pscan_ip_reg key hex 0a d3 37 04
```

BTF requires kernel support, check via `grep CONFIG_DEBUG_INFO_BTF_MODULES /boot/config-$(uname -r)`.
