CLANG ?= clang
LLC ?= llc
UNAME := $(shell uname)

KERNEL_VERSION := $(shell uname -r)
KERNEL_VERSION_SHORT := $(shell uname -r | sed 's/-generic//')
KERNEL_INCLUDE_PATH = /usr/src/linux-headers-$(KERNEL_VERSION)/include

XDP_TARGETS := bpf_kern_block
XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

NET_IF_NAME ?= veth-pscan-test
BPF_O_PATH ?= .
BPF_O_FILE ?= bpf_kern_block.o
BPF_NAME ?= xdp_port_scan_block

XDP_TUTORIAL_PATH ?= /tmp/xdp_tutorial
TEST_NETNS_NAME ?= $(NET_IF_NAME)

DOCKER_DNS_OVERWRITE ?= --dns 192.168.1.1

linux_deps:
	apt-get install linux-tools-common linux-tools-generic linux-tools-`uname -r` \
	linux-headers-generic linux-headers-`uname -r` libbpf libbpf-dev \
	clang make trace-cmd iproute2 tcpdump hping3 golang-go git
	# echo 1 > /proc/sys/net/netfilter/nf_log_all_netns
	# sysctl -w net.ipv6.conf.all.disable_ipv6=0

clone_xdp_tutorial:
	{ [ ! -d "$(XDP_TUTORIAL_PATH)" ] && git clone https://github.com/xdp-project/xdp-tutorial.git $(XDP_TUTORIAL_PATH) } || true

test_if_create: clone_xdp_tutorial
	sysctl -w net.ipv6.conf.all.disable_ipv6=0
	cd $(XDP_TUTORIAL_PATH) && ./testenv.sh setup --legacy-ip --name $(NET_IF_NAME)

test_if_destroy: clone_xdp_tutorial
	cd $(XDP_TUTORIAL_PATH) && ./testenv.sh teardown --legacy-ip --name $(NET_IF_NAME)

all: $(XDP_OBJ)

$(XDP_OBJ): %.o: %.c
ifeq ($(UNAME),Darwin)
	@echo "build this on linux, needs headers"
	exit 1
endif
	$(CLANG) -m64 -v -S -O2 -emit-llvm -c -g \
	    -include linux/kconfig.h \
	    -include asm_goto_workaround.h \
	    -I/usr/include/bpf \
        -I$(KERNEL_INCLUDE_PATH) \
        -I/usr/src/linux-headers-${KERNEL_VERSION}/arch/x86/include/generated \
        -I/usr/src/linux-headers-${KERNEL_VERSION_SHORT}/arch/x86/include \
	    -D__ASM_SYSREG_H \
	    -D __BPF_TRACING__ \
	    -D __BPF__ \
	    -D__KERNEL__ \
	    -D DEBUG=1 \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-implicit-function-declaration \
  		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-Wno-tautological-compare \
		-Wno-unknown-warning-option \
		-Wno-unused-variable \
		-Werror \
		-Wno-incompatible-library-redeclaration \
		-Wno-unused-label \
		-Wno-array-bounds \
		-Wno-frame-address \
		-Wno-uninitialized \
		-o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

pscan_stats:
	go mod download
	go mod tidy
	go mod vendor
	# hacks! until repo is pushed ....
	[ ! -L vendor/teleport_interview ] && cd vendor; ln -s ../ teleport_interview ; cd ../
	GOOS=darwin GOARCH=amd64 go build -o bin/pscan_stats_mac main.go
	GOOS=linux GOARCH=amd64 go build -o bin/pscan_stats_linux main.go

clean:
	rm -f *.o

xdp_load:
	ip link set dev $(NET_IF_NAME) xdp obj $(BPF_O_PATH)/$(BPF_O_FILE) sec $(BPF_NAME) verbose

xdp_unload:
	ip link set dev $(NET_IF_NAME) xdp off

recompile: clean all

test: recompile test_if_create run_test test_if_destroy

run_test:
ifeq ($(UNAME),Darwin)
	@echo "run on linux, integration tests"
	exit 1
endif
	go test -v test/main_test.go

docker_build: clean all pscan_stats
	docker build ./ -t bpf_portscan:latest --progress=plain --network=host

# Possible improvement: narrower capabilities
# Possible improvement: is privileged required?
docker_run:
	docker run -d ${DOCKER_DNS_OVERWRITE} \
		--privileged --cap-add NET_ADMIN --cap-add SYS_ADMIN \
		--network host -v /var/run/docker/netns:/var/run/netns \
		-e NET_IF_NAME=${NET_IF_NAME} -e BPF_O_PATH=${BPF_O_PATH} \
		bpf_portscan:latest

docker_stop:
	docker stop `docker ps -q --filter ancestor=bpf_portscan:latest`
	$(MAKE) docker_log

docker_log:
	docker logs --tail=5 `docker ps -aq --filter ancestor=bpf_portscan:latest`