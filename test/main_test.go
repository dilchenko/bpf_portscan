package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"os/exec"
	"testing"
)

const TestNetnsName = "veth-pscan-test"
const TestNetnsIP = "10.11.1.1"
const CountBlocked = 3
const CountNonBlocked = 2
const IPRegistryMapName = "pscan_ip_reg"

var (
	ipCmd        = "/usr/sbin/ip"
	hping3Cmd    = "/usr/sbin/hping3"
	testedPorts  = []int{1024, 1025, 1026}
	ipArgsCommon = []string{
		"netns",
		"exec",
		TestNetnsName,
		hping3Cmd,
		"-V",
		"-S",
		TestNetnsIP,
		"-p",
		fmt.Sprintf("++%d", testedPorts[0]),
		"--faster",
		"-c",
	}
)

type ipInfo struct {
	// struct bpf_spin_lock bpf_lock; - we don't need it
	Blocked         uint8
	PacketTimestamp uint64
	Port1           uint32
	Port2           uint32
	Port3           uint32
}

func xdpLoad() error {
	return xdpMakeTarget("xdp_load")
}

func xdpUnload() error {
	return xdpMakeTarget("xdp_unload")
}

func xdpMakeTarget(target string) error {
	var err error
	//var out []byte
	cmd := exec.Command("make", target)
	cmd.Dir = "../"
	_, err = cmd.CombinedOutput()
	//fmt.Printf("make %s combined output:\n%s\n", target, out)
	return err
}

func simulateTraffic(numIP, numPkt, startIp int) error {
	var err error

	ipArgs := append(ipArgsCommon, fmt.Sprintf("%d", numPkt))
	for i := startIp; i < startIp+numIP; i++ {
		ipArgsFinal := append(ipArgs, "-a", fmt.Sprintf("127.0.0.%d", i))
		//fmt.Printf("Running %s %s\n", ipCmd, strings.Join(ipArgsFinal[:], " "))
		//var out []byte
		_, err = exec.Command(ipCmd, ipArgsFinal...).CombinedOutput()
		if err.Error() != "exit status 1" {
			fmt.Printf("Error occured: [%s]\n", err)
			return err
		}
		//fmt.Printf("%s combined output:\n%s\n", ipCmd, out)
	}
	return nil
}

func simulateNonBlockedTraffic() error {
	return simulateTraffic(CountNonBlocked, CountNonBlocked, 10)
}

func simulateBlockedTraffic() error {
	return simulateTraffic(CountBlocked, CountBlocked, 20)
}

func readIPRegistry() ([]ipInfo, error) {
	var ipRegistry []ipInfo
	bpftoolCmd := "/usr/sbin/bpftool"
	bpfToolArgs := []string{"map", "dump", "name", IPRegistryMapName}
	statsJson, err := exec.Command(bpftoolCmd, bpfToolArgs...).Output()
	if err == nil {
		err = json.Unmarshal(statsJson, &ipRegistry)
	}
	return ipRegistry, err
}

func TestXDPUnloaded(t *testing.T) {
	var ipRegistry []ipInfo
	var err error

	// Clean slate
	err = xdpUnload()
	assert.Nil(t, err)

	err = simulateBlockedTraffic()
	assert.Nil(t, err)

	ipRegistry, err = readIPRegistry()
	assert.NotNil(t, err)
	assert.Equal(t, 0, len(ipRegistry))
}

func TestNonBlocked(t *testing.T) {
	var ipRegistry []ipInfo
	var err error

	err = xdpLoad()
	assert.Nil(t, err)

	err = simulateNonBlockedTraffic()
	assert.Nil(t, err)

	ipRegistry, err = readIPRegistry()
	assert.Nil(t, err)
	assert.Equal(t, CountNonBlocked, len(ipRegistry))
}

func TestBlocked(t *testing.T) {
	var ipRegistry []ipInfo
	var err error

	err = xdpLoad()
	assert.NotNil(t, err) // This should throw an error because XDP should be loaded

	err = simulateBlockedTraffic()
	assert.Nil(t, err)

	ipRegistry, err = readIPRegistry()
	assert.Nil(t, err)
	// XDP loaded above, so registry should have both blocked and non-blocked IPs in here
	assert.Equal(t, CountBlocked+CountNonBlocked, len(ipRegistry))
}

func TestUnload(t *testing.T) {
	var ipRegistry []ipInfo
	var err error

	err = xdpUnload()
	assert.Nil(t, err)

	err = simulateBlockedTraffic()
	assert.Nil(t, err)

	ipRegistry, err = readIPRegistry()
	assert.NotNil(t, err)
	assert.Equal(t, 0, len(ipRegistry))
}
