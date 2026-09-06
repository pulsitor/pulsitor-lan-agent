package discover

import (
	"net"
	"testing"
)

// The Linux table is the primary source of MAC addresses on the platform that matters
// most, and its incomplete rows must not become devices.
func TestParseProcNetARP(t *testing.T) {
	table := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0
192.168.1.20     0x1         0x2         12:22:33:44:55:66     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
`

	got := parseProcNetARP(table)

	if len(got) != 2 {
		t.Fatalf("expected the two resolved rows, got %d: %+v", len(got), got)
	}
	if got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC was not normalised: %s", got[0].MAC)
	}
	if !got[0].IP.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatalf("wrong address: %s", got[0].IP)
	}
}

// BSD prints a different shape, and drops leading zeros from octets.
func TestParseArpCommand(t *testing.T) {
	table := `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (192.168.1.20) at 2:2:3:4:5:6 on en0 ifscope [ethernet]
? (192.168.1.30) at (incomplete) on en0 ifscope [ethernet]
`

	got := parseArpCommand(table)

	if len(got) != 2 {
		t.Fatalf("expected two rows, got %d: %+v", len(got), got)
	}
	if got[1].MAC != "02:02:03:04:05:06" {
		t.Fatalf("short octets were not padded: %s", got[1].MAC)
	}
}

// One device must not appear twice because two sources spelled its MAC differently.
func TestNormaliseMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"2:2:3:4:5:6":       "02:02:03:04:05:06",
		"00:00:00:00:00:00": "",
		"(incomplete)":      "",
		"":                  "",
		"aa:bb:cc":          "",

		// Not hosts: the broadcast address, and anything with the group bit set. Both
		// sit in every ARP table and would otherwise become invented devices.
		"ff:ff:ff:ff:ff:ff": "",
		"01:00:5e:00:00:fb": "",
		"11:22:33:44:55:66": "",
	}

	for input, want := range cases {
		if got := NormaliseMAC(input); got != want {
			t.Errorf("NormaliseMAC(%q) = %q, want %q", input, got, want)
		}
	}
}

// The sweep skips the network and broadcast addresses, and refuses a network wide
// enough that walking it would outlast the interval.
func TestHosts(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	hosts, err := Hosts(network)
	if err != nil {
		t.Fatalf("hosts: %v", err)
	}
	if len(hosts) != 254 {
		t.Fatalf("expected 254 usable hosts, got %d", len(hosts))
	}
	if hosts[0].String() != "192.168.1.1" || hosts[253].String() != "192.168.1.254" {
		t.Fatalf("wrong bounds: %s..%s", hosts[0], hosts[253])
	}

	_, wide, _ := net.ParseCIDR("10.0.0.0/8")
	if _, err := Hosts(wide); err == nil {
		t.Fatal("a /8 should be refused, not swept")
	}
}

// The agent's idea of a private address has to match the server's, or it reports
// devices the server silently drops.
func TestIsPrivate(t *testing.T) {
	private := []string{"10.0.0.1", "172.16.5.4", "192.168.1.1", "100.64.0.1", "169.254.1.1", "fd00::1"}
	public := []string{"8.8.8.8", "1.1.1.1", "172.32.0.1", "93.184.216.34", "2606:4700::1"}

	for _, address := range private {
		if !IsPrivate(net.ParseIP(address)) {
			t.Errorf("%s should be private", address)
		}
	}
	for _, address := range public {
		if IsPrivate(net.ParseIP(address)) {
			t.Errorf("%s should not be private", address)
		}
	}
}

// The broadcast address of a subnet is in every ARP table. Recording it invents a device
// whose address changes every sweep, which downstream reads as a device that keeps
// moving between networks.
func TestIsEdgeAddress(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	edges := []string{"192.168.1.0", "192.168.1.255"}
	hosts := []string{"192.168.1.1", "192.168.1.42", "192.168.1.254"}

	for _, address := range edges {
		if !isEdgeAddress(net.ParseIP(address), network) {
			t.Errorf("%s is the network or broadcast address", address)
		}
	}
	for _, address := range hosts {
		if isEdgeAddress(net.ParseIP(address), network) {
			t.Errorf("%s is a usable host", address)
		}
	}
}
