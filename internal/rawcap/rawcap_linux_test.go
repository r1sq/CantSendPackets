package rawcap

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// udpFrame builds Ethernet + IPv4 (with options of ihlWords*4 bytes) + UDP.
func udpFrame(dst byte, srcPort, dstPort uint16, ihlWords int, fragOffset uint16) []byte {
	f := make([]byte, 14)
	f[0] = dst
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := make([]byte, ihlWords*4)
	ip[0] = 0x40 | byte(ihlWords)
	ip[9] = 17
	binary.BigEndian.PutUint16(ip[6:], fragOffset)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	return append(append(append(f, ip...), udp...), make([]byte, 20)...)
}

func accepts(t *testing.T, prog []bpf.Instruction, frame []byte) bool {
	t.Helper()
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestDHCPFilter(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"server reply", udpFrame(0xff, 67, 68, 5, 0), true},
		{"server reply with IP options", udpFrame(0xff, 67, 68, 6, 0), true},
		{"client request", udpFrame(0xff, 68, 67, 5, 0), false},
		{"other UDP", udpFrame(0xff, 53, 68, 5, 0), false},
		{"later fragment", udpFrame(0xff, 67, 68, 5, 0x0010), false},
	}
	for _, c := range cases {
		if got := accepts(t, DHCPServerReplies, c.frame); got != c.want {
			t.Errorf("%s: accepted = %v, want %v", c.name, got, c.want)
		}
	}
	arp := udpFrame(0xff, 67, 68, 5, 0)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if accepts(t, DHCPServerReplies, arp) {
		t.Error("ARP must not pass")
	}
}

func TestNonUnicastFilter(t *testing.T) {
	if !accepts(t, NonUnicast, udpFrame(0xff, 1, 2, 5, 0)) || !accepts(t, NonUnicast, udpFrame(0x01, 1, 2, 5, 0)) {
		t.Error("broadcast and multicast must pass")
	}
	if accepts(t, NonUnicast, udpFrame(0x02, 1, 2, 5, 0)) {
		t.Error("unicast must not pass")
	}
}
