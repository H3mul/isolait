package netd

import (
	"encoding/binary"
	"net/netip"
	"syscall"
	"testing"
)

func TestNetlinkMessagesAreWellFormed(t *testing.T) {
	check := func(name string, m []byte, wantType uint16, wantLen int) {
		t.Helper()
		if len(m) != wantLen {
			t.Errorf("%s: %d bytes, want %d", name, len(m), wantLen)
		}
		if got := binary.LittleEndian.Uint32(m); int(got) != len(m) {
			t.Errorf("%s: header length %d != message length %d", name, got, len(m))
		}
		if got := binary.LittleEndian.Uint16(m[4:]); got != wantType {
			t.Errorf("%s: type %d, want %d", name, got, wantType)
		}
		if len(m)%4 != 0 {
			t.Errorf("%s: not aligned to 4 bytes", name)
		}
	}
	up := linkUpMsg(7, 3)
	check("link up", up, rtmNewLink, 16+16)
	if binary.LittleEndian.Uint32(up[16+4:]) != 3 || binary.LittleEndian.Uint32(up[16+8:]) != syscall.IFF_UP || binary.LittleEndian.Uint32(up[16+12:]) != syscall.IFF_UP {
		t.Errorf("link up payload %x", up[16:])
	}
	addr := addrMsg(8, 3, netip.MustParseAddr("10.0.2.15"), 24)
	check("address", addr, rtmNewAddr, 16+8+8+8)
	if addr[16] != syscall.AF_INET || addr[17] != 24 || binary.LittleEndian.Uint32(addr[16+4:]) != 3 {
		t.Errorf("ifaddrmsg %x", addr[16:24])
	}
	if string(addr[28:32]) != string([]byte{10, 0, 2, 15}) || string(addr[36:40]) != string([]byte{10, 0, 2, 15}) {
		t.Errorf("address attributes %x", addr[24:])
	}
	route := defaultRouteMsg(9, 3, netip.MustParseAddr("10.0.2.2"))
	check("route", route, rtmNewRoute, 16+12+8+8)
	if route[16] != syscall.AF_INET || route[16+1] != 0 /* dst_len: default */ || route[16+4] != rtTableMain || route[16+7] != rtnUnicast {
		t.Errorf("rtmsg %x", route[16:28])
	}
	if string(route[32:36]) != string([]byte{10, 0, 2, 2}) || binary.LittleEndian.Uint32(route[40:]) != 3 {
		t.Errorf("route attributes %x", route[28:])
	}
}

func TestAckErrorParsing(t *testing.T) {
	ok := nlmsg(nlmsgError, 0, 1, make([]byte, 20)) // error code 0 is an acknowledgement
	if err := ackError(ok); err != nil {
		t.Errorf("ack: %v", err)
	}
	p := make([]byte, 20)
	code := -int32(syscall.EEXIST) // the kernel reports errors as negative errno values
	binary.LittleEndian.PutUint32(p, uint32(code))
	if err := ackError(nlmsg(nlmsgError, 0, 1, p)); err != syscall.EEXIST {
		t.Errorf("error reply: %v, want EEXIST", err)
	}
	if err := ackError([]byte{1, 2, 3}); err == nil {
		t.Error("a short reply was accepted")
	}
	if err := ackError(nlmsg(3, 0, 1, make([]byte, 20))); err == nil {
		t.Error("a reply that is not an error/ack was accepted")
	}
}
