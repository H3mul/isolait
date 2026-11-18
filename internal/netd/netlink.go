package netd

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
)

// A minimal rtnetlink client: just what is needed to bring up the sandbox's interface (link up, an address, a
// default route). Messages are encoded by hand so the standard library is all that is needed.

const (
	nlmsgError  = 2
	nlmFRequest = 0x1
	nlmFAck     = 0x4
	nlmFCreate  = 0x400
	nlmFExcl    = 0x200

	rtmNewLink  = 16
	rtmNewAddr  = 20
	rtmNewRoute = 24

	ifaLocal   = 2
	ifaAddress = 1
	rtaGateway = 5
	rtaOif     = 4

	rtTableMain = 254
	rtprotBoot  = 3
	rtScopeUniv = 0
	rtnUnicast  = 1
)

func align4(n int) int { return (n + 3) &^ 3 }

func rtattr(typ uint16, data []byte) []byte {
	b := make([]byte, align4(4+len(data)))
	binary.LittleEndian.PutUint16(b, uint16(4+len(data)))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func nlmsg(typ, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, 16, 16+len(payload))
	binary.LittleEndian.PutUint32(b, uint32(16+len(payload)))
	binary.LittleEndian.PutUint16(b[4:], typ)
	binary.LittleEndian.PutUint16(b[6:], flags)
	binary.LittleEndian.PutUint32(b[8:], seq)
	return append(b, payload...)
}

// linkUpMsg is RTM_NEWLINK setting IFF_UP on the interface with the given index.
func linkUpMsg(seq uint32, index int) []byte {
	p := make([]byte, 16) // struct ifinfomsg
	binary.LittleEndian.PutUint32(p[4:], uint32(index))
	binary.LittleEndian.PutUint32(p[8:], syscall.IFF_UP)  // flags
	binary.LittleEndian.PutUint32(p[12:], syscall.IFF_UP) // change mask
	return nlmsg(rtmNewLink, nlmFRequest|nlmFAck, seq, p)
}

// addrMsg is RTM_NEWADDR adding addr/prefix to the interface.
func addrMsg(seq uint32, index int, addr netip.Addr, prefix int) []byte {
	p := make([]byte, 8) // struct ifaddrmsg
	p[0] = syscall.AF_INET
	p[1] = byte(prefix)
	binary.LittleEndian.PutUint32(p[4:], uint32(index))
	a := addr.As4()
	p = append(p, rtattr(ifaLocal, a[:])...)
	p = append(p, rtattr(ifaAddress, a[:])...)
	return nlmsg(rtmNewAddr, nlmFRequest|nlmFAck|nlmFCreate|nlmFExcl, seq, p)
}

// defaultRouteMsg is RTM_NEWROUTE adding 0.0.0.0/0 via gw on the interface.
func defaultRouteMsg(seq uint32, index int, gw netip.Addr) []byte {
	p := make([]byte, 12) // struct rtmsg
	p[0] = syscall.AF_INET
	p[4] = rtTableMain
	p[5] = rtprotBoot
	p[6] = rtScopeUniv
	p[7] = rtnUnicast
	g := gw.As4()
	p = append(p, rtattr(rtaGateway, g[:])...)
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(index))
	p = append(p, rtattr(rtaOif, oif)...)
	return nlmsg(rtmNewRoute, nlmFRequest|nlmFAck|nlmFCreate|nlmFExcl, seq, p)
}

// ackError parses a kernel reply: nil for an acknowledgement, the errno for an error.
func ackError(reply []byte) error {
	if len(reply) < 20 {
		return fmt.Errorf("short netlink reply (%d bytes)", len(reply))
	}
	if binary.LittleEndian.Uint16(reply[4:]) != nlmsgError {
		return fmt.Errorf("unexpected netlink reply type %d", binary.LittleEndian.Uint16(reply[4:]))
	}
	if code := int32(binary.LittleEndian.Uint32(reply[16:])); code != 0 {
		return syscall.Errno(-code)
	}
	return nil
}

// netlinkDo sends each message on a fresh NETLINK_ROUTE socket in the calling thread's network namespace and
// checks every acknowledgement.
func netlinkDo(msgs ...[]byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for i, m := range msgs {
		if err := syscall.Sendto(fd, m, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
			return err
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		if err := ackError(buf[:n]); err != nil {
			return fmt.Errorf("netlink request %d: %w", i, err)
		}
	}
	return nil
}
