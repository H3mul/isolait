// netd spike: a TAP in another netns driven by gVisor netstack, forwarding guest TCP to the host
// network and relaying DNS. No policy, no product structure; just the feasibility path.
//
//	netd -ns /proc/<pid>/ns/net -map 203.0.113.10=127.0.0.1 -dns 127.0.0.1:5353
//
// -map rewrites a guest destination IP to another dial address so tests need no internet.
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	sysSetns    = 308 // amd64
	cloneNewnet = 0x40000000
	tunSetIff   = 0x400454ca
	iffTap      = 0x2
	iffNoPi     = 0x1000
	gateway     = "10.0.2.2"
	mtu         = 1500
)

func die(what string, err any) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

// openTap creates tap0 inside netns path from a locked thread that is never unlocked, so Go
// terminates the thread instead of reusing it in the wrong namespace.
func openTap(path string) (int, error) {
	type res struct {
		fd  int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		ns, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			ch <- res{-1, err}
			return
		}
		defer syscall.Close(ns)
		if _, _, e := syscall.RawSyscall(sysSetns, uintptr(ns), cloneNewnet, 0); e != 0 {
			ch <- res{-1, e}
			return
		}
		fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
		if err != nil {
			ch <- res{-1, err}
			return
		}
		var r struct {
			name  [16]byte
			flags uint16
			_     [22]byte
		}
		copy(r.name[:], "tap0")
		r.flags = iffTap | iffNoPi
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&r))); e != 0 {
			ch <- res{-1, e}
			return
		}
		ch <- res{fd, nil}
	}()
	r := <-ch
	return r.fd, r.err
}

func main() {
	nsPath := flag.String("ns", "", "netns path of the sandbox")
	maps := flag.String("map", "", "comma list of guestIP=dialIP")
	dnsUp := flag.String("dns", "127.0.0.1:53", "upstream DNS host:port")
	flag.Parse()
	remap := map[string]string{}
	for _, m := range strings.Split(*maps, ",") {
		if k, v, ok := strings.Cut(m, "="); ok {
			remap[k] = v
		}
	}

	fd, err := openTap(*nsPath)
	if err != nil {
		die("open tap", err)
	}
	syscall.SetNonblock(fd, true)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	mac, _ := net.ParseMAC("5a:94:ef:e4:0c:ee")
	ep, terr := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu, EthernetHeader: true, Address: tcpip.LinkAddress(mac)})
	if terr != nil {
		die("fdbased", terr)
	}
	const nic = 1
	if e := s.CreateNIC(nic, ep); e != nil {
		die("create nic", e)
	}
	s.SetPromiscuousMode(nic, true) // accept packets for any destination
	s.SetSpoofing(nic, true)        // answer from any source address
	gw := tcpip.AddrFromSlice(net.ParseIP(gateway).To4())
	if e := s.AddProtocolAddress(nic, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: gw.WithPrefix()}, stack.AddressProperties{}); e != nil {
		die("add addr", e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nic}})

	tcpFwd := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := id.LocalAddress.String()
		if m, ok := remap[dst]; ok {
			dst = m
		}
		// Dial first: a refused upstream becomes a refused guest connect, not connect-then-reset.
		up, err := net.DialTimeout("tcp", net.JoinHostPort(dst, strconv.Itoa(int(id.LocalPort))), 5*time.Second)
		if err != nil {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		gep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			up.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		c := gonet.NewTCPConn(&wq, gep)
		go func() { io.Copy(up, c); up.Close() }()
		go func() { io.Copy(c, up); c.Close() }()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		if r.ID().LocalPort != 53 {
			return false // non-DNS UDP dropped
		}
		var wq waiter.Queue
		gep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return false
		}
		c := gonet.NewUDPConn(&wq, gep)
		go func() {
			defer c.Close()
			up, err := net.Dial("udp", *dnsUp)
			if err != nil {
				return
			}
			defer up.Close()
			buf := make([]byte, 4096)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			up.Write(buf[:n])
			up.SetReadDeadline(time.Now().Add(3 * time.Second))
			if n, err = up.Read(buf); err == nil {
				c.Write(buf[:n])
			}
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	fmt.Println("ready")
	select {}
}
