package netd

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// The addresses the sandbox sees: its own, and the gateway where DNS is answered.
var (
	GuestAddr   = netip.MustParseAddr("10.0.2.15")
	GatewayAddr = netip.MustParseAddr("10.0.2.2")
)

const (
	guestPrefix = 24
	tapName     = "tap0"
	tapMTU      = 1500

	sysSetns    = 308 // amd64; arm64 uses 268
	cloneNewnet = 0x40000000
	tunSetIff   = 0x400454ca
	iffTap      = 0x2
	iffNoPi     = 0x1000
)

func setnsNumber() uintptr {
	if runtime.GOARCH == "arm64" {
		return 268
	}
	return sysSetns
}

// SetupNetns enters the network namespace at nsPath from a dedicated thread and brings up the sandbox's one
// interface there: it creates a tap device, turns loopback and the tap on, gives the tap the guest address and a
// default route via the gateway, and disables IPv6 everywhere. It returns the tap's file descriptor, which stays
// valid in this process. The thread is never released to the Go scheduler, so the runtime terminates it instead
// of reusing it in the wrong namespace.
func SetupNetns(nsPath string) (tapFD int, err error) {
	type res struct {
		fd  int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread() // deliberately never unlocked
		fd, err := setupInThread(nsPath)
		ch <- res{fd, err}
	}()
	r := <-ch
	return r.fd, r.err
}

func setupInThread(nsPath string) (int, error) {
	ns, err := syscall.Open(nsPath, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening the sandbox's network namespace %s: %w", nsPath, err)
	}
	defer syscall.Close(ns)
	if _, _, e := syscall.RawSyscall(setnsNumber(), uintptr(ns), cloneNewnet, 0); e != 0 {
		return -1, fmt.Errorf("entering the sandbox's network namespace: %w", e)
	}
	// IPv6 first: nothing else the sandbox does can use it while the rest is configured
	if err := disableIPv6(); err != nil {
		return -1, err
	}
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening /dev/net/tun: %w", err)
	}
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
	copy(ifr.name[:], tapName)
	ifr.flags = iffTap | iffNoPi
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tunSetIff, uintptr(unsafe.Pointer(&ifr))); e != 0 {
		syscall.Close(fd)
		return -1, fmt.Errorf("creating %s: %w", tapName, e)
	}
	if err := disableIPv6For(tapName); err != nil { // the tap did not exist when "all" was set
		syscall.Close(fd)
		return -1, err
	}
	lo, err1 := net.InterfaceByName("lo")
	tap, err2 := net.InterfaceByName(tapName)
	if err := errors.Join(err1, err2); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("finding the interfaces: %w", err)
	}
	if err := netlinkDo(
		linkUpMsg(1, lo.Index),
		linkUpMsg(2, tap.Index),
		addrMsg(3, tap.Index, GuestAddr, guestPrefix),
		defaultRouteMsg(4, tap.Index, GatewayAddr),
	); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("configuring the sandbox's network: %w", err)
	}
	return fd, nil
}

// disableIPv6 turns IPv6 off for every interface that exists and every one created later.
func disableIPv6() error {
	for _, scope := range []string{"all", "default", "lo"} {
		if err := disableIPv6For(scope); err != nil {
			return err
		}
	}
	return nil
}

func disableIPv6For(scope string) error {
	err := os.WriteFile("/proc/sys/net/ipv6/conf/"+scope+"/disable_ipv6", []byte("1"), 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil // a kernel without IPv6 has nothing to disable
	}
	if err != nil {
		return fmt.Errorf("disabling IPv6 on %s: %w", scope, err)
	}
	return nil
}
