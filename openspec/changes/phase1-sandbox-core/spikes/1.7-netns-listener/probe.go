// probe: listen on 127.0.0.1:<port> inside another network namespace (from a locked thread that
// setns'd into it) and forward accepted connections to <target> dialed from the original namespace.
// usage: probe <netns-path> <port> <target>      SIGUSR1 closes the listener and its connections.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
)

const (
	sysSetns   = 308 // amd64
	cloneNewnet = 0x40000000
)

func die(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}

// listenIn creates the listening socket in netns path. The goroutine stays locked to its thread and
// exits afterwards, so Go terminates that thread instead of reusing it in the wrong namespace.
func listenIn(path, addr string) (net.Listener, error) {
	type res struct {
		l   net.Listener
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: thread dies with the goroutine
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			ch <- res{nil, err}
			return
		}
		defer syscall.Close(fd)
		if _, _, e := syscall.RawSyscall(sysSetns, uintptr(fd), cloneNewnet, 0); e != 0 {
			ch <- res{nil, e}
			return
		}
		l, err := net.Listen("tcp", addr)
		ch <- res{l, err}
	}()
	r := <-ch
	return r.l, r.err
}

func main() {
	nsPath, port, target := os.Args[1], os.Args[2], os.Args[3]
	l, err := listenIn(nsPath, "127.0.0.1:"+port)
	if err != nil {
		die("listen in netns", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target) // runs in the original netns
			if err != nil {
				c.Close()
				continue
			}
			mu.Lock()
			conns = append(conns, c, up)
			mu.Unlock()
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	fmt.Println("listening")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1)
	<-sig
	l.Close()
	mu.Lock()
	for _, c := range conns {
		c.Close()
	}
	mu.Unlock()
	fmt.Println("closed")
	select {} // stay alive; the test kills us
}
