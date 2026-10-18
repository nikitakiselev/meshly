// Command fileserver is the integration-test helper that runs inside the
// test containers: TCP/UDP token servers (optionally pushing lines), probes,
// a connect check, streaming and receiving clients and a static HTTP server
// for release downloads. It is not part of meshly.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	tcp := flag.Int("tcp", 0, "serve TCP on this port")
	udp := flag.Int("udp", 0, "serve UDP on this port")
	token := flag.String("token", "ok", "reply token")
	probe := flag.Bool("probe", false, "probe mode")
	connect := flag.Bool("connect", false, "exit 0 once a TCP connection to -tcp-dial is established (no token needed)")
	tcpDial := flag.String("tcp-dial", "", "probe a TCP server")
	udpDial := flag.String("udp-dial", "", "probe a UDP server")
	timeout := flag.Duration("timeout", 2*time.Second, "probe timeout")
	stream := flag.String("stream", "", "connect and send a line every 200ms")
	push := flag.Bool("push", false, "with -tcp or -udp: send a line every 200ms after the token")
	recv := flag.String("recv", "", "connect over TCP and print each line received")
	recvUDP := flag.String("recv-udp", "", "send a datagram and print each one received")
	dir := flag.String("serve-dir", "", "serve this directory over HTTP")
	listen := flag.String("listen", ":8000", "HTTP listen address")
	flag.Parse()
	switch {
	case *dir != "":
		fail(http.ListenAndServe(*listen, http.FileServer(http.Dir(*dir))))
	case *connect && *tcpDial != "":
		c, err := net.DialTimeout("tcp", *tcpDial, *timeout)
		fail(err)
		_ = c.Close()
	case *probe && *tcpDial != "":
		c, err := net.DialTimeout("tcp", *tcpDial, *timeout)
		fail(err)
		_ = c.SetDeadline(time.Now().Add(*timeout))
		line, err := bufio.NewReader(c).ReadString('\n')
		fail(err)
		fmt.Print(line)
	case *probe && *udpDial != "":
		c, err := net.Dial("udp", *udpDial)
		fail(err)
		_ = c.SetDeadline(time.Now().Add(*timeout))
		_, err = c.Write([]byte("probe\n"))
		fail(err)
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		fail(err)
		fmt.Print(string(buf[:n]))
	case *stream != "":
		c, err := net.DialTimeout("tcp", *stream, *timeout)
		fail(err)
		for i := 1; ; i++ {
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := fmt.Fprintf(c, "line %d\n", i); err != nil {
				fail(err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	case *recv != "":
		c, err := net.DialTimeout("tcp", *recv, *timeout)
		fail(err)
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			fmt.Println(sc.Text())
		}
		fail(sc.Err())
	case *recvUDP != "":
		c, err := net.Dial("udp", *recvUDP)
		fail(err)
		_, err = c.Write([]byte("probe\n"))
		fail(err)
		buf := make([]byte, 512)
		for {
			n, err := c.Read(buf)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			fmt.Print(string(buf[:n]))
		}
	case *tcp != 0:
		l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *tcp))
		fail(err)
		for {
			c, err := l.Accept()
			if err != nil {
				continue
			}
			go serveTCP(c, *tcp, *token, *push)
		}
	case *udp != 0:
		pc, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", *udp))
		fail(err)
		buf := make([]byte, 2048)
		pushing := map[string]bool{}
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			logHit("udp", *udp, addr.String())
			_ = n
			_, _ = pc.WriteTo([]byte(*token+"\n"), addr)
			if *push && !pushing[addr.String()] {
				pushing[addr.String()] = true
				go pushLines(func(line string) error { _, err := pc.WriteTo([]byte(line), addr); return err })
			}
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func serveTCP(c net.Conn, port int, token string, push bool) {
	defer c.Close()
	logHit("tcp", port, c.RemoteAddr().String())
	_, _ = fmt.Fprintln(c, token)
	if push {
		pushLines(func(line string) error {
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			_, err := fmt.Fprint(c, line)
			return err
		})
		return
	}
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		f, err := os.OpenFile(fmt.Sprintf("/tmp/recv-tcp-%d", port), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(f, sc.Text())
			f.Close()
		}
	}
}

// pushLines sends "push <n>" every 200ms, for at most about 3 minutes.
func pushLines(send func(string) error) {
	for i := 1; i <= 900; i++ {
		if send(fmt.Sprintf("push %d\n", i)) != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func logHit(proto string, port int, from string) {
	f, err := os.OpenFile(fmt.Sprintf("/tmp/hits-%s-%d", proto, port), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		fmt.Fprintln(f, from)
		f.Close()
	}
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
