// Command fileserver is the integration-test helper that runs inside the
// test containers: TCP/UDP token servers, probes, a streaming client and a
// static HTTP server for release downloads. It is not part of meshly.
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
	tcpDial := flag.String("tcp-dial", "", "probe a TCP server")
	udpDial := flag.String("udp-dial", "", "probe a UDP server")
	timeout := flag.Duration("timeout", 2*time.Second, "probe timeout")
	stream := flag.String("stream", "", "connect and send a line every 200ms")
	dir := flag.String("serve-dir", "", "serve this directory over HTTP")
	listen := flag.String("listen", ":8000", "HTTP listen address")
	flag.Parse()
	switch {
	case *dir != "":
		fail(http.ListenAndServe(*listen, http.FileServer(http.Dir(*dir))))
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
	case *tcp != 0:
		l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *tcp))
		fail(err)
		for {
			c, err := l.Accept()
			if err != nil {
				continue
			}
			go serveTCP(c, *tcp, *token)
		}
	case *udp != 0:
		pc, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", *udp))
		fail(err)
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			logHit("udp", *udp, addr.String())
			_ = n
			_, _ = pc.WriteTo([]byte(*token+"\n"), addr)
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func serveTCP(c net.Conn, port int, token string) {
	defer c.Close()
	logHit("tcp", port, c.RemoteAddr().String())
	_, _ = fmt.Fprintln(c, token)
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		f, err := os.OpenFile(fmt.Sprintf("/tmp/recv-tcp-%d", port), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(f, sc.Text())
			f.Close()
		}
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
