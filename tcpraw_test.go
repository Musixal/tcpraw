package tcpraw

import (
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"testing"
	"fmt"
)

const portServerPacket = "[::]:3457"
const portRemotePacket = "127.0.0.1:3457"

func init() {
	//startTCPServer()
	startTCPRawServer()
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()
}

func startTCPRawServer() *TCPConn {
	conn, err := Listen("tcp", portServerPacket)
	if err != nil {
		log.Panicln(err)
	}
	err = conn.SetReadBuffer(1024 * 1024)
	if err != nil {
		log.Println(err)
	}
	err = conn.SetWriteBuffer(1024 * 1024)
	if err != nil {
		log.Println(err)
	}

	go func() {
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				log.Println("server readfrom:", err)
				return
			}
			//echo
			_, err = conn.WriteTo(buf[:n], addr)
			if err != nil {
				log.Println("server writeTo:", err)
				return
			}
		}
	}()
	return conn
}

func BenchmarkEcho(b *testing.B) {
fmt.Println("====> Total iterations:", b.N)

	conn, err := Dial("tcp", portRemotePacket)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	addr, err := net.ResolveTCPAddr("tcp", portRemotePacket)
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		n, err := conn.WriteTo(buf, addr)
		if err != nil {
			b.Fatal(n, err)
		}

		if n, addr, err := conn.ReadFrom(buf); err != nil {
			b.Fatal(n, addr, err)
		}
	}
}
