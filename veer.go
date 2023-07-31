package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
}

var options struct {
	Proxy          string
	Dest           string
	ConnectTimeout time.Duration
}

const version = "0.1.0"

func init() {
	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "veer %s, a tool for tunneling SSH through proxies.\n", version)
		fmt.Fprintf(output, "Basic usages:\n")
		fmt.Fprintf(output, "tunnel through http proxy:  veer -p http://127.0.0.1:1090 -d %%h:%%p\n")
		fmt.Fprintf(output, "tunnel through socks5 proxy: veer -p socks://127.0.0.1:1090 -d %%h:%%p\n")
		fmt.Fprintf(output, "\nOptions:\n")
		flag.VisitAll(func(f *flag.Flag) {
			var dft string
			if f.DefValue != "" {
				dft = " (default to " + f.DefValue + ")"
			}
			fmt.Fprintf(output, "    -%s        %s%s\n", f.Name, f.Usage, dft)
		})
	}
	flag.StringVar(&options.Proxy, "p", "", `proxy uri, a valid uri example: "proto://[username:password@]hostname:port"`)
	flag.StringVar(&options.Dest, "d", "", `destination address, in the form of "hostname:port"`)
	flag.DurationVar(&options.ConnectTimeout, "t", time.Second, `connection timeout, time units could be "s", "ms"`)
}

func errorExit(err error) {
	log.Print(err)
	os.Exit(1)
}

type Tunnel interface {
	Connect(conn net.Conn, dest string, auth *url.Userinfo) error
}

func writeall(w io.Writer, buf []byte) error {
	var n int
	for n < len(buf) {
		g, err := w.Write(buf[n:])
		if err != nil {
			return err
		}
		n += g
	}
	return nil
}

const crlf = "\r\n"

var linefeed = []byte("\r\n\r\n")

type httpTunnel struct{}

func (httpTunnel) Connect(conn net.Conn, dest string, auth *url.Userinfo) error {
	var buf bytes.Buffer
	buf.WriteString("CONNECT ")
	buf.WriteString(dest)
	buf.WriteString(" HTTP/1.0")
	buf.WriteString(crlf)
	buf.WriteString("Host: ")
	buf.WriteString(dest)
	buf.WriteString(crlf)
	if auth != nil {
		buf.WriteString("Proxy-Authorization: basic ")
		enc := base64.NewEncoder(base64.StdEncoding, &buf)
		pwd, _ := auth.Password()
		enc.Write([]byte(auth.Username() + ":" + pwd))
		enc.Close()
		buf.WriteString(crlf)
	}
	buf.WriteString(crlf)
	if err := writeall(conn, buf.Bytes()); err != nil {
		return fmt.Errorf("send CONNECT to http proxy fail: %v", err)
	}
	buf.Reset()
	var d [40]byte // 40 bytes for 200 response.
	for {
		if buf.Len() > 256 {
			return fmt.Errorf("too large CONNECT response: %s", buf.String())
		}
		n, err := conn.Read(d[:])
		if err != nil {
			return fmt.Errorf("receive CONNECT response from http proxy fail: %v", err)
		}
		buf.Write(d[:n])
		i := bytes.Index(buf.Bytes(), linefeed)
		if i > 0 { // response header filled
			r := string(buf.Bytes()[:i])
			parts := strings.SplitN(r, " ", 3)
			if len(parts) != 3 || !strings.HasPrefix(parts[0], "HTTP/") {
				return fmt.Errorf("receive bad CONNECT response: %s", r)
			}
			code, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("receive bad CONNECT response: %s", r)
			}
			if code < 200 || code >= 300 {
				return fmt.Errorf("CONNECT response %d: %s", code, parts[2])
			}

			lb := buf.Bytes()[i+len(linefeed):]
			if len(lb) > 0 {
				if err := writeall(os.Stdout, lb); err != nil {
					errorExit(fmt.Errorf("send proxy data to stdout fail: %v", err))
				}
			}
			break
		}
	}
	return nil
}

type socksTunnel struct{}

// Wire protocol constants.
const (
	Version5 = 0x05

	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04

	CmdConnect = 0x01 // establishes an active-open forward proxy connection
	cmdBind    = 0x02 // establishes a passive-open forward proxy connection

	AuthMethodNotRequired         = 0x00 // no authentication required
	AuthMethodUsernamePassword    = 0x02 // use username/password
	AuthMethodNoAcceptableMethods = 0xff // no acceptable authentication methods

	StatusSucceeded = 0x00

	authUsernamePasswordVersion = 0x01
	authStatusSucceeded         = 0x00
)

func (st socksTunnel) Connect(conn net.Conn, dest string, user *url.Userinfo) error {
	host, port, err := splitHostPort(dest)
	if err != nil {
		return fmt.Errorf("bad destination: %v", err)
	}

	b := make([]byte, 0, 6+len(dest)) // the size here is just an estimate
	b = append(b, Version5)
	if user == nil {
		b = append(b, byte(2), AuthMethodNotRequired, AuthMethodUsernamePassword)
	} else {
		b = append(b, byte(1), AuthMethodNotRequired)
	}
	if err := writeall(conn, b); err != nil {
		return fmt.Errorf("socks connect write fails in stage 1: %v", err)
	}
	if _, err := io.ReadFull(conn, b[:2]); err != nil {
		return fmt.Errorf("socks connect read fails in stage 1: %v", err)
	}
	if b[0] != Version5 {
		return errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	am := b[1]
	if err := st.auth(am, conn, user); err != nil {
		return err
	}

	b = b[:0]
	// ver, cmd, rsv
	b = append(b, Version5, CmdConnect, 0)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, AddrTypeIPv4)
			b = append(b, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			b = append(b, AddrTypeIPv6)
			b = append(b, ip6...)
		} else {
			return fmt.Errorf("bad destination: unknwon address type")
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("bad destination: FQDN too long")
		}
		b = append(b, AddrTypeFQDN)
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}
	b = append(b, byte(port>>8), byte(port))
	if err := writeall(conn, b); err != nil {
		return fmt.Errorf("socks connect write fails in stage 2: %v", err)
	}
	if _, err := io.ReadFull(conn, b[:4]); err != nil {
		return fmt.Errorf("socks connect read fails in stage 2: %v", err)
	}
	if b[0] != Version5 {
		return errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	if b[1] != StatusSucceeded {
		return errors.New("unknown socks status " + strconv.Itoa(int(b[1])))
	}
	if b[2] != 0 {
		return errors.New("non-zero reserved field")
	}
	l := 2
	switch b[3] {
	case AddrTypeIPv4:
		l += net.IPv4len
	case AddrTypeIPv6:
		l += net.IPv6len
	case AddrTypeFQDN:
		if _, err := io.ReadFull(conn, b[:1]); err != nil {
			return fmt.Errorf("socks fails at statge 2: %v", err)
		}
		l += int(b[0])
	default:
		return errors.New("unknown address type " + strconv.Itoa(int(b[3])))
	}
	if cap(b) < l {
		b = make([]byte, l)
	} else {
		b = b[:l]
	}
	if _, err := io.ReadFull(conn, b[:l]); err != nil {
		return fmt.Errorf("socks connect read fails in stage 2: %v", err)
	}
	return nil
}

func (socksTunnel) auth(am byte, conn net.Conn, user *url.Userinfo) error {
	switch am {
	case AuthMethodNoAcceptableMethods:
		return errors.New("no acceptable authentication methods")
	case AuthMethodNotRequired:
		return nil
	case AuthMethodUsernamePassword:
		u := user.Username()
		p, _ := user.Password()
		if len(u) == 0 || len(u) > 255 || len(p) > 255 {
			return errors.New("invalid username/password")
		}
		b := []byte{authUsernamePasswordVersion}
		b = append(b, byte(len(u)))
		b = append(b, u...)
		b = append(b, byte(len(p)))
		b = append(b, p...)
		if err := writeall(conn, b); err != nil {
			return fmt.Errorf("socks auth fail: %v", err)
		}
		if _, err := io.ReadFull(conn, b[:2]); err != nil {
			return fmt.Errorf("socks auth fail: %v", err)
		}
		if b[0] != authUsernamePasswordVersion {
			return errors.New("invalid username/password version")
		}
		if b[1] != authStatusSucceeded {
			return errors.New("username/password authentication failed")
		}
		return nil
	default:
		return errors.New("unexpected auth method " + strconv.Itoa(int(am)))
	}
}

var tunnels = map[string]Tunnel{
	"http":  httpTunnel{},
	"socks": socksTunnel{},
}

func main() {
	flag.Parse()
	if options.Proxy == "" {
		errorExit(errors.New("proxy uri not setting, using -p to set proxy"))
	}
	if options.Dest == "" {
		errorExit(errors.New("destination not setting, using -d to set destination"))
	}

	uri, err := url.Parse(options.Proxy)
	if err != nil {
		errorExit(fmt.Errorf("bad proxy uri: %v", err))
	}
	tu, ok := tunnels[uri.Scheme]
	if !ok {
		errorExit(fmt.Errorf("bad proxy proto: %s", uri.Scheme))
	}
	conn, err := net.DialTimeout("tcp", uri.Host, options.ConnectTimeout)
	if err != nil {
		conn.Close()
		errorExit(fmt.Errorf("dial proxy fail: %v", err))
	}
	if err := tu.Connect(conn, options.Dest, uri.User); err != nil {
		conn.Close()
		errorExit(err)
	}
	log.Printf("Proxy connect: %s -> %s", options.Proxy, options.Dest)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(os.Stdout, conn); err != nil {
			conn.Close()
			errorExit(fmt.Errorf("send proxy data to stdout fail: %v", err))
		}
	}()
	if _, err := io.Copy(conn, os.Stdin); err != nil {
		conn.Close()
		errorExit(fmt.Errorf("send stdin data to proxy fail: %v", err))
	}
	wg.Wait()
}

func splitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}
	return host, portnum, nil
}
