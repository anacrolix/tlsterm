package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/anacrolix/missinggo"
	"github.com/anacrolix/missinggo/expect"
	"github.com/anacrolix/tagflag"
)

type TunnelAddr struct {
	Local  *net.TCPAddr
	Remote *net.TCPAddr
}

var _ tagflag.Marshaler = (*TunnelAddr)(nil)

func (me *TunnelAddr) Marshal(s string) error {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return fmt.Errorf("bad tunnel: %q", s)
	}
	i += strings.IndexByte(s[i+1:], ':')
	i++
	err := tagflag.Unmarshal(s[:i], &me.Local)
	if err != nil {
		return fmt.Errorf("error unmarshalling local addr: %v", err)
	}
	err = tagflag.Unmarshal(s[i+1:], &me.Remote)
	if err != nil {
		return fmt.Errorf("error unmarshalling remote addr: %v", err)
	}
	return nil
}

func (TunnelAddr) RequiresExplicitValue() bool { return true }

func addClientCAs(cfg *tls.Config) {
	b, err := ioutil.ReadFile("clientcas.pem")
	expect.Nil(err)
	expect.Ok(cfg.ClientCAs.AppendCertsFromPEM(b))
}

func main() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	var flags = struct {
		tagflag.StartPos
		Tunnels []TunnelAddr
	}{}
	tagflag.Parse(&flags)
	tlsCfg := &tls.Config{
		ClientCAs:  x509.NewCertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	var err error
	tlsCfg.Certificates, err = missinggo.LoadCertificateDir("./certs")
	expect.Nil(err)
	addClientCAs(tlsCfg)
	for _, t := range flags.Tunnels {
		go func() {
			expect.Nil(listen(t, tlsCfg))
		}()
	}
	select {}
}

func listen(tun TunnelAddr, tc *tls.Config) error {
	l, err := tls.Listen("tcp", tun.Local.String(), tc)
	expect.Nil(err)
	defer l.Close()
	var nextConnId int
	for {
		c, err := l.Accept()
		expect.Nil(err)
		connId := nextConnId
		nextConnId++
		log.Printf("#%v: accepted connection from %v", connId, c.RemoteAddr())
		go func() {
			defer c.Close()
			oc, err := net.Dial("tcp", tun.Remote.String())
			if err != nil {
				log.Printf("#%v: error dialing %v: %v", connId, tun.Remote, err)
				return
			}
			defer oc.Close()
			log.Printf("#%v: dialed %v", connId, oc.RemoteAddr())
			go func() {
				defer c.Close()
				defer oc.Close()
				n, err := io.Copy(c, oc)
				log.Printf("#%v: copied %d bytes from origin", connId, n)
				if err != nil {
					log.Printf("#%v: error copying from origin: %v", connId, err)
				}
			}()
			n, err := io.Copy(oc, c)
			log.Printf("#%v: copied %d bytes to origin", connId, n)
			if err != nil {
				log.Printf("#%v: error copying to origin: %v", connId, err)
			}
		}()
	}
}
