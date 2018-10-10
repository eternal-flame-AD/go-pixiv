package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/eternal-flame-AD/goproxy"
)

var (
	PixivDomains = []string{
		"pixiv.net",
		"www.pixiv.net",
		"i.pximg.net",
		"source.pixiv.net",
		"accounts.pixiv.net",
		"touch.pixiv.net",
		"imgaz.pixiv.net",
		"app-api.pixiv.net",
		"oauth.secure.pixiv.net",
		"dic.pixiv.net",
		"comic.pixiv.net",
		"factory.pixiv.net",
		"g-client-proxy.pixiv.net",
		"sketch.pixiv.net",
		"payment.pixiv.net",
		"sensei.pixiv.net",
		"novel.pixiv.net",
		"en-dic.pixiv.net",
		"i1.pixiv.net",
		"i2.pixiv.net",
		"i3.pixiv.net",
		"i4.pixiv.net",
		"d.pixiv.org",
		"pixiv.pximg.net",
		"fanbox.pixiv.net",
		"s.pximg.net",
		"pixivsketch.net",
		"pximg.net",
	}

	PixivDomainsWithPort []string

	FakeConfigCache = make(map[string]*tls.Config, 0)
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func init() {
	PixivDomainsWithPort = make([]string, len(PixivDomains))
	for i, name := range PixivDomains {
		PixivDomainsWithPort[i] = name + ":443"
	}
}

func updateDeadline(conn *tls.Conn, duration time.Duration) {
	conn.SetDeadline(time.Now().Add(duration))
}

func main() {
	verbosevar := boolflag{new(bool)}
	flag.Var(verbosevar, "v", "verbose")
	listen := flag.String("l", ":8080", "listen address")
	flag.Parse()
	verbose := verbosevar.Get().(bool)

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest(
		goproxy.ReqHostIs(PixivDomainsWithPort...),
	).HijackConnect(func(req *http.Request, clientraw net.Conn, ctx *goproxy.ProxyCtx) {
		fmt.Println(ctx.Req.URL.Host, ctx.Req.URL.Hostname())

		defer func() {
			if e := recover(); e != nil {
				ctx.Logf("error connecting to remote: %v", e)
				if verbose {
					debug.PrintStack()
				}
				clientraw.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
			}
			clientraw.Close()
		}()

		processchan := make(chan error)
		clientTLSConfig, err := func(host string) (*tls.Config, error) {
			if config, ok := FakeConfigCache[host]; ok {
				return config, nil
			}
			config, err := goproxy.TLSConfigFromCA(&goproxy.GoproxyCa)(host, ctx)
			if err != nil {
				return nil, err
			}
			FakeConfigCache[host] = config
			return config, nil
		}(ctx.Req.URL.Host)
		orPanic(err)
		client := tls.Server(clientraw, clientTLSConfig)
		updateDeadline(client, 5*time.Second)
		orPanic(client.Handshake())
		defer client.Close()

		clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

		remoteraw, err := net.Dial("tcp", ctx.Req.Host)
		orPanic(err)
		defer remoteraw.Close()

		remote := tls.Client(remoteraw, &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				log.Println("verifying cert for ", ctx.Req.URL.Hostname())
				certs := make([]*x509.Certificate, len(rawCerts))
				for i, c := range rawCerts {
					var err error
					certs[i], err = x509.ParseCertificate(c)
					if err != nil {
						return errors.New("Cert parse failed: " + err.Error())
					}
				}
				opts := x509.VerifyOptions{
					DNSName:       ctx.Req.URL.Hostname(),
					Intermediates: x509.NewCertPool(),
				}

				for i, cert := range certs {
					if i == 0 {
						continue
					}
					opts.Intermediates.AddCert(cert)
				}
				_, err := certs[0].Verify(opts)
				if err != nil {
					//Fallback
					for _, name := range PixivDomains {
						opts.DNSName = name
						_, err := certs[0].Verify(opts)
						if err == nil {
							return nil
						}
					}
				}
				if err != nil {
					log.Printf("Refusing to connect to %s: Cert invalid\n", ctx.Req.URL.Hostname())
					log.Println(certs[0].DNSNames)
				}
				return err
			},
		})
		orPanic(remote.Handshake())
		fmt.Println("Handshake success")
		defer remote.Close()
		remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))

		go func() {
			buffer := make([]byte, 1024)
			var err error
			for {
				updateDeadline(client, 5*time.Second)
				num, err := clientBuf.Read(buffer)
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
				_, err = remoteBuf.Write(buffer[:num])
				if err != nil {
					break
				}
				if err = remoteBuf.Flush(); err != nil {
					break
				}
			}
			processchan <- err
		}()
		go func() {
			buffer := make([]byte, 1024)
			var err error
			for {
				updateDeadline(client, 5*time.Second)
				num, err := remoteBuf.Read(buffer)
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
				_, err = clientBuf.Write(buffer[:num])
				if err != nil {
					break
				}
				if err = clientBuf.Flush(); err != nil {
					break
				}
			}
			processchan <- err
		}()

		orPanic(<-processchan)
		orPanic(<-processchan)
	})
	proxy.Verbose = verbose
	log.Fatal(http.ListenAndServe(*listen, proxy))
}
