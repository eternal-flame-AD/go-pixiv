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
	"strings"
	"sync"
	"time"

	"github.com/eternal-flame-AD/goproxy"
)

var (
	BlackHoleDomains = []string{
		"www.google.com",
		"google.com",
		"fonts.googleapis.com",
	}

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

	PixivDomainsWithPort     []string
	BlackHoleDomainsWithPort []string

	FakeConfigCache = make(map[string]*tls.Config, 0)
	IPCache         = struct {
		Data map[string]string
		Lock sync.RWMutex
	}{make(map[string]string), sync.RWMutex{}}
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func init() {
	PixivDomainsWithPort = make([]string, len(PixivDomains))
	BlackHoleDomainsWithPort = make([]string, len(BlackHoleDomains))
	for i, name := range PixivDomains {
		PixivDomainsWithPort[i] = name + ":443"
	}
	for i, name := range BlackHoleDomains {
		BlackHoleDomainsWithPort[i] = name + ":443"
	}
}

func updateDeadline(conn *tls.Conn, duration time.Duration) {
	conn.SetDeadline(time.Now().Add(duration))
}

func main() {
	verbosevar := boolflag{new(bool)}
	flag.Var(verbosevar, "v", "verbose")
	listen := flag.String("l", ":8080", "listen address")
	endpoint := flag.String("e", "https://1.0.0.1/dns-query", "DoH endpoint")
	flag.Parse()
	verbose := verbosevar.Get().(bool)

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest(
		goproxy.ReqHostIs(BlackHoleDomainsWithPort...),
	).HandleConnect(goproxy.AlwaysReject)

	proxy.OnRequest(
		goproxy.ReqHostIs(PixivDomainsWithPort...),
	).HijackConnect(func(req *http.Request, clientraw net.Conn, ctx *goproxy.ProxyCtx) {
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

		log.Printf("Establishing connection to %s\n", ctx.Req.URL.Hostname())

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

		remoteraw := func() net.Conn {
			IPCache.Lock.RLock()
			ip, ok := IPCache.Data[ctx.Req.URL.Hostname()]
			IPCache.Lock.RUnlock()
			if ok {
				remoteraw, err := net.Dial("tcp", ip+ctx.Req.Host[strings.LastIndex(ctx.Req.Host, ":"):])
				if err == nil {
					if verbose {
						log.Println("Successfully retrieved IP cache for " + ctx.Req.URL.Hostname())
					}
					return remoteraw
				}
			}
			query := DNSQuery{
				ctx.Req.URL.Hostname(),
				"A",
				*endpoint,
				false,
				false,
			}
			log.Printf("Obtaining DNS records for %s\n", ctx.Req.URL.Hostname())
			res, err := query.Do()
			orPanic(err)
			for _, ans := range res.Answer {
				var err error
				if ans.Type != 1 {
					continue
				}
				remoteraw, err := net.Dial("tcp", ans.Data+ctx.Req.Host[strings.LastIndex(ctx.Req.Host, ":"):])
				if err == nil {
					IPCache.Lock.Lock()
					IPCache.Data[ctx.Req.URL.Hostname()] = ans.Data
					IPCache.Lock.Unlock()
					return remoteraw
				}
				if verbose {
					fmt.Println("Error while attempting connect: " + err.Error())
				}
			}
			return nil
		}()
		if remoteraw == nil {
			panic("No available IPs for " + ctx.Req.URL.Hostname())
		}
		if verbose {
			log.Printf("Estabished remote connection for %s (%s)\n", ctx.Req.URL.Hostname(), remoteraw.RemoteAddr())
		}
		defer remoteraw.Close()

		remote := tls.Client(remoteraw, &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
					log.Printf("Refusing to connect to %s: Cert invalid: Remote certificate is for %s\n", ctx.Req.URL.Hostname(), certs[0].DNSNames)
				}
				return err
			},
		})
		orPanic(remote.Handshake())
		log.Printf("Handshake to %s succeeded:)\n", ctx.Req.URL.Hostname())
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

		if verbose {
			log.Println("Closing connection for " + ctx.Req.URL.Hostname())
		}
	})
	proxy.Verbose = verbose
	log.Fatal(http.ListenAndServe(*listen, proxy))
}
