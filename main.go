package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
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
	Config.DNSEndpoint = *endpoint
	Config.Verbose = verbosevar.Get().(bool)

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest(
		goproxy.ReqHostIs("go-pixiv.local"),
	).DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		client := http.Client{}
		r.URL.Host = "127.0.0.1:8081"
		req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		req.Header.Add("X-Proxy-Thru", "1")
		resp, err := client.Do(req)
		if err != nil {
			return r, nil
		}
		resp.Header.Add("X-Proxy-Thru", "1")
		resp.Header.Add("Access-Control-Allow-Origin", "*")
		return r, resp
	})

	proxy.OnRequest(
		goproxy.ReqHostIs("go-pixiv.local:443"),
	).HijackConnect(func(req *http.Request, clientraw net.Conn, ctx *goproxy.ProxyCtx) {
		cfg, err := goproxy.TLSConfigFromCA(&goproxy.GoproxyCa)("go-pixiv.local", ctx)
		if err != nil {
			log.Panicln(err)
		}
		server := tls.Server(clientraw, cfg)
		body := ""
		resp := &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          ioutil.NopCloser(bytes.NewBufferString(body)),
			ContentLength: int64(len(body)),
			Request:       req,
			Header:        make(http.Header, 0),
		}
		resp.Header.Add("Access-Control-Allow-Origin", "*")
		resp.Write(server)
		server.CloseWrite()
	})

	proxy.OnRequest(
		goproxy.ReqHostIs(BlackHoleDomainsWithPort...),
	).HandleConnect(goproxy.AlwaysReject)

	proxy.OnRequest(
		goproxy.ReqHostIs(PixivDomainsWithPort...),
	).HijackConnect(func(req *http.Request, clientraw net.Conn, ctx *goproxy.ProxyCtx) {
		defer func() {
			if e := recover(); e != nil {
				ctx.Logf("error connecting to remote: %v", e)
				if Config.Verbose {
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
					if Config.Verbose {
						log.Println("Successfully retrieved IP cache for " + ctx.Req.URL.Hostname())
					}
					return remoteraw
				}
			}
			query := DNSQuery{
				ctx.Req.URL.Hostname(),
				"A",
				Config.DNSEndpoint,
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
				if Config.Verbose {
					fmt.Println("Error while attempting connect: " + err.Error())
				}
			}
			return nil
		}()
		if remoteraw == nil {
			panic("No available IPs for " + ctx.Req.URL.Hostname())
		}
		if Config.Verbose {
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

		if Config.Verbose {
			log.Println("Closing connection for " + ctx.Req.URL.Hostname())
		}
	})
	proxy.Verbose = Config.Verbose

	go func() {
		managemux := http.NewServeMux()
		managemux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Proxy-Thru") == "" {
				// No proxy, check proxy config with fetch
				w.Header().Add("Content-Type", "text/html")
				w.WriteHeader(200)
				w.Write([]byte(`
				<noscript>
					Javascript is disabled. Go-Pixiv should work without it.
				</noscript>
				<script>
					fetch("http://go-pixiv.local").then(()=>{
						window.location.href="http://go-pixiv.local/"
					}).catch(()=>{
						document.body.innerHTML="Proxy is not enabled, please set your local proxy to http://127.0.0.1:8080/"
					})
				</script>`))
				return
			}

			tpl, err := template.New("Manage-Main").Parse(`
			<html>
				<head>
					<title>Go-Pixiv</title>
					<style>
						.ok {
							color: green;
						}
						.error {
							color: red;
						}
						.testing {
							color: blue;
						}
					</style>
				</head>
				<body>
					<h1>Go-Pixiv</h1>
					<ul>
						<li>Proxy Configuation: <span class="ok">OK</span></li>
						<li>CA Trust: <span id="ca-test" class="testing">Testing...</span></li>
						<li>DNS-Over-HTTPS: <span id="dns-test" class="testing">Testing...</span>
							<ul>
								{{range .}}
									<li class="domain-test-item" data-domain='{{.}}'></li>
								{{end}}
							</ul>
						</li>
					</ul>
					<button id="btn-go" onclick="window.location.href='https://www.pixiv.net/'" style="display: none;">Go Pixiv!</button>
					<script>
						let testpromises = []
						testpromises.push(new Promise((resolve,reject)=>{
							fetch("https://go-pixiv.local/").then(()=>{
								document.querySelector("#ca-test").innerText = "OK";
								document.querySelector("#ca-test").setAttribute("class", "ok")
								resolve()
							}).catch(e=>{
								document.querySelector("#ca-test").innerHTML = "Error. Please check if you have the <a href=\"https://github.com/eternal-flame-AD/goproxy/raw/master/ca.pem\">CA certificate</a> installed properly.";
								document.querySelector("#ca-test").setAttribute("class", "error")
								reject()
							})
						}))
						let dnspromises = []
						for (let item of document.querySelectorAll(".domain-test-item")) {
							let host = item.getAttribute("data-domain");
							item.innerHTML = ` + "`" + `${host}: <span class="testing">Testing...<span>` + "`" + `
							dnspromises.push(new Promise((resolve, reject)=>{
								fetch("http://go-pixiv.local/dns?"+host).then(res=>res.json().then(data=>{
									item.innerHTML = ` + "`" + `${host}: <span class="${data.success?"ok":"error"}">${data.success?"OK":"Error"} (${data.data})</span>` + "`" + `
									resolve()
								})).catch(e=>{
									item.innerHTML = ` + "`" + `${host}: <span class="error">Error</span>` + "`" + `
									reject()
								})
							}))
						}
						Promise.all(dnspromises).then(()=>{
							document.querySelector("#dns-test").innerText = "OK";
							document.querySelector("#dns-test").setAttribute("class", "ok")
						}).catch(()=>{
							document.querySelector("#dns-test").innerText = "Error";
							document.querySelector("#dns-test").setAttribute("class", "error")
						})
						testpromises.push(...dnspromises)

						Promise.all(testpromises).then(()=>{
							document.querySelector("#btn-go").setAttribute("style", "")
						})
					</script>
				</body>
			</html>
			`)
			if err != nil {
				log.Println(err)
			}
			w.WriteHeader(200)
			tpl.Execute(w, PixivDomains)
		})

		managemux.HandleFunc("/dns", func(w http.ResponseWriter, r *http.Request) {
			host := r.URL.RawQuery

			response := struct {
				Success bool   `json:"success"`
				Data    string `json:"data"`
			}{}
			req := DNSQuery{
				host,
				"A",
				Config.DNSEndpoint,
				false,
				false,
			}
			res, err := req.Do()
			if err != nil {
				response.Data = err.Error()
				resp, _ := json.Marshal(response)
				w.WriteHeader(500)
				w.Write(resp)
				return
			}
			for _, item := range res.Answer {
				if item.Type != 1 {
					continue
				}

				remoteraw, err := net.Dial("tcp", item.Data+":443")
				if err != nil {
					response.Success = false
					response.Data = err.Error()
					continue
				}
				response.Success = true
				IPCache.Lock.Lock()
				IPCache.Data[host] = item.Data
				IPCache.Lock.Unlock()
				response.Data = item.Data
				remoteraw.Close()
				break
			}
			resp, err := json.Marshal(response)
			if err != nil {
				log.Println(err)
			}
			w.WriteHeader(200)
			w.Write(resp)
		})
		http.ListenAndServe("127.0.0.1:8081", managemux)
	}()
	go func() {
		openbrowser("http://127.0.0.1:8081")
	}()

	log.Fatal(http.ListenAndServe(*listen, proxy))
}
