package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	docker "github.com/ilowe/jongleur/docker"
	"github.com/ilowe/log"
)

type Handler func(rw http.ResponseWriter, req *http.Request)
type HostMap map[string]Handler

var Version = "0.0.1"

func handler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Infoln(req.URL)
		rw.Header().Set("X-Proxied-By", fmt.Sprintf("jongleur v%s", Version))
		proxy.ServeHTTP(rw, req)
	}
}

var hostMap = make(HostMap)
var sslHostMap = make(HostMap)
var auth = make(map[string]bool)

func Unregister(container *docker.Container) {
	log.Debugln("unregistering", container.Id)
	host := getBaseHostname(container)
	delete(hostMap, host)
	delete(sslHostMap, host)
	delete(auth, host)
	log.Debugln("hosts:", hostMap)
	log.Debugln("SSL hosts:", sslHostMap)
	log.Infof("%s left all vhost clusters\n", host)
}

func getBaseHostname(container *docker.Container) string {
	return strings.Split(container.Config.Hostname, ".")[0]
}

func Register(container *docker.Container) {
	target, _ := url.Parse(fmt.Sprintf("http://%s", container.NetworkSettings.IpAddress))
	host := getBaseHostname(container)

	for i := range container.Config.Env {
		kv := strings.Split(container.Config.Env[i], "=")
		switch {
		case kv[0] == "VHOST" && kv[1] == "1":
			hostMap[host] = httputil.NewSingleHostReverseProxy(target).ServeHTTP
			log.Debugln("hosts:", hostMap)
			log.Infof("%s joined vhost cluster\n", host)

		case kv[0] == "VHOST_AUTH" && kv[1] == "1":
			auth[host] = true

		case kv[0] == "VHOST_SSL" && kv[1] == "1":
			sslHostMap[host] = httputil.NewSingleHostReverseProxy(target).ServeHTTP
			delete(hostMap, host)
			hostMap[host] = func(rw http.ResponseWriter, req *http.Request) {
				http.Redirect(rw, req, "https://"+req.Host+req.RequestURI, 302)
			}
			log.Debugln("hosts:", hostMap)
			log.Debugln("SSL hosts:", sslHostMap)
			log.Infof("%s joined SSL vhost cluster\n", host)

		}
	}
}

func dockerEventHandler(evt *docker.Event) {
	switch evt.Status {
	case "start":
		Register(evt.Container)
	case "die":
		Unregister(evt.Container)
	case "create":
	default:
		log.Debugf("don't know how to handle event status: %s", evt.Status)
	}
}

func dispatch(m HostMap, rw http.ResponseWriter, req *http.Request) {
	log.Debugln("dispatching")
	host := strings.Split(req.Host, ".")[0]

	_, authReq := auth[host]

	if h, ok := m[host]; ok {
		if authReq {
			checkAuth(h, rw, req)
		} else {
			h(rw, req)
		}
	} else {
		http.NotFound(rw, req)
	}
}

func checkAuth(h Handler, rw http.ResponseWriter, req *http.Request) {
	header, ok := req.Header["Authorization"]

	if !ok {
		http.Error(rw, "unauth", http.StatusUnauthorized)
		return
	}

	auth := strings.SplitN(header[0], " ", 2)

	if len(auth) != 2 || auth[0] != "Basic" {
		http.Error(rw, "unsupported", http.StatusBadRequest)
		return
	}

	payload, _ := base64.StdEncoding.DecodeString(auth[1])
	pair := strings.SplitN(string(payload), ":", 2)

	if len(pair) != 2 || !validate(pair[0], pair[1]) {
		http.Error(rw, "unauth", http.StatusUnauthorized)
		return
	}

	h(rw, req)
}

func validate(user string, pass string) bool {
	return user == "root" && pass == "winter"
}

func main() {
	var verbose, quiet bool
	var httpPort, httpsPort string

	flag.BoolVar(&verbose, "v", false, "be verbose")
	flag.BoolVar(&quiet, "q", false, "be quiet")

	flag.StringVar(&httpPort, "http-port", "80", "The port to listen on for HTTP connections")
	flag.StringVar(&httpsPort, "https-port", "443", "The port to listen on for HTTPS connections")

	flag.Parse()

	switch {
	case verbose:
		log.Verbose()
	case quiet:
		log.Quiet()
	default:
		log.Normal()
	}

	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		log.Debugln(req.TLS)
		if req.TLS == nil {
			dispatch(hostMap, rw, req)
		} else {
			dispatch(sslHostMap, rw, req)
		}
	})

	log.Infoln("Watching docker container lifecycles...")

	go docker.WatchDocker(dockerEventHandler)

	log.Infof("Starting HTTP/S endpoints on ports %s and %s...\n", httpPort, httpsPort)

	go http.ListenAndServe(":" + httpPort, nil)
	http.ListenAndServeTLS(":" + httpsPort, "secure.crt", "secure.key", nil)
	
}
