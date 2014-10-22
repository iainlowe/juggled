// Package jongleur provides an HTTP/S juggler for connections to docker containers.
package jongleur

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/ilowe/log"
)

// BUG(ilowe): you are expected to actually want TLS/SSL support so the cases where you don't use it are poorly handled

// Current library version
var Version = "0.0.2"

// container struct for loading hosts from .json files
type Hosts struct {
	Hosts []Host `json:"hosts",omitempty`
}

// mapped host for docker container
type Host struct {
	HostID      string `json:"id"`
	IPAddress   string `json:"ip"`
	SSL         bool   `json:"ssl",omitempty`
	RequireAuth bool   `json:"auth",omitempty`
	handle      func(rw http.ResponseWriter, req *http.Request)
}

func newHost(HostID, IPAddress string, SSL bool, RequireAuth bool) *Host {
	target, _ := url.Parse(fmt.Sprintf("http://%s", IPAddress))
	handle := httputil.NewSingleHostReverseProxy(target).ServeHTTP

	return &Host{
		HostID:      HostID,
		IPAddress:   IPAddress,
		SSL:         SSL,
		RequireAuth: RequireAuth,
		handle:      handle,
	}
}

type Jongleur struct {
	sslCert string // Certificate file to use for TLS/SSL connections
	sslKey  string // Key file to use for TLS/SSL connections

	hosts map[string]*Host
}

func NewJongleur(cert, key string) *Jongleur {
	return &Jongleur{sslCert: cert, sslKey: key, hosts: make(map[string]*Host)}
}

// BUG(ilowe): LoadHostmapFile should really support using the container name for convenience

// Loads host mappings from a JSON file
func (j Jongleur) LoadHostmapFile(hostmapFile string) {
	if jsonSrc, err := ioutil.ReadFile(hostmapFile); err == nil {
		var hosts = &Hosts{}
		json.Unmarshal(jsonSrc, &hosts)

		for i := range hosts.Hosts {
			j.RegisterHost(hosts.Hosts[i])
		}
	} else {
		log.Errorln(err)
	}
}

func handler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Infoln(req.URL)
		rw.Header().Set("X-Proxied-By", fmt.Sprintf("jongleur v%s", Version))
		proxy.ServeHTTP(rw, req)
	}
}

// Removes the host mapping for the supplied hostID.
// If the hostID is not found in the current host map, the call is ignored.
func (j Jongleur) Unregister(hostID string) {
	log.Debugln("unregistering", hostID)
	delete(j.hosts, hostID)
}

// Registers a new host mapping for the supplied container
func (j Jongleur) Register(hostID, ipAddress string, requireSSL bool, requireAuth bool) {
	j.hosts[hostID] = newHost(hostID, ipAddress, requireSSL, requireAuth)
	log.Infof("registered new host %s at IP %s (SSL: %v, BasicAuth: %v)\n", hostID, ipAddress, requireSSL, requireAuth)
}

// Convenience function for registering existing host structs.
func (j Jongleur) RegisterHost(h Host) {
	j.Register(h.HostID, h.IPAddress, h.SSL, h.RequireAuth)
}

/////////////////////////////////////////////

func (j Jongleur) handleHTTPRequests(rw http.ResponseWriter, req *http.Request) {
	requestedHostID := strings.Split(req.Host, ".")[0]

	if host, ok := j.hosts[requestedHostID]; ok {
		switch {
		case host.SSL && req.TLS == nil:
			http.Redirect(rw, req, "https://"+req.Host+req.RequestURI, 302)
		default:
			host.handle(rw, req)
		}
	} else {
		http.NotFound(rw, req)
	}
}

// Main entry point for juggling requests to docker containers
//
// Calling this will start watching docker and will start serving HTTP/S requests.
func (j Jongleur) Juggle(httpAddr, httpsAddr string) {
	go j.watchDocker()

	log.Infof("Starting HTTP/S endpoints on ports %s and %s...\n", httpAddr, httpsAddr)
	http.HandleFunc("/", j.handleHTTPRequests)

	switch {
	case j.sslCert != "" && j.sslKey != "":
		go http.ListenAndServeTLS(httpsAddr, j.sslCert, j.sslKey, nil)
	case j.sslCert != "" || j.sslKey != "":
		log.Errorln("you must specify both a key and certificate in order to enable TLS/SSL")
		os.Exit(-1)
	}

	http.ListenAndServe(httpAddr, nil)
}

func (j Jongleur) handleDockerEvents(events chan event) {
	var evt event

	for {
		evt = <-events

		switch evt.Status {
		case "start":
			skip := true
			auth := false
			ssl := false
			c := evt.container

			for i := range c.Config.Env {
				kv := strings.Split(c.Config.Env[i], "=")

				switch {
				case kv[0] == "VHOST" && kv[1] == "1":
					skip = false
				case kv[0] == "VHOST_AUTH" && kv[1] == "1":
					skip = false
					auth = true
				case kv[0] == "VHOST_SSL" && kv[1] == "1":
					skip = false
					ssl = true
				}
			}

			if !skip {
				j.Register(c.HostID(), c.IP(), ssl, auth)
			} else if h, ok := j.hosts[c.HostID()]; ok {
				h.IPAddress = c.HostID()
				h.SSL = ssl
				h.RequireAuth = auth
			}
		case "die":
			j.Unregister(evt.container.HostID())
		default:
			log.Debugf("don't know how to handle event status: %s", evt.Status)
		}
	}
}

func (j Jongleur) watchDocker() {
	var events = make(chan event)

	go watchDocker(events)
	go j.handleDockerEvents(events)
}

///////////////////// Auth stuff

func checkAuth(h func(rw http.ResponseWriter, req *http.Request), rw http.ResponseWriter, req *http.Request) {
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
