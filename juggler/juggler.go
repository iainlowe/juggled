// Package juggler provides an HTTP/S virtual host mapper for connections to docker containers.
package juggler

import (
	"crypto/tls"
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

// The current library version.
var Version = "0.0.2"

type hosts struct {
	hosts []Host `json:"hosts"`
}

// The Host type is a mapped/exposed docker container.
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

// The Juggler type should not be used directly; instead, use NewJuggler to get instances of this type.
type Juggler struct {
	mapAll  bool   // Map all seen nodes
	sslCert string // Certificate file to use for TLS/SSL connections
	sslKey  string // Key file to use for TLS/SSL connections

	hosts map[string]*Host
}

// NewJuggler creates and initializes a new instance of the Juggler type.
func NewJuggler(cert, key string) *Juggler {
	return &Juggler{mapAll: true, sslCert: cert, sslKey: key, hosts: make(map[string]*Host)}
}

// BUG(ilowe): LoadHostmapFile should really support using the container name for convenience
// BUG(ilowe): loaded hosts need to be mapped to a name

// LoadHostmapFile loads host mappings from a .json file.
func (j Juggler) LoadHostmapFile(hostmapFile string) {
	if jsonSrc, err := ioutil.ReadFile(hostmapFile); err == nil {
		var h = &hosts{}
		json.Unmarshal(jsonSrc, &h)

		for i := range h.hosts {
			j.RegisterHost(h.hosts[i])
		}
	} else {
		log.Errorln(err)
	}
}

func handler(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Infoln(req.URL)
		rw.Header().Set("X-Proxied-By", fmt.Sprintf("juggler v%s", Version))
		proxy.ServeHTTP(rw, req)
	}
}

// Unregister removes the host mapping for the supplied hostID.
// If the hostID is not found in the current host map, the call is ignored
// (ie. it is safe to call this function with host IDs that don't exist).
func (j Juggler) Unregister(hostID string) {
	log.Debugln("unregistering", hostID)
	delete(j.hosts, hostID)
}

// Register creates a new container mapping.
func (j Juggler) Register(hostID, ipAddress string, requireSSL bool, requireAuth bool, names ...string) {
	host := newHost(hostID, ipAddress, requireSSL, requireAuth)
	for _, name := range names {
		j.hosts[name] = host
	}
	j.hosts[hostID] = host
	log.Infof("registered new host %s at IP %s (SSL: %v, BasicAuth: %v, Names: %v)\n", hostID, ipAddress, requireSSL, requireAuth, names)
}

// RegisterHost is a convenience function for registering existing instances of the Host type.
func (j Juggler) RegisterHost(h Host, names ...string) {
	j.Register(h.HostID, h.IPAddress, h.SSL, h.RequireAuth, names...)
}

/////////////////////////////////////////////

func (j Juggler) handleHTTPRequests(rw http.ResponseWriter, req *http.Request) {
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

// Juggle is the main entry point for juggling requests to docker containers.
// Calling this will start watching docker and serving HTTP/S requests.
func (j Juggler) Juggle(httpAddr, httpsAddr string) {
	go j.watchDocker()

	log.Infof("Starting HTTP/S endpoints on ports %s and %s...\n", httpAddr, httpsAddr)

	http.HandleFunc("/", j.handleHTTPRequests)

	sslServer := http.Server{
		Addr:      httpsAddr,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS10},
	}

	httpServer := http.Server{Addr: httpAddr}

	switch {
	case j.sslCert != "" && j.sslKey != "":
		go func() {
			if err := sslServer.ListenAndServeTLS(j.sslCert, j.sslKey); err != nil {
				log.Errorln("failed to start TLS/SSL:", err)
				os.Exit(-2)
			}
		}()
	case j.sslCert != "" || j.sslKey != "":
		log.Errorln("you must specify both a key and certificate in order to enable TLS/SSL")
		os.Exit(-1)
	}

	if err := httpServer.ListenAndServe(); err != nil {
		log.Errorln("failed to start HTTP server:", err)
		os.Exit(-3)
	}
}

func (j Juggler) handleDockerEvents(events chan event) {
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

			if (c.IP() != "" && j.mapAll) || !skip {
				names := []string{}
				names = append(names, c.Name[1:])

				iname := c.ID[:12]
				hname := c.Config.Hostname

				if iname != hname {
					names = append(names, hname)
				}

				j.Register(iname, c.IP(), ssl, auth, names...)
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

func (j Juggler) watchDocker() {
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
