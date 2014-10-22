package jongleur

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/ilowe/log"
)
import "encoding/json"

type event struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	container *container
}

type container struct {
	ID              string
	Image           string
	Config          *config
	NetworkSettings *networkSettings
}

type config struct {
	Hostname string
	Env      []string
}

type networkSettings struct {
	IPAddress   string
	PortMapping map[string]map[string]string
}

func (c container) HostID() string {
	return strings.Split(c.Config.Hostname, ".")[0]
}

func (c container) IP() string {
	return c.NetworkSettings.IPAddress
}

func watchDocker(events chan event) {
	c := http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}
	res, err := c.Get("http://localhost/events?since=1")
	if err != nil {
		log.Errorln(err)
	}
	defer res.Body.Close()

	d := json.NewDecoder(res.Body)
	log.Infoln("Watching docker container lifecycles...")

	for {
		var evt event
		if err := d.Decode(&evt); err != nil {
			if err == io.EOF {
				break
			}
			log.Errorln(err)
		}
		if container := inspectContainer(evt.ID, c); container != nil {
			evt.container = container
			events <- evt
		}
	}

	close(events)
}

func inspectContainer(id string, c http.Client) *container {
	// Use the container id to fetch the container json from the Remote API
	// http://docs.docker.io/en/latest/api/docker_remote_api_v1.4/#inspect-a-container
	res, err := c.Get("http://localhost/containers/" + id + "/json")
	if err != nil {
		log.Infoln(err)
		return nil
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		d := json.NewDecoder(res.Body)

		var container container
		if err = d.Decode(&container); err != nil {
			log.Error(err)
		}
		return &container
	}
	return nil
}
