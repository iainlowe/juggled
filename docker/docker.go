package jongleur

import (
	"encoding/json"
	"github.com/ilowe/log"
	"io"
	"net/http"
	"net"
)

type Event struct {
	Id        string `json:"id"`
	Status    string `json:"status"`
	Container *Container
}

type Config struct {
	Hostname string
	Env      []string
}

type NetworkSettings struct {
	IpAddress   string
	PortMapping map[string]map[string]string
}

type Container struct {
	Id              string
	Image           string
	Config          *Config
	NetworkSettings *NetworkSettings
}

func inspectContainer(id string, c http.Client) *Container {
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

		var container Container
		if err = d.Decode(&container); err != nil {
			log.Error(err)
		}
		return &container
	}
	return nil
}


func WatchDocker(handler func(evt *Event)) {
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
	for {
		var event Event
		if err := d.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			log.Errorln(err)
		}
		if container := inspectContainer(event.Id, c); container != nil {
			event.Container = container
			handler(&event)
		}
	}
}
