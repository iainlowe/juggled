/*
	The jongleur tool implements a basic command-line interface for the Jongleur library.

	Hosts File

	You can provide a hosts file to force certain types of mappings pre-hoc by providing
	a JSON file and using the --hostmap/-H flag when running jongleur from the command-line.

	The JSON should look like:

		{
			"hosts": [
				{
					"id": "68394fda8458",
					"ssl": true,
					"auth": false
				}
			]
		}

	NOTE: You need to use the ID of the container because it's a pain to search by name :)
*/
package main

import (
	"fmt"
	"os"

	flag "github.com/ogier/pflag"

	"github.com/ilowe/jongleur"
	"github.com/ilowe/log"
)

func main() {
	var verbose, quiet bool
	var httpPort, httpsPort string
	var sslCert, sslKey string

	var hostmapFile string
	var outputVersion bool

	flag.BoolVarP(&verbose, "verbose", "v", false, "be verbose")
	flag.BoolVarP(&quiet, "quiet", "q", false, "be quiet")
	flag.BoolVarP(&outputVersion, "version", "V", false, "output version and exit")

	flag.StringVarP(&hostmapFile, "hostmap", "H", "", "(optional) a file containing host mappings")

	flag.StringVarP(&httpPort, "http", "w", ":80", "The address to listen on for HTTP connections")
	flag.StringVarP(&httpsPort, "https", "s", ":443", "The address to listen on for HTTPS connections")

	flag.StringVarP(&sslCert, "sslCert", "c", "", "The certificate file to use for TLS/SSL")
	flag.StringVarP(&sslKey, "sslKey", "k", "", "The key file to use for TLS/SSL")

	flag.Parse()

	if outputVersion {
		fmt.Println(jongleur.Version)
		os.Exit(0)
	}

	switch {
	case verbose:
		log.Verbose()
	case quiet:
		log.Quiet()
	default:
		log.Normal()
	}

	j := jongleur.NewJongleur(sslCert, sslKey)

	if hostmapFile != "" {
		j.LoadHostmapFile(hostmapFile)
	}

	if httpPort == ":80" || httpsPort == ":443" && os.Geteuid() != 0 {
		log.Errorln("Non-root user cannot use ports under 1024!")
		os.Exit(-1)
	}

	j.Juggle(httpPort, httpsPort)
}
