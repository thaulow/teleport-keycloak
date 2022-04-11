package main

import (
	"os"

	log "github.com/sirupsen/logrus"
)

func main() {
	supportedOSs := map[string][]string{
		"debian": {
			"stretch",
			"buster",
			"bullseye",
			"bookwork",
			"trixie",
		},
		"ubuntu": {
			"xenial",
			"yakkety",
			"zesty",
			"artful",
			"bionic",
			"cosmic",
			"disco",
			"eoan",
			"focal",
			"groovy",
			"hirsuite",
			"impish",
			"jammy",
		},
	}

	config, err := ParseFlags()
	if err != nil {
		log.Fatal(err.Error())
	}

	setupLogger(config)

	art, err := NewAptRepoTool(config, &supportedOSs)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = art.Run()
	if err != nil {
		log.Fatal(err.Error())
	}
}

func setupLogger(config *Config) {
	if *config.logJson {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{})
	}
	log.SetOutput(os.Stdout)
	log.SetLevel(log.Level(*config.logLevel))
}
