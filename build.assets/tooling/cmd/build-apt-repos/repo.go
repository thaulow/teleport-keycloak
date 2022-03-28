package main

import (
	"fmt"
	"path/filepath"
)

type repo struct {
	os             string
	osVersion      string
	releaseChannel string
	majorVersion   string
}

func (r *repo) Name() string {
	return fmt.Sprintf("%s-%s-%s-%s", r.os, r.osVersion, r.releaseChannel, r.majorVersion)
}

func (r *repo) Component() string {
	return fmt.Sprintf("%s/%s", r.releaseChannel, r.majorVersion)
}

func (r *repo) OSInfo() string {
	return fmt.Sprintf("%s %s", r.os, r.osVersion)
}

func (r *repo) PublishedRepoRelativePath() string {
	// `./<os>/dists/<os version>/<release channel>/<major version>/`
	return filepath.Join(r.os, "dists", r.osVersion, r.releaseChannel, r.majorVersion)
}
