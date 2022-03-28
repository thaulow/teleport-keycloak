package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// This provides wrapper functions for the Aptly command. Aptly is written in Go but it doesn't appear
// to have a good binary API to use, only a CLI tool and REST API.

type Aptly struct{}

func SetupAptly() *Aptly {
	a := &Aptly{}
	a.EnsureDefaultConfigExists()
	// Additional config can be handled here if needed in the future
	return a
}

func (*Aptly) EnsureDefaultConfigExists() {
	// If the default config doesn't exist then it will be created the first time an Aptly command is
	// ran, which messes up the output.
	cmd := exec.Command("aptly", "repo", "list")
	err := cmd.Run()

	if err != nil {
		HandleFatalCommandError(err, "Failed to create default Aptly config", cmd)
	}
}

func (a *Aptly) CreateRepoIfNotExists(r *repo) bool {
	if a.DoesRepoExist(r) {
		fmt.Println("not creating repo")
		return false
	}

	fmt.Printf("Creating repo %s\n", r.Name())
	distributionArg := fmt.Sprintf("-distribution=%s", r.osVersion)
	componentArg := fmt.Sprintf("-component=%s/%s", r.releaseChannel, r.majorVersion)
	cmd := exec.Command("aptly", "repo", "create", distributionArg, componentArg, r.Name())
	err := cmd.Run()

	if err != nil {
		HandleFatalCommandError(err, "Failed to create repo \"%s\"", cmd, r.Name())
	}

	return true
}

func (a *Aptly) DoesRepoExist(r *repo) bool {
	repoName := r.Name()
	for _, existingRepoName := range a.GetExistingRepoNames() {
		if repoName == existingRepoName {
			return true
		}
	}

	return false
}

func (a *Aptly) GetExistingRepoNames() []string {

	// The output of the command will be simiar to:
	// ```
	// <repo name 1>
	// ...
	// <repo name N>
	// ```
	cmd := exec.Command("aptly", "repo", "list", "-raw")
	cmdOutput, err := cmd.Output()

	if err != nil {
		HandleFatalCommandError(err, "Failed to get a list of existing repos", cmd)
	}

	// Split the command output by new line
	return strings.Split(string(cmdOutput), "\n")
}

func (a *Aptly) ImportDeb(repoName string, debPath string) {
	cmd := exec.Command("aptly", "repo", "add", repoName, debPath)
	err := cmd.Run()

	if err != nil {
		HandleFatalCommandError(err, "Failed to add \"%s\" to repo \"%s\"", cmd, debPath, repoName)
	}
}

// Is there a more idiomatic way of writing this?
func (a *Aptly) PublishRepos(repos []*repo) {
	repoNames := make([]string, len(repos))
	for i, repo := range repos {
		repoNames[i] = repo.Name()
	}

	args := []string{"publish", "repo"}
	if len(repos) > 1 {
		componentsArgument := fmt.Sprintf("-component=%s", strings.Repeat(",", len(repos)-1))
		args = append(args, componentsArgument)
	}
	args = append(args, repoNames...)
	args = append(args, repos[0].os)

	cmd := exec.Command("aptly", args...)
	err := cmd.Run()

	if err != nil {
		HandleFatalCommandError(err, "Failed to publish repos", cmd)
	}
}

func (a *Aptly) GetRootDir() string {
	cmd := exec.Command("aptly", "config", "show")
	output, err := cmd.Output()

	if err != nil {
		HandleFatalCommandError(err, "Failed retrieve Aptly config info", cmd)
	}

	var outputJson map[string]interface{}
	err = json.Unmarshal(output, &outputJson)
	if err != nil {
		handleFatalError(err, "Failed to unmarshal `%s` output JSON into map", strings.Join(cmd.Args, " "))
	}

	if rootDirValue, ok := outputJson["rootDir"]; !ok {
		HandleFatalIssue("Failed to find `rootDir` key in `%s` output JSON", strings.Join(cmd.Args, " "))
	} else {
		if rootDirString, ok := rootDirValue.(string); !ok {
			HandleFatalIssue("The `rootDir` key in `%s` output JSON is not of type `string`", strings.Join(cmd.Args, " "))
		} else {
			return rootDirString
		}
	}

	HandleFatalIssue("This code path should never be hit")
	return ""
}

func (a *Aptly) CreateReposFromBucket(bucketPath string) <-chan *repo {
	// The file tree that we care about here will be of the following structure:
	// `/<bucketPath>/<os>/dists/<os version>/<release channel>/<major version>/...`

	out := make(chan *repo)

	go func() {
		defer close(out)
		for os := range GetSubdirectories(bucketPath) {
			osVersionParentDirectory := filepath.Join(bucketPath, os, "dists")
			for osVersion := range GetSubdirectories(osVersionParentDirectory) {
				releaseChannelParentDirectory := filepath.Join(osVersionParentDirectory, osVersion)
				for releaseChannel := range GetSubdirectories(releaseChannelParentDirectory) {
					majorVersionParentDirectory := filepath.Join(releaseChannelParentDirectory, releaseChannel)
					for majorVersion := range GetSubdirectories(majorVersionParentDirectory) {
						r := &repo{
							os:             os,
							osVersion:      osVersion,
							releaseChannel: releaseChannel,
							majorVersion:   majorVersion,
						}

						if a.CreateRepoIfNotExists(r) {
							out <- r
						}
					}
				}
			}
		}
	}()

	return out
}

func (a *Aptly) CreateReposFromArtifactRequirements(supportedOSInfo map[string][]string,
	releaseChannel string, majorVersion string) <-chan *repo {
	out := make(chan *repo)

	go func() {
		defer close(out)
		for os, osVersions := range supportedOSInfo {
			for _, osVersion := range osVersions {
				r := &repo{
					os:             os,
					osVersion:      osVersion,
					releaseChannel: releaseChannel,
					majorVersion:   majorVersion,
				}

				if a.CreateRepoIfNotExists(r) {
					out <- r
				}
			}
		}
	}()

	return out
}
