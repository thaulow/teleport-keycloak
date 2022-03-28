package main

import (
	"container/list"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/seqsense/s3sync"
)

func main() {
	// artifactPath := "/artifacts"
	// bucketName := "aptly-test20220223185137234100000001"
	// localBucketPath := "/bucket"
	// majorVersion := "vTODO"
	// releaseChannel := "stable"
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
		},
	}

	args := parseFlags()

	awsSession := session.Must(session.NewSession())
	aptly := SetupAptly()

	downloadExistingRepo(awsSession, *args.bucketName, *args.localBucketPath)

	repos := list.New()

	// Recreate existing repos with existin debs
	for repo := range aptly.CreateReposFromBucket(*args.localBucketPath) {
		repoPath := filepath.Join(*args.localBucketPath, repo.PublishedRepoRelativePath())
		aptly.ImportDeb(repo.Name(), repoPath)
		repos.PushBack(repo)
	}

	// Create new repos that may be missing in the case we add more channels/OS specific support/major versions
	for repo := range aptly.CreateReposFromArtifactRequirements(supportedOSs, *args.releaseChannel, *args.majorVersion) {
		repos.PushBack(repo)
	}

	// Walk over the artifact filesystem tree and find debs
	err := filepath.WalkDir(*args.artifactPath,
		func(debPath string, d fs.DirEntry, err error) error {
			fmt.Println(debPath)
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			fileName := d.Name()
			if filepath.Ext(fileName) != ".deb" {
				return nil
			}

			// Import new artifacts into all repos that match the artifact's requirements
			for e := repos.Front(); e != nil; e = e.Next() {
				repo := e.Value.(*repo)

				// Other checks could be added here to ensure that a given deb gets added to the correct repo
				// such as name or parent directory, facilitating os-specific artifacts
				if repo.majorVersion != *args.majorVersion || repo.releaseChannel != *args.releaseChannel {
					continue
				}

				fmt.Println("importing deb")
				aptly.ImportDeb(repo.Name(), debPath)
			}

			return nil
		},
	)
	if err != nil {
		handleFatalError(err, "Failed to find and import debs")
	}

	// Build a map keyed by os info with value of all repos that support the os in the key
	// This will be used to structure the publish command
	categorizedRepos := make(map[string]*list.List)
	for e := repos.Front(); e != nil; e = e.Next() {
		r := e.Value.(*repo)

		if osRepos, ok := categorizedRepos[r.OSInfo()]; ok {
			osRepos.PushBack(r)
		} else {
			a := list.New()
			a.PushBack(r)
			categorizedRepos[r.OSInfo()] = a
		}
	}

	for os, osRepoList := range categorizedRepos {
		osRepoArray := make([]*repo, osRepoList.Len())
		fmt.Printf("%s %d %d\n", os, osRepoList.Len(), len(osRepoArray))

		// If anybody knows of a better way to write this loop please let me know
		i := 0
		for e := osRepoList.Front(); e != nil; e = e.Next() {
			fmt.Printf("%d %s\n", i, e.Value.(*repo).osVersion)
			osRepoArray[i] = e.Value.(*repo)
			i++
		}

		aptly.PublishRepos(osRepoArray)
	}

	syncExistingRepo(awsSession, *args.bucketName, filepath.Join(aptly.GetRootDir(), "public"))
}

func downloadExistingRepo(awsSession *session.Session, bucketName string, localPath string) {
	EnsureDirectoryExists(localPath)

	bucketPath := fmt.Sprintf("s3://%s", bucketName)
	syncManager := s3sync.New(awsSession)
	err := syncManager.Sync(bucketPath, localPath)
	if err != nil {
		handleFatalError(err, "Failed to sync \"%s\" to \"%s\"", bucketPath, localPath)
	}
}

func syncExistingRepo(awsSession *session.Session, bucketName string, localPath string) {
	bucketPath := fmt.Sprintf("s3://%s", bucketName)
	syncManager := s3sync.New(awsSession)
	err := syncManager.Sync(localPath, bucketPath)
	if err != nil {
		handleFatalError(err, "Failed to sync \"%s\" to \"%s\"", localPath, bucketName)
	}
}
