package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type arguments struct {
	artifactPath    *string
	bucketName      *string
	localBucketPath *string
	majorVersion    *string
	releaseChannel  *string
}

func parseFlags() *arguments {
	args := &arguments{
		artifactPath:    flag.String("artifact-path", "/artifacts", "Path to the filesystem tree containing the *.deb files to add to the APT repos"),
		bucketName:      flag.String("bucket", "", "The name of the S3 bucket where the repo should be synced to/from"),
		localBucketPath: flag.String("local-bucket-path", "/bucket", "The local path where the bucket should be synced to"),
		majorVersion:    flag.String("artifact-major-version", "", "The major version of the artifacts that will be added to the APT repos"),
		releaseChannel:  flag.String("artifact-release-channel", "", "The release channel of the APT repos that the artifacts should be added to"),
	}

	flag.Parse()
	validateArguments(args)
	return args
}

func validateArguments(args *arguments) {
	validateArtifactPath(args.artifactPath)
	validateBucketName(args.bucketName)
	validateLocalBucketPath(args.localBucketPath)
	validateMajorVersion(args.majorVersion)
	validateReleaseChannel(args.releaseChannel)
}

func validateArtifactPath(value *string) {
	validateNotEmtpy(value, "artifact-path")

	if stat, err := os.Stat(*value); os.IsNotExist(err) {
		handleInvalidFlag("The artifact-path \"%s\" does not exist", *value)
	} else if !stat.IsDir() {
		handleInvalidFlag("The artifact-path \"%s\" is not a directory", *value)
	}
}

func validateBucketName(value *string) {
	validateNotEmtpy(value, "bucket")
}

func validateLocalBucketPath(value *string) {
	validateNotEmtpy(value, "local-bucket-path")

	if stat, err := os.Stat(*value); err == nil && !stat.IsDir() {
		handleInvalidFlag("The local bucket path points to a file instead of a directory")
	}
}

func validateMajorVersion(value *string) {
	validateNotEmtpy(value, "artifact-major-version")

	// Can somebody validate that all major versions (even for dev tags/etc.) should follow this pattern?
	regex := `^v\d+$`
	matched, err := regexp.MatchString(regex, *value)
	if err != nil {
		handleFatalError(err, "Failed to validate the artifact major version flag via regex")
	}

	if !matched {
		handleInvalidFlag("The artifact major version flag does not match %s", regex)
	}
}

func validateReleaseChannel(value *string) {
	validateNotEmtpy(value, "artifact-release-channel")

	// Not sure what other channels we'd want to support, but they should be listed here
	validReleaseChannels := []string{"stable"}

	for _, validReleaseChannel := range validReleaseChannels {
		if *value == validReleaseChannel {
			return
		}
	}

	handleInvalidFlag("The release channel contains an invalid value. Valid values are: %s", strings.Join(validReleaseChannels, ","))
}

func validateNotEmtpy(value *string, flagName string) {
	if *value != "" {
		return
	}

	handleInvalidFlag("The %s flag should not be empty", flagName)
}

func handleInvalidFlag(message string, params ...interface{}) {
	flag.Usage()
	fmt.Println()
	HandleFatalIssue(message, params...)
}
