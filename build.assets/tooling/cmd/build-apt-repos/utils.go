package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
)

func GetSubdirectories(basePath string) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)

		files, err := ioutil.ReadDir(basePath)
		if err != nil {
			handleFatalError(err, "Failed to read directory \"%s\"", basePath)
		}

		for _, file := range files {
			if !file.IsDir() {
				continue
			}

			out <- file.Name()
		}
	}()

	return out
}

func EnsureDirectoryExists(path string) {
	err := os.MkdirAll(path, 0660)
	if err != nil {
		handleFatalError(err, "Failed to create directory \"%s\"", path)
	}
}

func HandleFatalCommandError(err error, message string, command *exec.Cmd, params ...interface{}) {
	commandRan := strings.Join(command.Args, " ")
	handleFatalError(err, fmt.Sprintf("%s. Command ran: \"%s\"", message, commandRan), params...)
}

func handleFatalError(err error, message string, params ...interface{}) {
	HandleFatalIssue(fmt.Sprintf("%s. Error: %v\n", message, err), params...)
}

func HandleFatalIssue(message string, params ...interface{}) {
	fmt.Printf(message, params...)
	fmt.Println()
	debug.PrintStack()
	os.Exit(1)
}
