/*
Copyright 2022 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bot

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/url"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/gravitational/trace"
)

// TODO(russjones): Validate user controlled input.
func (b *Bot) Backport(ctx context.Context) error {
	if !b.c.Review.IsInternal(b.c.Environment.Author) {
		return trace.BadParameter("automatic backports are only supported for internal contributors")
	}

	pull, err := b.c.GitHub.GetPullRequest(ctx,
		b.c.Environment.Organization,
		b.c.Environment.Repository,
		b.c.Environment.Number)
	if err != nil {
		return trace.Wrap(err)
	}

	// Extract backport branches names from labels attached to the Pull
	// Request. If no backports were requested, return right away.
	branches := findBranches(pull.UnsafeLabels)
	if len(branches) == 0 {
		return nil
	}

	var rows []row

	for _, base := range branches {
		head := fmt.Sprintf("bot/backport-%v-%v", b.c.Environment.Number, base)

		r := row{
			Result: "Success",
			Branch: base,
		}

		// Create and push git branch for backport to GitHub.
		err := b.createBackportBranch(ctx,
			b.c.Environment.Organization,
			b.c.Environment.Repository,
			b.c.Environment.Number,
			pull.UnsafeTitle,
			base,
			b.c.Environment.UnsafeHead,
			head,
		)
		if err != nil {
			r.Result = "Failure"
			r.Error = err

			rows = append(rows, r)
			continue
		}

		// Create Pull Request for backport.
		number, err := b.c.GitHub.CreatePullRequest(ctx,
			b.c.Environment.Organization,
			b.c.Environment.Repository,
			fmt.Sprintf("[%v] %v", strings.Trim(base, "branch/"), pull.UnsafeTitle),
			head,
			base,
			fmt.Sprintf("Backport #%v to %v", b.c.Environment.Number, base))
		if err != nil {
			r.Result = "Failure"
			r.Error = err

			rows = append(rows, r)
			continue
		}

		r.Link = url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   path.Join(b.c.Environment.Organization, b.c.Environment.Repository, "pull", strconv.Itoa(number)),
		}
		rows = append(rows, r)
	}

	err = b.updatePullRequest(ctx,
		b.c.Environment.Organization,
		b.c.Environment.Repository,
		b.c.Environment.Number,
		data{
			Author: b.c.Environment.Author,
			Rows:   rows,
		})
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// findBranches looks through the labels attached to a Pull Request for all the
// backport branches the user requested.
func findBranches(labels []string) []string {
	var branches []string

	for _, label := range labels {
		if !strings.HasPrefix(label, "backport/") {
			continue
		}

		branches = append(branches, strings.TrimPrefix(label, "backport/"))
	}

	sort.Strings(branches)

	return branches
}

// createBackportBranch will create and push a git branch with all the commits
// from a Pull Request on it.
//
// TODO(russjones): Refactor to use go-git (so similar git library) instead of
// executing git from disk.
func (b *Bot) createBackportBranch(ctx context.Context, organization string, repository string, number int, title string, base string, head string, newHead string) error {
	if err := git("config", "--global", "user.name", "github-actions"); err != nil {
		log.Printf("Failed to set user.name: %v.", err)
	}
	if err := git("config", "--global", "user.email", "github-actions@goteleport.com"); err != nil {
		log.Printf("Failed to set user.email: %v.", err)
	}

	// Fetch base and head branches and create new backport branch that tracks
	// the branch the Pull Request will be backported to.
	if err := git("fetch", "origin", base, head); err != nil {
		return trace.Wrap(err)
	}
	if err := git("checkout", "-b", newHead, "--track", fmt.Sprintf("origin/%v", base)); err != nil {
		return trace.Wrap(err)
	}

	// Get list of commits to backport and cherry-pick to backport branch.
	commits, err := b.c.GitHub.ListCommits(ctx,
		organization,
		repository,
		number)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, commit := range commits {
		if err := git("cherry-pick", commit); err != nil {
			if er := git("cherry-pick", "--abort"); er != nil {
				return trace.NewAggregate(err, er)
			}
			return trace.BadParameter("failed to cherry-pick %v", commit)
		}
	}

	// Push branch to origin (GitHub).
	if err := git("push", "origin", newHead); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// updatePullRequest will leave a comment on the Pull Request with the status
// of all backports.
func (b *Bot) updatePullRequest(ctx context.Context, organization string, repository string, number int, d data) error {
	var buf bytes.Buffer

	t := template.Must(template.New("table").Parse(table))
	if err := t.Execute(&buf, d); err != nil {
		return trace.Wrap(err)
	}

	err := b.c.GitHub.CreateComment(ctx,
		organization,
		repository,
		number,
		buf.String())
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func git(args ...string) error {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return trace.BadParameter(string(out))
	}
	return nil
}

type data struct {
	// Author of the Pull Request. If set, used to @author on GitHub so they
	// get a notification.
	Author string

	// Rows represent backports.
	Rows []row
}

type row struct {
	// Result of the backport, either "Success" or "Failure".
	Result string

	// Output is set when "Result" is "Failure" and contains stdout and stderr
	// from "git" with details why the cherry-pick failed.
	Error error

	// Branch is the name of the backport branch.
	Branch string

	// Link is a URL pointing to the created backport Pull Request.
	Link url.URL
}

const table = `
{{if ne .Author ""}}
@{{.Author}} Some backports failed, see table below.
{{end}}

| Result | Branch | Pull Request | Error |
|--------|--------|--------------|-------|
{{- range .Rows}}
| {{.Result}} | {{.Branch}} | {{.Link}} | {{.Error}} |
{{- end}}
`
