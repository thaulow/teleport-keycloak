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
	"strconv"
	"strings"
	"text/template"

	"github.com/gravitational/trace"
)

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

	branches := findBranches(pull.UnsafeLabels)

	var statuses []Status
	for _, base := range branches {
		status := "Success"
		number, err := b.backportBranch(ctx,
			b.c.Environment.Organization,
			b.c.Environment.Repository,
			b.c.Environment.Number,
			pull.UnsafeTitle,
			base)
		if err != nil {
			status = "Failure"
			log.Printf("Failed to backport %v to %v: %v.", b.c.Environment.Number, base, err)
		}

		statuses = append(statuses, Status{
			Status: status,
			Branch: base,
			Link: url.URL{
				Scheme: "https",
				Host:   "github.com",
				Path:   path.Join(b.c.Environment.Organization, b.c.Environment.Repository, "pull", strconv.Itoa(number)),
			},
		})
	}

	err = b.updatePullRequest(ctx,
		b.c.Environment.Organization,
		b.c.Environment.Repository,
		b.c.Environment.Number,
		statuses)
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

	return branches
}

// TODO(russjones): Manually test backport logic to make sure it is robot in
// the case of failure to cherry-pick a commit.
func (b *Bot) backportBranch(ctx context.Context, organization string, repository string, number int, title string, base string) (int, error) {
	git("config", "--global", "user.email", "bot@goteleport.com")
	git("config", "--global", "user.name", "github-actions")

	head := fmt.Sprintf("bot/backport-%v", number)

	// Fetch base and head branches and create the backport branch that tracks
	// the branch the Pull Request will be backported to.
	// TODO(russjones): Check for injection attacks here.
	if err := git("fetch", "origin", base); err != nil {
		return 0, trace.Wrap(err)
	}
	if err := git("fetch", "origin", b.c.Environment.UnsafeHead); err != nil {
		return 0, trace.Wrap(err)
	}
	if err := git("checkout", "-b", head, "--track", fmt.Sprintf("origin/%v", base)); err != nil {
		return 0, trace.Wrap(err)
	}

	// Get list of commits to backport and cherry-pick to backport branch.
	commits, err := b.c.GitHub.ListCommits(ctx,
		organization,
		repository,
		number)
	if err != nil {
		return 0, trace.Wrap(err)
	}
	for _, commit := range commits {
		if err := git("cherry-pick", commit); err != nil {
			if err := git("cherry-pick", "--abort"); err != nil {
				log.Printf("Failed to cherry-pick: %v.", err)
				return 0, trace.Wrap(err)
			}
			return 0, trace.Wrap(err)
		}
	}

	// Push branch to origin (GitHub).
	if err := git("push", "origin", head); err != nil {
		return 0, trace.Wrap(err)
	}

	// Create Pull Request for backport.
	num, err := b.c.GitHub.CreatePullRequest(ctx,
		organization,
		repository,
		fmt.Sprintf("[%v] %v", strings.Trim(base, "branch/"), title),
		head,
		base,
		fmt.Sprintf("Backport #%v to %v", number, base))
	if err != nil {
		return 0, trace.Wrap(err)
	}
	return num, nil
}

// updatePullRequest will leave a comment on the Pull Request with the status
// of all backports.
func (b *Bot) updatePullRequest(ctx context.Context, organization string, repository string, number int, statuses []Status) error {
	var buf bytes.Buffer

	t := template.Must(template.New("table").Parse(table))
	if err := t.Execute(&buf, statuses); err != nil {
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
		log.Printf("git %v; failed with %v; %v", strings.Join(args, " "), err, string(out))
		return trace.Wrap(err)
	}
	return nil
}

type Status struct {
	Status string
	Branch string
	Link   url.URL
}

const table = `
| Status | Branch | Pull Request |
|--------|--------|--------------|
{{- range .}}
| {{.Status}} | {{.Branch}} | {{.Link}} |
{{- end}}`
