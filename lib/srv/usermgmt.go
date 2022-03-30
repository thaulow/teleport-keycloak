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

package srv

import (
	"context"
	"errors"
	"io"
	"os/user"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/siddontang/go/log"
)

// NewHostUsers initialize a new HostUsers object
func NewHostUsers(ctx context.Context) (HostUsers, error) {
	backend, err := newHostUsersBackend()
	if err != nil {
		return nil, err
	}
	cancelCtx, cancelFunc := context.WithCancel(ctx)
	return &HostUserManagment{
		backend: backend,
		ctx:     cancelCtx,
		cancel:  cancelFunc,
	}, nil
}

type HostUsersBackend interface {
	// GetAllUsers returns all host users on a node.
	GetAllUsers() ([]string, error)
	// UserGIDs returns a list of group ids for a user.
	UserGIDs(*user.User) ([]string, error)
	// Lookup retrieves a user by name.
	Lookup(name string) (*user.User, error)
	// LookupGroup retrieves a group by name.
	LookupGroup(group string) (*user.Group, error)
	// CreateGroup creates a group on a host.
	CreateGroup(group string) error
	// CreateUser creates a user on a host.
	CreateUser(name string, groups []string) error
	// DeleteUser deletes a user from a host.
	DeleteUser(name string) error
}

// HostUsersProvisioningBackend is used to implement HostUsersBackend
type HostUsersProvisioningBackend struct{}

type userCloser struct {
	users    HostUsers
	backend  HostUsersBackend
	username string
}

func (u *userCloser) Close() error {
	teleportGroup, err := u.backend.LookupGroup(types.TeleportServiceGroup)
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(u.users.DeleteUser(u.username, teleportGroup.Gid))
}

var ErrUserLoggedIn = errors.New("User logged in error")

type HostUsers interface {
	// CreateUser creates a temporary Teleport user in the TeleportServiceGroup
	CreateUser(name string, hostRoleInfo *services.HostUsersInfo) (io.Closer, error)
	// DeleteUser deletes a temporary Teleport user only if they are
	// in a specified group
	DeleteUser(name string, gid string) error
	// DeleteAllUsers deletes all suer in the TeleportServiceGroup
	DeleteAllUsers() error
	// UserCleanup starts a periodic user deletion cleanup loop for
	// users that failed to delete
	UserCleanup()
	// Shutdown cancels the UserCleanup loop
	Shutdown()
}

type HostUserManagment struct {
	backend HostUsersBackend
	ctx     context.Context
	cancel  context.CancelFunc
}

var _ HostUsers = &HostUserManagment{}

// CreateUser creates a temporary Teleport user in the TeleportServiceGroup
func (u *HostUserManagment) CreateUser(name string, ui *services.HostUsersInfo) (io.Closer, error) {
	tempUser, err := u.backend.Lookup(name)
	if err != nil && err != user.UnknownUserError(name) {
		return nil, trace.Wrap(err)
	}
	if tempUser != nil {
		// try to delete even if the user already exists as only users
		// in the teleport-system group will be deleted and this way
		// if a user creates multiple sessions the account will
		// succeed in deletion
		return &userCloser{
			username: name,
			users:    u,
			backend:  u.backend,
		}, trace.AlreadyExists("User already exists")
	}

	groups := append(ui.Groups, types.TeleportServiceGroup)
	var errs []error
	for _, group := range groups {
		if err := u.createGroupIfNotExist(group); err != nil {
			errs = append(errs, err)
			continue
		}
	}
	if err := trace.NewAggregate(errs...); err != nil {
		return nil, trace.WrapWithMessage(err, "error while creating groups")
	}

	err = u.backend.CreateUser(name, groups)
	if err != nil && !trace.IsAlreadyExists(err) {
		return nil, trace.WrapWithMessage(err, "error while creating user")
	}
	return &userCloser{
		username: name,
		users:    u,
		backend:  u.backend,
	}, nil
}

func (u *HostUserManagment) createGroupIfNotExist(group string) error {
	_, err := u.backend.LookupGroup(group)
	if err != nil && err != user.UnknownGroupError(group) {
		return trace.Wrap(err)
	}
	err = u.backend.CreateGroup(group)
	if trace.IsAlreadyExists(err) {
		return nil
	}
	return trace.Wrap(err)
}

// DeleteAllUsers deletes all host users in the teleport service group.
func (u *HostUserManagment) DeleteAllUsers() error {
	users, err := u.backend.GetAllUsers()
	if err != nil {
		return trace.Wrap(err)
	}
	teleportGroup, err := u.backend.LookupGroup(types.TeleportServiceGroup)
	if err != nil {
		return trace.Wrap(err)
	}
	var errs []error
	for _, name := range users {
		errs = append(errs, u.DeleteUser(name, teleportGroup.Gid))
	}
	return trace.NewAggregate(errs...)
}

// DeleteUser deletes the user only if they are
// present in the specified group
func (u *HostUserManagment) DeleteUser(username string, gid string) error {
	tempUser, err := u.backend.Lookup(username)
	if err != nil {
		return trace.Wrap(err)
	}
	ids, err := u.backend.UserGIDs(tempUser)
	if err != nil {
		return trace.Wrap(err)
	}
	for _, id := range ids {
		if id == gid {
			err := u.backend.DeleteUser(username)
			if errors.Is(err, ErrUserLoggedIn) {
				log.Warnf("Not deleting user %q, user has another session, or running process", username)
				return nil
			}
			return trace.Wrap(err)
		}
	}
	log.Debugf("User %q not deleted: not a temporary user", username)
	return nil
}

// UserCleanup starts a periodic user deletion cleanup loop for
// users that failed to delete
func (u *HostUserManagment) UserCleanup() {
	cleanupTicker := time.NewTicker(time.Minute * 5)
	defer cleanupTicker.Stop()
	for {
		select {
		case <-cleanupTicker.C:
			if err := u.DeleteAllUsers(); err != nil {
				log.Error("Error during temporary user cleanup: ", err)
			}
		case <-u.ctx.Done():
			return
		}
	}
}

// Shutdown cancels the UserCleanup loop
func (u *HostUserManagment) Shutdown() {
	u.cancel()
}
