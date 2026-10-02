package panel

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/panelkey"
	"github.com/veylvpn/backend/internal/web"
)

var (
	errLastOwner = errors.New("last owner")
	errTaken     = errors.New("username taken")
	errNoUser    = errors.New("no such user")
)

type userOut struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Created   int64  `json:"created"`
	LastLogin int64  `json:"last_login"`
	TwoFactor bool   `json:"two_factor"`
	Sessions  int    `json:"sessions"`
}

type inviteOut struct {
	ID      string `json:"id"`
	Role    string `json:"role"`
	Note    string `json:"note"`
	By      string `json:"by"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
}

func (p *Panel) team(w http.ResponseWriter, r *http.Request) {
	users := []userOut{}
	invites := []inviteOut{}
	p.db.View(func(d *data) {
		for _, u := range d.Users {
			o := userOut{ID: u.ID, Username: u.Username, Role: u.Role, Created: u.Created, LastLogin: u.LastLogin, TwoFactor: u.TOTP != "" && !u.MustEnroll}
			for _, s := range d.Sessions {
				if s.UserID == u.ID {
					o.Sessions++
				}
			}
			users = append(users, o)
		}
		for _, i := range d.Invites {
			if i.Expires > p.now().Unix() {
				invites = append(invites, inviteOut{ID: i.ID, Role: i.Role, Note: i.Note, By: i.By, Created: i.Created, Expires: i.Expires})
			}
		}
	})
	sort.Slice(users, func(i, j int) bool {
		if roleLevel[users[i].Role] != roleLevel[users[j].Role] {
			return roleLevel[users[i].Role] > roleLevel[users[j].Role]
		}
		return users[i].Username < users[j].Username
	})
	web.JSON(w, http.StatusOK, map[string]any{"users": users, "invites": invites})
}

type inviteIn struct {
	Role string `json:"role"`
	Note string `json:"note"`
}

func (p *Panel) createInvite(w http.ResponseWriter, r *http.Request) {
	var in inviteIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if _, ok := roleLevel[in.Role]; !ok {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Pick a role: owner, admin or viewer.")
		return
	}
	in.Note = panelkey.CleanName(in.Note)
	a := current(r)
	t := randToken(32)
	now := p.now()
	inv := TeamInvite{ID: randID(), Hash: hashToken(t), Role: in.Role, Note: in.Note, By: a.User.Username, Created: now.Unix(), Expires: now.Add(InviteTTL).Unix()}
	if err := p.db.Update(func(d *data) error {
		if len(d.Invites) >= 50 {
			d.Invites = d.Invites[1:]
		}
		d.Invites = append(d.Invites, inv)
		return nil
	}); err != nil {
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Could not create the invite.")
		return
	}
	p.audit(a.User.Username, "team.invite", in.Role, in.Note)
	web.JSON(w, http.StatusCreated, map[string]any{"token": t, "path": "join#" + t, "expires": inv.Expires, "id": inv.ID})
}

func (p *Panel) deleteInvite(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	_ = p.db.Update(func(d *data) error {
		keep := d.Invites[:0]
		for _, i := range d.Invites {
			if i.ID == id {
				found = true
				continue
			}
			keep = append(keep, i)
		}
		d.Invites = keep
		return nil
	})
	if !found {
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "That invite no longer exists.")
		return
	}
	p.audit(current(r).User.Username, "team.invite.delete", id, "")
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type roleIn struct {
	Role string `json:"role"`
}

func (p *Panel) patchUser(w http.ResponseWriter, r *http.Request) {
	var in roleIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	if _, ok := roleLevel[in.Role]; !ok {
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Pick a role: owner, admin or viewer.")
		return
	}
	id := r.PathValue("id")
	name := ""
	err := p.db.Update(func(d *data) error {
		u := d.user(id)
		if u == nil {
			return errNoUser
		}
		if u.Role == RoleOwner && in.Role != RoleOwner && d.owners() <= 1 {
			return errLastOwner
		}
		u.Role = in.Role
		u.Epoch = randID()
		name = u.Username
		return nil
	})
	if !p.teamErr(w, err) {
		return
	}
	p.audit(current(r).User.Username, "team.role", name, in.Role)
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *Panel) teamErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, errNoUser):
		web.Error(w, http.StatusNotFound, "NOT_FOUND", "That person is no longer on the team.")
	case errors.Is(err, errLastOwner):
		web.Error(w, http.StatusConflict, "LAST_OWNER", "The panel needs at least one owner.")
	case errors.Is(err, errTaken):
		web.Error(w, http.StatusConflict, "USERNAME_TAKEN", "That username is taken.")
	default:
		web.Error(w, http.StatusInternalServerError, "INTERNAL", "Something went wrong on the server.")
	}
	return false
}

func (p *Panel) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := ""
	err := p.db.Update(func(d *data) error {
		u := d.user(id)
		if u == nil {
			return errNoUser
		}
		if u.Role == RoleOwner && d.owners() <= 1 {
			return errLastOwner
		}
		name = u.Username
		keep := d.Users[:0]
		for _, x := range d.Users {
			if x.ID != id {
				keep = append(keep, x)
			}
		}
		d.Users = keep
		ss := d.Sessions[:0]
		for _, s := range d.Sessions {
			if s.UserID != id {
				ss = append(ss, s)
			}
		}
		d.Sessions = ss
		return nil
	})
	if !p.teamErr(w, err) {
		return
	}
	p.audit(current(r).User.Username, "team.remove", name, "")
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (p *Panel) reset2FA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	name := ""
	err := p.db.Update(func(d *data) error {
		u := d.user(id)
		if u == nil {
			return errNoUser
		}
		u.TOTP, u.TOTPLast, u.Recovery, u.MustEnroll, u.Epoch = "", 0, nil, true, randID()
		name = u.Username
		return nil
	})
	if !p.teamErr(w, err) {
		return
	}
	p.audit(current(r).User.Username, "team.reset-2fa", name, "")
	web.JSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type joinIn struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p *Panel) findInvite(token string) (TeamInvite, bool) {
	if len(token) < 30 || len(token) > 64 {
		return TeamInvite{}, false
	}
	h := hashToken(token)
	var inv TeamInvite
	ok := false
	p.db.View(func(d *data) {
		for _, i := range d.Invites {
			if subtle.ConstantTimeCompare([]byte(i.Hash), []byte(h)) == 1 && i.Expires > p.now().Unix() {
				inv, ok = i, true
			}
		}
	})
	return inv, ok
}

func (p *Panel) joinInfo(w http.ResponseWriter, r *http.Request) {
	var in joinIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	key := p.throttleKey(r)
	if p.throttle.Locked(key) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	inv, ok := p.findInvite(in.Token)
	if !ok {
		p.throttle.Fail(key)
		web.Error(w, http.StatusNotFound, "INVALID_INVITE", "This invite link is not valid or has expired. Ask for a new one.")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"role": inv.Role, "by": inv.By, "name": p.settings().Name, "expires": inv.Expires})
}

func (p *Panel) createUser(username, password, role string, mustEnroll bool) (User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !ValidUsername(username) {
		return User{}, errors.New("username")
	}
	if !ValidPassword(password) {
		return User{}, admin.ErrWeakPassword
	}
	h, err := admin.HashPassword(password)
	if err != nil {
		return User{}, err
	}
	u := User{ID: randID(), Username: username, Role: role, Password: h, Created: p.now().Unix(), Epoch: randID(), MustEnroll: mustEnroll}
	err = p.db.Update(func(d *data) error {
		if d.userByName(username) != nil {
			return errTaken
		}
		d.Users = append(d.Users, u)
		return nil
	})
	return u, err
}

func (p *Panel) joinStart(w http.ResponseWriter, r *http.Request) {
	var in joinIn
	if !web.Decode(w, r, &in, bodyLimit) {
		return
	}
	key := p.throttleKey(r)
	if p.throttle.Locked(key) {
		web.Error(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Too many attempts. Wait a few minutes and try again.")
		return
	}
	inv, ok := p.findInvite(in.Token)
	if !ok {
		p.throttle.Fail(key)
		web.Error(w, http.StatusNotFound, "INVALID_INVITE", "This invite link is not valid or has expired. Ask for a new one.")
		return
	}
	if !ValidUsername(strings.ToLower(strings.TrimSpace(in.Username))) {
		web.Error(w, http.StatusBadRequest, "BAD_USERNAME", "Usernames use 3 to 32 lowercase letters, digits, dots, dashes or underscores.")
		return
	}
	if !ValidPassword(in.Password) {
		web.Error(w, http.StatusBadRequest, "WEAK_PASSWORD", "Use at least 12 characters.")
		return
	}
	var used bool
	if err := p.db.Update(func(d *data) error {
		keep := d.Invites[:0]
		for _, i := range d.Invites {
			if i.ID == inv.ID {
				used = true
				continue
			}
			keep = append(keep, i)
		}
		d.Invites = keep
		return nil
	}); err != nil || !used {
		web.Error(w, http.StatusNotFound, "INVALID_INVITE", "This invite link was already used.")
		return
	}
	u, err := p.createUser(in.Username, in.Password, inv.Role, true)
	if err != nil {
		_ = p.db.Update(func(d *data) error { d.Invites = append(d.Invites, inv); return nil })
		if errors.Is(err, errTaken) {
			p.teamErr(w, err)
			return
		}
		web.Error(w, http.StatusBadRequest, "BAD_REQUEST", "Those details did not work.")
		return
	}
	p.audit(u.Username, "team.join", inv.Role, "invited by "+inv.By)
	web.JSON(w, http.StatusOK, map[string]any{"enroll": p.startEnroll(u.ID, "")})
}
