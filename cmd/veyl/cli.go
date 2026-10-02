package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/veylvpn/backend/internal/admin"
	"github.com/veylvpn/backend/internal/api"
	"github.com/veylvpn/backend/internal/backup"
	"github.com/veylvpn/backend/internal/privdrop"
	"github.com/veylvpn/backend/internal/setup"
	"github.com/veylvpn/backend/internal/store"
)

func groupNumber(n string) string {
	if len(n) != 16 {
		return n
	}
	return n[0:4] + " " + n[4:8] + " " + n[8:12] + " " + n[12:16]
}

func randomSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func accountMain(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err := asService(); err != nil {
		return fail(err)
	}
	d, err := loadDeps()
	if err != nil {
		return fail(err)
	}
	switch args[0] {
	case "new":
		fs := flag.NewFlagSet("account new", flag.ContinueOnError)
		label := fs.String("label", "", "")
		days := fs.Int("expires-days", 0, "")
		withPw := fs.Bool("password", false, "")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		o := store.CreateOpts{Label: *label}
		if *days > 0 {
			o.Expires = time.Now().Add(time.Duration(*days) * 24 * time.Hour).Unix()
		}
		pw := ""
		if *withPw {
			pw = randomSecret(12)
			o.Password = pw
		}
		number, acc, err := d.Store.CreateAccount(o)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("Account number: %s\n", groupNumber(number))
		if pw != "" {
			fmt.Printf("Password:       %s\n", pw)
		} else {
			fmt.Println("The user chooses a password the first time they sign in.")
		}
		fmt.Printf("Account id:     %s\n", acc.ID)
		fmt.Println("Save the number now. It is stored hashed and cannot be shown again.")
		return 0
	case "list":
		list, err := d.Store.Accounts()
		if err != nil {
			return fail(err)
		}
		fmt.Printf("%-14s %-22s %-8s %-11s %-11s %s\n", "ID", "LABEL", "DEVICES", "CREATED", "EXPIRES", "STATE")
		for _, a := range list {
			exp := "never"
			if a.Expires > 0 {
				exp = time.Unix(a.Expires, 0).UTC().Format("2006-01-02")
			}
			state := "active"
			if err := a.Active(time.Now().Unix()); err != nil {
				state = err.Error()
			}
			fmt.Printf("%-14s %-22s %-8d %-11s %-11s %s\n", a.ID, a.Label, len(a.Devices), time.Unix(a.Created, 0).UTC().Format("2006-01-02"), exp, state)
		}
		return 0
	case "delete":
		if len(args) < 2 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		target := strings.ReplaceAll(args[1], " ", "")
		var devs []store.Device
		if store.ValidNumber(target) {
			devs, err = d.Store.DeleteAccount(target)
		} else {
			devs, err = d.Store.DeleteID(target)
		}
		if err != nil {
			return fail(err)
		}
		_ = api.RevokeEffects(d, devs)
		fmt.Printf("Deleted. %d device(s) revoked.\n", len(devs))
		return 0
	}
	fmt.Fprint(os.Stderr, usage)
	return 2
}

func inviteMain(args []string) int {
	if len(args) == 0 || args[0] != "new" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("invite new", flag.ContinueOnError)
	uses := fs.Int("uses", 1, "")
	days := fs.Int("days", 7, "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if err := asService(); err != nil {
		return fail(err)
	}
	d, err := loadDeps()
	if err != nil {
		return fail(err)
	}
	var exp int64
	if *days > 0 {
		exp = time.Now().Add(time.Duration(*days) * 24 * time.Hour).Unix()
	}
	code, _, err := d.Store.NewInvite(*uses, exp)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Invite code: %s\n", code)
	fmt.Printf("Usable %d time(s)", *uses)
	if exp > 0 {
		fmt.Printf(", until %s", time.Unix(exp, 0).UTC().Format("2006-01-02"))
	}
	fmt.Println(".")
	return 0
}

func adminMain(args []string) int {
	if len(args) == 0 || args[0] != "reset-password" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if !privdrop.Elevated() {
		return fail(errors.New("run this as root or Administrator"))
	}
	if err := asService(); err != nil {
		return fail(err)
	}
	pw := randomSecret(15)
	if err := admin.ResetPassword(paths(), pw); err != nil {
		return fail(err)
	}
	fmt.Printf("New admin password: %s\n", pw)
	fmt.Println("Two-factor authentication was turned off. Turn it back on in the admin panel.")
	return 0
}

func publicHost() (string, bool) {
	if d, err := loadDeps(); err == nil {
		if h := d.Settings.Get().Host; h != "" {
			return h, true
		}
	}
	conn, err := net.Dial("udp", "9.9.9.9:53")
	if err == nil {
		defer conn.Close()
		if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return a.IP.String(), false
		}
	}
	return "<server-ip>", false
}

func setupLinkMain(args []string) int {
	if !privdrop.Elevated() {
		return fail(errors.New("run this as root or Administrator"))
	}
	if err := asService(); err != nil {
		return fail(err)
	}
	d, err := loadDeps()
	if err != nil {
		return fail(err)
	}
	host, https := publicHost()
	if d.Settings.Get().Configured {
		fmt.Println("Setup is already complete. Open the admin panel: https://" + host + "/admin")
		return 0
	}
	token, err := setup.NewToken(d.Paths)
	if err != nil {
		return fail(err)
	}
	fmt.Println("Open this link to finish setup:")
	fmt.Println()
	fmt.Println("  " + setup.Link(host, token, https))
	fmt.Println()
	return 0
}

func readPassphrase() (string, error) {
	if v := os.Getenv("VEYL_BACKUP_PASSPHRASE"); v != "" {
		return v, nil
	}
	fmt.Fprint(os.Stderr, "Backup passphrase: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 12 {
		return "", errors.New("passphrase must be at least 12 characters")
	}
	return line, nil
}

func backupMain(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	pass, err := readPassphrase()
	if err != nil {
		return fail(err)
	}
	out := args[0]
	data, err := backup.Create(paths(), pass)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return fail(err)
	}
	fmt.Println("Encrypted backup written to", out)
	return 0
}

func restoreMain(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	force := fs.Bool("force", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	pass, err := readPassphrase()
	if err != nil {
		return fail(err)
	}
	if err := asService(); err != nil {
		return fail(err)
	}
	restore := backup.Restore
	if *force {
		restore = backup.RestoreForce
	}
	if err := restore(paths(), data, pass); err != nil {
		return fail(err)
	}
	fmt.Println("Restored. Run: sudo veyl agent run apply")
	return 0
}
