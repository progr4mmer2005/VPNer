//go:build linux

package agent

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OpenVPN management interface client: answers username/password, static
// and dynamic (CRV1) challenges and private key passwords, asking the user
// in the UI whenever something is needed that is not saved.

var (
	needAuthRe = regexp.MustCompile(`^>PASSWORD:Need '([^']+)' (username/password|password)(?: SC:(\d),(.*))?`)
	crv1Re     = regexp.MustCompile(`^>PASSWORD:Verification Failed: '([^']+)' \['CRV1:([^:]*):([^:]*):([^:]*):(.*)'\]`)
	failRe     = regexp.MustCompile(`^>PASSWORD:Verification Failed: '([^']+)'`)
)

func mgmtQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func (c *conn) runOpenVPNMgmt(cmd *exec.Cmd) {
	sock := filepath.Join(c.dir, "mgmt.sock")
	var conn net.Conn
	for i := 0; i < 100; i++ { // the socket appears right after start
		var err error
		if conn, err = net.Dial("unix", sock); err == nil {
			break
		}
		if cmd.ProcessState != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	if conn == nil {
		c.log("management: не удалось подключиться к OpenVPN")
		return
	}
	defer conn.Close()
	var wmu sync.Mutex
	send := func(line string) {
		wmu.Lock()
		defer wmu.Unlock()
		fmt.Fprintf(conn, "%s\n", line)
	}

	creds := c.spec.Creds
	user, pass, keyPass := "", "", ""
	if creds != nil {
		user, pass, keyPass = creds.User, creds.Pass, creds.KeyPass
	}
	passRejected := false
	var crvState, crvUser, crvResponse string

	sendAuth := func(typ, u, p string) {
		send("username " + mgmtQuote(typ) + " " + mgmtQuote(u))
		send("password " + mgmtQuote(typ) + " " + mgmtQuote(p))
		c.afterCredentials()
	}
	mfa := ""
	if creds != nil {
		mfa = creds.MFA
	}
	// withUser asks for the username if it is unknown, then calls next.
	withUser := func(next func(u string)) {
		if user != "" {
			next(user)
			return
		}
		c.askUser("Логин OpenVPN:", false, func(u string) {
			user = strings.TrimSpace(u)
			next(user)
		})
	}
	withPass := func(next func(p string)) {
		if pass != "" && !passRejected {
			next(pass)
			return
		}
		c.askUser("Пароль OpenVPN:", true, func(p string) {
			pass, passRejected = p, false
			next(pass)
		})
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, ">HOLD:"):
			send("hold release")
		case strings.HasPrefix(line, ">INFO:"):
		case crv1Re.MatchString(line):
			// dynamic challenge: the server asks a question after the password
			m := crv1Re.FindStringSubmatch(line)
			crvState = m[3]
			if b, err := base64.StdEncoding.DecodeString(m[4]); err == nil {
				crvUser = string(b)
			} else {
				crvUser = user
			}
			echo := strings.Contains(m[2], "E")
			c.askUser(m[5], !echo, func(r string) { crvResponse = strings.TrimSpace(r) })
		case failRe.MatchString(line):
			c.log("OpenVPN: сервер отклонил логин/пароль или код")
			passRejected = true
			c.mu.Lock()
			c.answered = map[int]bool{}
			c.mu.Unlock()
		case needAuthRe.MatchString(line):
			m := needAuthRe.FindStringSubmatch(line)
			typ, kind, scFlag, scText := m[1], m[2], m[3], m[4]
			switch {
			case typ == "Private Key":
				if keyPass != "" && !passRejected {
					send("password " + mgmtQuote(typ) + " " + mgmtQuote(keyPass))
				} else {
					c.askUser("Пароль закрытого ключа:", true, func(p string) {
						keyPass = p
						send("password " + mgmtQuote(typ) + " " + mgmtQuote(p))
					})
				}
			case kind == "password":
				c.askUser(fmt.Sprintf("OpenVPN запрашивает «%s»:", typ), true, func(p string) {
					send("password " + mgmtQuote(typ) + " " + mgmtQuote(p))
				})
			case crvState != "":
				// answer to the dynamic challenge goes in place of the password
				st, u, r := crvState, crvUser, crvResponse
				crvState, crvResponse = "", ""
				if r == "" {
					c.askUser("Код подтверждения:", true, func(r string) {
						sendAuth(typ, u, "CRV1::"+st+"::"+strings.TrimSpace(r))
					})
				} else {
					sendAuth(typ, u, "CRV1::"+st+"::"+r)
				}
			case scFlag != "":
				// static challenge (OTP) together with the password
				withUser(func(u string) {
					withPass(func(p string) {
						respond := func(r string) {
							resp := "SCRV1:" + base64.StdEncoding.EncodeToString([]byte(p)) + ":" +
								base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(r)))
							sendAuth(typ, u, resp)
						}
						if mfa != "" && !passRejected {
							respond(mfa) // e.g. "push": the user only approves on the phone
							return
						}
						c.askUser(strings.TrimSpace(scText), scFlag != "1", respond)
					})
				})
			default:
				withUser(func(u string) {
					withPass(func(p string) { sendAuth(typ, u, p) })
				})
			}
		}
	}
}
