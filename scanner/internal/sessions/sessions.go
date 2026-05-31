package sessions

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Session holds a named authentication identity for multi-session scanning.
// One session = one complete scan with distinct credentials.
type Session struct {
	Name    string
	Cookie  string   // Cookie header value
	Bearer  string   // Bearer token for Authorization
	Headers []string // Extra "Key: Value" pairs
}

// Parse reads a session file and returns all defined sessions.
//
// File format (one session per line, comments with #):
//
//	admin|cookie=PHPSESSID=abc123;csrftoken=xyz
//	user|bearer=eyJhbGciOiJIUzI1NiJ9...
//	superadmin|cookie=sessionid=def456|header=X-Role: superadmin
//	apikey|header=X-API-Key: secret123
//	anonymous
func Parse(path string) ([]Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sessions: open %s: %w", path, err)
	}
	defer f.Close()

	var sessions []Session
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		sess, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("sessions: line %d: %w", lineNo, err)
		}
		sessions = append(sessions, sess)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("sessions: read: %w", err)
	}
	if len(sessions) == 0 {
		return nil, fmt.Errorf("sessions: no sessions defined in %s", path)
	}
	return sessions, nil
}

// parseLine parses one line of the session file.
// Format: name[|directive[|directive...]]
// Directives: cookie=<val>  bearer=<val>  header=<Key: Value>
func parseLine(line string) (Session, error) {
	parts := strings.SplitN(line, "|", -1)
	sess := Session{Name: strings.TrimSpace(parts[0])}
	if sess.Name == "" {
		return sess, fmt.Errorf("session name is empty")
	}

	for _, directive := range parts[1:] {
		directive = strings.TrimSpace(directive)
		switch {
		case strings.HasPrefix(directive, "cookie="):
			sess.Cookie = strings.TrimPrefix(directive, "cookie=")
		case strings.HasPrefix(directive, "bearer="):
			sess.Bearer = strings.TrimPrefix(directive, "bearer=")
		case strings.HasPrefix(directive, "header="):
			h := strings.TrimPrefix(directive, "header=")
			if strings.Index(h, ":") <= 0 {
				return sess, fmt.Errorf("invalid header directive %q — expected Key: Value", h)
			}
			sess.Headers = append(sess.Headers, h)
		default:
			return sess, fmt.Errorf("unknown directive %q", directive)
		}
	}
	return sess, nil
}
