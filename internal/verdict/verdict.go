// Package verdict is the shared outcome vocabulary of every check.
package verdict

import (
	"errors"
	"fmt"
)

// Level is what a check concluded. Unknown is distinct from OK on purpose: a
// diagnostic tool must never report "all clear" when it simply could not see.
type Level string

const (
	OK      Level = "ok"
	Warn    Level = "warn"
	Problem Level = "problem"
	Unknown Level = "unknown"
)

// Msg is user-facing text as a key into the frontend's catalog (frontend/i18n.js)
// plus its arguments. The backend never holds display text, so the language can
// change without re-running anything. An argument may itself be a Msg.
type Msg struct {
	Key  string         `json:"key"`
	Args map[string]any `json:"args,omitempty"`
}

// M builds a Msg from a key and alternating argument names and values.
func M(key string, kv ...any) Msg {
	m := Msg{Key: key}
	if len(kv) > 0 {
		m.Args = make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			m.Args[fmt.Sprint(kv[i])] = kv[i+1]
		}
	}
	return m
}

// Pair builds a headline and detail from a key: key+".h" and key+".d".
func Pair(key string, kv ...any) (headline, detail Msg) {
	return M(key+".h", kv...), M(key+".d", kv...)
}

// IsZero reports whether the Msg is unset.
func (m Msg) IsZero() bool { return m.Key == "" }

// String is for logs and test failures, never for display.
func (m Msg) String() string {
	if len(m.Args) == 0 {
		return m.Key
	}
	return fmt.Sprintf("%s%v", m.Key, m.Args)
}

// MsgError is an error whose text is translatable. It's used by pointer, so a
// package-level one works with errors.Is.
type MsgError struct{ Msg Msg }

func (e *MsgError) Error() string { return e.Msg.String() }

// Err builds a translatable error.
func Err(key string, kv ...any) *MsgError { return &MsgError{Msg: M(key, kv...)} }

// AsMsg returns an error's translatable form. Errors from the OS or libraries
// that have no translation are shown verbatim through err.raw.
func AsMsg(err error) Msg {
	var me *MsgError
	if errors.As(err, &me) {
		return me.Msg
	}
	if err == nil {
		return Msg{}
	}
	return M("err.raw", "text", err.Error())
}
