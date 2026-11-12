package proxy

import (
	"os"
	"strings"

	"github.com/r1sq/CantSendPackets/internal/verdict"
)

// ReadSettings reads the proxy from the environment, which is what command line
// programs on Linux follow. Lowercase wins, as in curl.
func ReadSettings() Settings {
	return envSettings(os.Getenv)
}

func envSettings(getenv func(string) string) Settings {
	get := func(name string) string {
		if v := strings.TrimSpace(getenv(strings.ToLower(name))); v != "" {
			return v
		}
		return strings.TrimSpace(getenv(strings.ToUpper(name)))
	}
	var list []string
	if v := get("http_proxy"); v != "" {
		list = append(list, "http="+hostPort(v))
	}
	if v := get("https_proxy"); v != "" {
		list = append(list, "https="+hostPort(v))
	}
	// all_proxy is often SOCKS, which isn't supported; an HTTP one fills the gaps.
	if v := get("all_proxy"); v != "" && strings.HasPrefix(strings.ToLower(v), "http") {
		list = append(list, hostPort(v))
	}
	return Settings{
		Env:       strings.Join(list, ";"),
		EnvBypass: strings.ReplaceAll(get("no_proxy"), ",", ";"),
	}
}

// hostPort reduces "http://user:pw@proxy:3128/" to "proxy:3128". Logins aren't
// taken from the environment: the app asks, as on Windows.
func hostPort(v string) string {
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSuffix(v, "/")
}

// Detect reads the settings and resolves them for the given test URLs. Linux has
// no system PAC engine, so WPAD isn't looked for and a PAC override is reported
// as unusable.
func Detect(urls []string, override Override) Result {
	settings := ReadSettings()
	settings.Override = override
	return Resolve(settings, noPAC{}, urls)
}

type noPAC struct{}

func (noPAC) WPAD() (string, error) { return "", ErrNoWPAD }
func (noPAC) Evaluate(string, string) (string, error) {
	return "", verdict.Err("err.proxy.noPacEngine")
}
