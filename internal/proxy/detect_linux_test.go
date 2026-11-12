package proxy

import "testing"

func TestEnvSettings(t *testing.T) {
	env := map[string]string{
		"http_proxy":  "http://user:secret@proxy.corp:3128/",
		"HTTPS_PROXY": "proxy.corp:3129",
		"https_proxy": "",
		"no_proxy":    "localhost,.corp,10.0.0.0/8",
		"ALL_PROXY":   "socks5://s:1080",
	}
	s := envSettings(func(k string) string { return env[k] })
	if s.Env != "http=proxy.corp:3128;https=proxy.corp:3129" {
		t.Errorf("Env = %q: credentials must be dropped and SOCKS ignored", s.Env)
	}
	if s.EnvBypass != "localhost;.corp;10.0.0.0/8" {
		t.Errorf("EnvBypass = %q", s.EnvBypass)
	}

	urls := []string{"http://a.example/", "https://b.example/"}
	r := Resolve(s, noPAC{}, urls)
	if r.Source != SourceEnv || r.Routes[urls[0]][0].Host != "proxy.corp:3128" || r.Routes[urls[1]][0].Host != "proxy.corp:3129" {
		t.Errorf("resolved %+v", r)
	}
}

func TestPACOverrideIsReportedOnLinux(t *testing.T) {
	r := Resolve(Settings{Override: Override{Mode: OverridePAC, PACURL: "http://x/p.pac"}}, noPAC{}, []string{"http://a/"})
	if r.Issue.IsZero() || len(r.Primary([]string{"http://a/"})) != 0 {
		t.Errorf("a PAC that can't be evaluated must be reported, and go direct: %+v", r)
	}
}
