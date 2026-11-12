package verdict

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const repoRoot = "../.."

var catalogLine = regexp.MustCompile(`(?m)^\s*"([\w.]+)":\s*"((?:[^"\\]|\\.)*)",\s*$`)

func loadCatalog(t *testing.T) (de, en map[string]string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot, "frontend/i18n.js"))
	if err != nil {
		t.Fatal(err)
	}
	deSrc, enSrc, ok := strings.Cut(string(src), "\n  en: {")
	if !ok {
		t.Fatal("couldn't find the en block in i18n.js")
	}
	parse := func(s string) map[string]string {
		out := map[string]string{}
		for _, m := range catalogLine.FindAllStringSubmatch(s, -1) {
			out[m[1]] = m[2]
		}
		return out
	}
	de, en = parse(deSrc), parse(enSrc)
	if len(de) < 100 || len(en) < 100 {
		t.Fatalf("catalog parse looks wrong: %d de, %d en", len(de), len(en))
	}
	return de, en
}

// usedKeys finds every key referenced from Go, the frontend and the preview mock.
func usedKeys(t *testing.T) map[string]string {
	t.Helper()
	direct := []*regexp.Regexp{
		regexp.MustCompile(`verdict\.(?:M|Err)\("([\w.]+)"`),
		regexp.MustCompile(`"(err\.[\w.]+)"`),
		regexp.MustCompile(`\bt\("([\w.]+)"`),
		regexp.MustCompile(`data-i18n(?:-[a-z-]+)?="([\w.]+)"`),
		regexp.MustCompile(`\bm\("([\w.]+)"`),
	}
	pairs := []*regexp.Regexp{
		regexp.MustCompile(`\b(?:set|sum)\(verdict\.\w+,\s*"([\w.]+)"`),
		regexp.MustCompile(`\bpair\("([\w.]+)"`),
		regexp.MustCompile(`\bshowHeroKey\("\w+",\s*"([\w.]+)"`),
	}
	used := map[string]string{}
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "build" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if strings.HasSuffix(path, "_test.go") || d.Name() == "i18n.js" || (ext != ".go" && ext != ".js" && ext != ".html") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, re := range direct {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				used[m[1]] = path
			}
		}
		for _, re := range pairs {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				used[m[1]+".h"], used[m[1]+".d"] = path, path
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(used) < 100 {
		t.Fatalf("key scan looks wrong: found only %d", len(used))
	}
	return used
}

func TestEveryUsedKeyIsTranslated(t *testing.T) {
	de, en := loadCatalog(t)
	var missing []string
	for key, where := range usedKeys(t) {
		if _, ok := de[key]; !ok {
			missing = append(missing, "de: "+key+" (used in "+where+")")
		}
		if _, ok := en[key]; !ok {
			missing = append(missing, "en: "+key+" (used in "+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("untranslated keys would show raw in the UI:\n%s", strings.Join(missing, "\n"))
	}
}

func TestLanguagesMatch(t *testing.T) {
	de, en := loadCatalog(t)
	for k := range de {
		if _, ok := en[k]; !ok {
			t.Errorf("%s is missing from en", k)
		}
	}
	for k := range en {
		if _, ok := de[k]; !ok {
			t.Errorf("%s is missing from de", k)
		}
	}
}

func TestPlaceholdersMatch(t *testing.T) {
	de, en := loadCatalog(t)
	placeholder := regexp.MustCompile(`\{\w+\}`)
	set := func(s string) string {
		found := placeholder.FindAllString(s, -1)
		sort.Strings(found)
		// A sentence may repeat a value in one language only.
		var out []string
		for i, f := range found {
			if i == 0 || f != found[i-1] {
				out = append(out, f)
			}
		}
		return strings.Join(out, ",")
	}
	for k, v := range de {
		if en[k] != "" && set(v) != set(en[k]) {
			t.Errorf("%s: de has %s, en has %s", k, set(v), set(en[k]))
		}
	}
}

func TestGermanIsActuallyGerman(t *testing.T) {
	de, en := loadCatalog(t)
	same := 0
	for k, v := range de {
		if en[k] == v {
			same++
		}
	}
	// Plenty of technical terms are the same word, but most text must differ.
	if float64(same)/float64(len(de)) > 0.2 {
		t.Errorf("%d of %d German strings are identical to the English", same, len(de))
	}
}

func TestMsgHelpers(t *testing.T) {
	m := M("a.b", "n", 2)
	if m.Args["n"] != 2 || m.IsZero() {
		t.Errorf("%+v", m)
	}
	h, d := Pair("x", "n", 1)
	if h.Key != "x.h" || d.Key != "x.d" {
		t.Errorf("%s %s", h, d)
	}
	wrapped := Err("err.timeout")
	if AsMsg(wrapped).Key != "err.timeout" {
		t.Errorf("%s", AsMsg(wrapped))
	}
	if !(Msg{}).IsZero() || !AsMsg(nil).IsZero() {
		t.Error("zero handling")
	}
}
