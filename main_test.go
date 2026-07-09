package main

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUUID(t *testing.T) {
	id, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !isUUID(id) {
		t.Fatalf("invalid uuid: %s", id)
	}
}

func TestSingBoxInstallArgs(t *testing.T) {
	args, err := singBoxInstallArgs("v1.13.14", false, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-s", "--", "--version", "1.13.14"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %#v, want %#v", args, want)
	}

	args, err = singBoxInstallArgs(defaultSingBoxVersion, true, false)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"-s", "--"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("latest args = %#v, want %#v", args, want)
	}

	if _, err := singBoxInstallArgs(defaultSingBoxVersion, true, true); err == nil {
		t.Fatal("expected --latest and --beta conflict")
	}
}

func TestRealityKeypairCanDerivePublicKey(t *testing.T) {
	kp, err := generateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := deriveRealityPublicKey(kp.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.publicKey {
		t.Fatalf("derived public key mismatch: %s != %s", pub, kp.publicKey)
	}
}

func TestRandomHexChars(t *testing.T) {
	value, err := randomHexChars(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 5 {
		t.Fatalf("len = %d, want 5", len(value))
	}
	if err := validateShortID(value); err != nil {
		t.Fatalf("generated invalid short id %q: %v", value, err)
	}
}

func TestValidateProfileName(t *testing.T) {
	for _, name := range []string{"TW", "gomami-capsolver-hk", "hk_01"} {
		if err := validateProfileName(name); err != nil {
			t.Fatalf("expected %q to be valid: %v", name, err)
		}
	}
	for _, name := range []string{"", "1hk", "-hk", "hk test", "hk.example"} {
		if err := validateProfileName(name); err == nil {
			t.Fatalf("expected %q to be invalid", name)
		}
	}
}

func TestBuildSSLink(t *testing.T) {
	link, err := buildLink(profile{
		Type:     "ss",
		Name:     "TW",
		Server:   "example.com",
		Port:     52501,
		Method:   "aes-256-gcm",
		Password: "secret",
		Network:  "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "ss" || u.Host != "example.com:52501" || u.Fragment != "TW" {
		t.Fatalf("unexpected ss link: %s", link)
	}
	if u.Query().Get("type") != "tcp" {
		t.Fatalf("missing tcp type: %s", link)
	}
}

func TestBuildVLESSRealityLink(t *testing.T) {
	link, err := buildLink(profile{
		Type:        "vless-reality",
		Name:        "hk",
		Server:      "191.101.132.44",
		Port:        50000,
		UUID:        "ab77e688-2fa3-485f-9448-a893bf09f242",
		SNI:         "www.apple.com",
		PublicKey:   "abc",
		ShortID:     "b2",
		SpiderX:     "/dsnX",
		Fingerprint: "chrome",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "vless" || u.Host != "191.101.132.44:50000" {
		t.Fatalf("unexpected vless link: %s", link)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"encryption": "none",
		"security":   "reality",
		"type":       "tcp",
		"sni":        "www.apple.com",
		"pbk":        "abc",
		"sid":        "b2",
		"spx":        "/dsnX",
		"fp":         "chrome",
	} {
		if got := q.Get(k); got != want {
			t.Fatalf("query %s = %q, want %q in %s", k, got, want, link)
		}
	}
}

func TestBuildClashConfig(t *testing.T) {
	config, err := buildClashConfig([]profile{
		{
			Type:     "ss",
			Name:     "tw-iepl-1",
			Port:     12046,
			Method:   "aes-256-gcm",
			Password: "secret",
		},
		{
			Type:        "vless-reality",
			Name:        "neburst-jk-hk",
			Port:        53790,
			UUID:        "bdf18969-4589-4060-9627-82909a5505fe",
			SNI:         "www.nvidia.com",
			PublicKey:   "SsN67VcBMJvXwp7lo9YjRxBRObbCW0J46Y_hBzU3ji0",
			ShortID:     "9fa0",
			Fingerprint: "chrome",
		},
	}, "fde63gz6-1y61.apt-hcloud.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`proxies:`,
		`type: "ss"`,
		`server: "fde63gz6-1y61.apt-hcloud.com"`,
		`udp: true`,
		`type: "vless"`,
		`uuid: "bdf18969-4589-4060-9627-82909a5505fe"`,
		`"client-fingerprint": "chrome"`,
		`"reality-opts": {"public-key": "SsN67VcBMJvXwp7lo9YjRxBRObbCW0J46Y_hBzU3ji0", "short-id": "9fa0"}`,
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q in:\n%s", want, config)
		}
	}
}

func TestBuildClashRejectsURLServer(t *testing.T) {
	_, err := buildClashConfig([]profile{{
		Type:     "ss",
		Name:     "tw",
		Port:     12046,
		Method:   "aes-256-gcm",
		Password: "secret",
	}}, "https://example.com")
	if err == nil {
		t.Fatal("expected URL server to be rejected")
	}
}

func TestSelectProfiles(t *testing.T) {
	profiles := []profile{{Name: "one"}, {Name: "two"}, {Name: "three"}}
	selected, err := selectProfiles(profiles, "1, 3")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 || selected[0].Name != "one" || selected[1].Name != "three" {
		t.Fatalf("unexpected selected profiles: %#v", selected)
	}
	all, err := selectProfiles(profiles, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("all len = %d, want 3", len(all))
	}
}

func TestExportUsesInitializedServer(t *testing.T) {
	dir := t.TempDir()
	app := appConfig{
		configPath: filepath.Join(dir, "config.json"),
		statePath:  filepath.Join(dir, "state.json"),
		service:    "sing-box",
	}
	st := stateFile{
		Server: "example.com",
		Profiles: []profile{{
			Type:     "ss",
			Name:     "TW",
			Port:     52501,
			Method:   "aes-256-gcm",
			Password: "secret",
		}},
	}
	if err := saveState(app.statePath, st); err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		r.Close()
	})
	if _, err := w.WriteString("1\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	var out strings.Builder
	var errOut strings.Builder
	if err := exportClashInteractive(app, bufio.NewReader(os.Stdin), &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `server: "example.com"`) {
		t.Fatalf("export did not use initialized server:\n%s", out.String())
	}
	if strings.Contains(errOut.String(), "Server domain/IP") {
		t.Fatalf("export should not prompt for server anymore: %s", errOut.String())
	}
}

func TestAddVLESSRealityUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	app := appConfig{
		configPath: filepath.Join(dir, "config.json"),
		statePath:  filepath.Join(dir, "state.json"),
		service:    "sing-box",
	}
	var out strings.Builder
	var errOut strings.Builder
	if err := addVLESSReality(app, vlessRealityAddOptions{
		Name:   "hk",
		Port:   50000,
		Server: "example.com",
	}, &out, &errOut); err != nil {
		t.Fatalf("run failed: %v stderr=%s", err, errOut.String())
	}

	data, err := os.ReadFile(app.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Profiles) != 1 {
		t.Fatalf("profiles len = %d, want 1", len(st.Profiles))
	}
	p := st.Profiles[0]
	if p.SNI != defaultRealitySNI {
		t.Fatalf("SNI = %q, want %q", p.SNI, defaultRealitySNI)
	}
	if len(p.ShortID) != 5 {
		t.Fatalf("short id = %q, want length 5", p.ShortID)
	}
	if p.PrivateKey == "" || p.PublicKey == "" || p.UUID == "" {
		t.Fatalf("expected generated reality credentials: %#v", p)
	}
	if !strings.Contains(out.String(), "sni=www.nvidia.com") {
		t.Fatalf("missing default sni in output: %s", out.String())
	}
}

func TestAddSSWritesConfigAndState(t *testing.T) {
	dir := t.TempDir()
	app := appConfig{
		configPath: filepath.Join(dir, "config.json"),
		statePath:  filepath.Join(dir, "state.json"),
		service:    "sing-box",
	}
	var out strings.Builder
	var errOut strings.Builder
	if err := addSS(app, ssAddOptions{
		Name:     "TW",
		Port:     52501,
		Server:   "example.com",
		Password: "secret",
	}, &out, &errOut); err != nil {
		t.Fatalf("run failed: %v stderr=%s", err, errOut.String())
	}

	data, err := os.ReadFile(app.configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("unexpected inbounds: %#v", cfg["inbounds"])
	}
	inbound := inbounds[0].(map[string]any)
	if inbound["type"] != "shadowsocks" || inbound["tag"] != "ss-tw" {
		t.Fatalf("unexpected inbound: %#v", inbound)
	}
	if _, ok := inbound["network"]; ok {
		t.Fatalf("default shadowsocks inbound should omit network for tcp+udp: %#v", inbound)
	}
	if !strings.Contains(out.String(), "ss://") {
		t.Fatalf("missing share link: %s", out.String())
	}

	data, err = os.ReadFile(app.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Profiles) != 1 || st.Profiles[0].Network != "both" {
		t.Fatalf("expected default ss network both: %#v", st.Profiles)
	}
}

func TestCommandModeIsRejected(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	var errOut strings.Builder
	err := run([]string{
		"--config", filepath.Join(dir, "config.json"),
		"--state", filepath.Join(dir, "state.json"),
		"add", "ss",
		"--name", "TW",
		"--port", "52501",
	}, &out, &errOut)
	if err == nil {
		t.Fatal("expected command mode to be rejected")
	}
	if !strings.Contains(err.Error(), "interactive only") {
		t.Fatalf("unexpected error: %v", err)
	}
}
