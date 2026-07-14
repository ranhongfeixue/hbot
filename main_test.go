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
	value, err := randomHexChars(defaultRealityShortIDLen)
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != defaultRealityShortIDLen {
		t.Fatalf("len = %d, want %d", len(value), defaultRealityShortIDLen)
	}
	if err := validateShortID(value); err != nil {
		t.Fatalf("generated invalid short id %q: %v", value, err)
	}
	if err := validateShortID("abc"); err == nil {
		t.Fatal("expected odd-length short id to be rejected")
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
	if len(p.ShortID) != defaultRealityShortIDLen {
		t.Fatalf("short id = %q, want length %d", p.ShortID, defaultRealityShortIDLen)
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

func TestAddHTTPOutboundWritesConfig(t *testing.T) {
	dir := t.TempDir()
	app := appConfig{
		configPath: filepath.Join(dir, "config.json"),
		statePath:  filepath.Join(dir, "state.json"),
		service:    "sing-box",
	}
	var out strings.Builder
	var errOut strings.Builder
	if err := addHTTPOutbound(app, httpOutboundAddOptions{
		Name:     "proxy",
		Server:   "proxy.example.com",
		Port:     8080,
		Username: "user",
		Password: "pass",
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
	outbounds, ok := cfg["outbounds"].([]any)
	if !ok || len(outbounds) != 2 {
		t.Fatalf("unexpected outbounds: %#v", cfg["outbounds"])
	}
	direct := outbounds[0].(map[string]any)
	if direct["type"] != "direct" || direct["tag"] != "direct" {
		t.Fatalf("direct outbound should stay first: %#v", direct)
	}
	httpOutbound := outbounds[1].(map[string]any)
	for key, want := range map[string]any{
		"type":        "http",
		"tag":         "http-proxy",
		"server":      "proxy.example.com",
		"server_port": float64(8080),
		"username":    "user",
		"password":    "pass",
	} {
		if got := httpOutbound[key]; got != want {
			t.Fatalf("http outbound %s = %#v, want %#v in %#v", key, got, want, httpOutbound)
		}
	}
	if _, ok := cfg["route"]; ok {
		t.Fatalf("adding an exit should not create route rules by default: %#v", cfg["route"])
	}
}

func TestSetInboundExitRulesWritesRouteAction(t *testing.T) {
	cfg := baseConfig()
	appendInbound(cfg, map[string]any{"type": "shadowsocks", "tag": "ss-tw", "listen_port": 52501})
	appendInbound(cfg, map[string]any{"type": "shadowsocks", "tag": "ss-hk", "listen_port": 52502})
	appendOutbound(cfg, map[string]any{"type": "http", "tag": "http-proxy", "server": "proxy.example.com", "server_port": 8080})

	if err := setInboundExitRules(cfg, []string{"ss-tw"}, "http-proxy"); err != nil {
		t.Fatal(err)
	}
	route := cfg["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1: %#v", len(rules), rules)
	}
	rule := rules[0].(map[string]any)
	if rule["action"] != "route" || rule["outbound"] != "http-proxy" {
		t.Fatalf("unexpected route rule: %#v", rule)
	}
	inbound := rule["inbound"].([]any)
	if len(inbound) != 1 || inbound[0] != "ss-tw" {
		t.Fatalf("unexpected inbound matcher: %#v", inbound)
	}
	exits := inboundExitMap(cfg)
	if exits["ss-tw"] != "http-proxy" {
		t.Fatalf("ss-tw exit = %q, want http-proxy", exits["ss-tw"])
	}
	if exits["ss-hk"] != "" {
		t.Fatalf("ss-hk should keep default exit, got %q", exits["ss-hk"])
	}
}

func TestClearInboundExitRuleKeepsUnmanagedRules(t *testing.T) {
	cfg := baseConfig()
	appendOutbound(cfg, map[string]any{"type": "http", "tag": "http-proxy", "server": "proxy.example.com", "server_port": 8080})
	route := ensureRoute(cfg)
	route["rules"] = []any{
		map[string]any{"inbound": []any{"ss-tw", "ss-hk"}, "action": "route", "outbound": "http-proxy"},
		map[string]any{"inbound": []any{"ss-us"}, "domain": []any{"example.com"}, "action": "route", "outbound": "http-proxy"},
	}

	if err := setInboundExitRules(cfg, []string{"ss-tw"}, "direct"); err != nil {
		t.Fatal(err)
	}
	rules := route["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules len = %d, want 2: %#v", len(rules), rules)
	}
	trimmed := rules[0].(map[string]any)
	inbound := trimmed["inbound"].([]any)
	if len(inbound) != 1 || inbound[0] != "ss-hk" {
		t.Fatalf("expected grouped simple rule to keep only ss-hk: %#v", trimmed)
	}
	complex := rules[1].(map[string]any)
	if _, ok := complex["domain"]; !ok {
		t.Fatalf("complex unmanaged rule should be kept: %#v", complex)
	}
}

func TestShowStatusDisplaysExitRules(t *testing.T) {
	dir := t.TempDir()
	app := appConfig{
		configPath: filepath.Join(dir, "config.json"),
		statePath:  filepath.Join(dir, "state.json"),
		service:    "sing-box",
	}
	if err := saveState(app.statePath, stateFile{
		Server: "example.com",
		Profiles: []profile{
			{Type: "ss", Name: "TW", Tag: "ss-tw", Port: 52501},
			{Type: "ss", Name: "HK", Tag: "ss-hk", Port: 52502},
		},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := baseConfig()
	appendOutbound(cfg, map[string]any{"type": "http", "tag": "http-proxy", "server": "proxy.example.com", "server_port": 8080})
	if err := setInboundExitRules(cfg, []string{"ss-tw"}, "http-proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := writeConfig(app.configPath, cfg); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	if err := showStatus(app, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"service:",
		"ss  TW  :52501  tag=ss-tw  exit=http-proxy",
		"ss  HK  :52502  tag=ss-hk  exit=direct (own)",
		"http-proxy  http  proxy.example.com:8080",
		"ss-tw -> http-proxy",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, out.String())
		}
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
