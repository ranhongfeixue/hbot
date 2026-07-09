package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConfigPath       = "/etc/sing-box/config.json"
	defaultStatePath        = "/etc/hbot/state.json"
	defaultService          = "sing-box"
	defaultRealitySNI       = "www.nvidia.com"
	defaultSingBoxVersion   = "1.13.14"
	singBoxInstallScriptURL = "https://sing-box.app/install.sh"
)

type appConfig struct {
	configPath string
	statePath  string
	service    string
}

type stateFile struct {
	Server   string    `json:"server,omitempty"`
	Profiles []profile `json:"profiles"`
}

type profile struct {
	Type          string `json:"type"`
	Name          string `json:"name"`
	Tag           string `json:"tag"`
	Server        string `json:"server,omitempty"`
	Port          int    `json:"port"`
	Method        string `json:"method,omitempty"`
	Password      string `json:"password,omitempty"`
	Network       string `json:"network,omitempty"`
	UUID          string `json:"uuid,omitempty"`
	SNI           string `json:"sni,omitempty"`
	RealityServer string `json:"reality_server,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	ShortID       string `json:"short_id,omitempty"`
	SpiderX       string `json:"spider_x,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	CreatedAt     string `json:"created_at"`
}

type writeResult struct {
	BackupPath string
}

type addOptions struct {
	SNI string
}

type ssAddOptions struct {
	Name     string
	Port     int
	Method   string
	Password string
	Network  string
	Server   string
	Restart  bool
}

type vlessRealityAddOptions struct {
	Name          string
	Port          int
	UUID          string
	SNI           string
	RealityServer string
	PrivateKey    string
	PublicKey     string
	ShortID       string
	SpiderX       string
	Fingerprint   string
	Server        string
	Restart       bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	app, rest, err := parseGlobal(args, stderr)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return cmdPanel(app, stdout, stderr)
	}

	switch rest[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return errors.New("hbot is interactive only; run `hbot` without commands")
	}
}

func parseGlobal(args []string, stderr io.Writer) (appConfig, []string, error) {
	app := appConfig{
		configPath: defaultConfigPath,
		statePath:  defaultStatePath,
		service:    defaultService,
	}
	fs := flag.NewFlagSet("hbot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&app.configPath, "config", app.configPath, "sing-box config path")
	fs.StringVar(&app.statePath, "state", app.statePath, "manager state path")
	fs.StringVar(&app.service, "service", app.service, "systemd service name")
	if err := fs.Parse(args); err != nil {
		return app, nil, err
	}
	return app, fs.Args(), nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `hbot - small sing-box server manager

Usage:
  hbot [global flags]

Global flags:
  --config  /etc/sing-box/config.json
  --state   /etc/hbot/state.json
  --service sing-box

Notes:
  Run hbot without commands. It opens an interactive menu.
  First run can install sing-box, initialize config, enable systemd service, and try BBR.
  Reality client links cannot be converted back to server configs unless you still have the private key.`)
}

func cmdInit(app appConfig, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "public server IP or domain for generated links")
	force := fs.Bool("force", false, "replace config with a fresh base config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := loadState(app.statePath)
	if err != nil {
		return err
	}
	if *server != "" {
		if err := validateServer(*server); err != nil {
			return err
		}
		st.Server = *server
	}
	if err := saveState(app.statePath, st); err != nil {
		return err
	}

	if *force {
		if _, err := writeConfig(app.configPath, baseConfig()); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote fresh config: %s\n", app.configPath)
	} else if _, err := os.Stat(app.configPath); errors.Is(err, os.ErrNotExist) {
		if _, err := writeConfig(app.configPath, baseConfig()); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "created config: %s\n", app.configPath)
	} else if err != nil {
		return err
	} else if _, err := loadConfig(app.configPath); err != nil {
		return fmt.Errorf("existing config is not valid JSON: %w", err)
	} else {
		fmt.Fprintf(stdout, "kept existing config: %s\n", app.configPath)
	}

	warnBBR(stderr)
	if err := enableSingBoxAtBoot(app, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "warning: enable boot start failed: %v\n", err)
	}
	if err := startSingBox(app, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "warning: start sing-box failed: %v\n", err)
	}
	return nil
}

func cmdPanel(app appConfig, stdout, stderr io.Writer) error {
	reader := bufio.NewReader(os.Stdin)
	if err := firstRunSetup(app, reader, stdout, stderr); err != nil {
		return err
	}

	for {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "hbot")
		fmt.Fprintln(stdout, "  1) add")
		fmt.Fprintln(stdout, "  2) export")
		fmt.Fprintln(stdout, "  3) restart")
		fmt.Fprintln(stdout, "  4) start")
		fmt.Fprintln(stdout, "  5) stop")
		fmt.Fprintln(stdout, "  0) exit")
		choice, err := promptLine(reader, stdout, "Choice: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "1", "add":
			if err := addInteractive(app, addOptions{}, reader, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
			}
		case "2", "export":
			if err := exportClashInteractive(app, reader, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
			}
		case "3", "restart":
			if err := restartSingBox(app, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
			}
		case "4", "start":
			warnBBR(stderr)
			if err := startSingBox(app, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
			}
		case "5", "stop":
			if err := stopSingBox(app, stdout, stderr); err != nil {
				fmt.Fprintf(stderr, "error: %v\n", err)
			}
		case "0", "q", "quit", "exit":
			return nil
		default:
			fmt.Fprintln(stdout, "please choose add, export, restart, start, stop, or exit")
		}
	}
}

func firstRunSetup(app appConfig, reader *bufio.Reader, stdout, stderr io.Writer) error {
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("sing-box"); err != nil {
			yes, err := promptYesNo(reader, stdout, "sing-box not found. Download and install sing-box 1.13.14 now? [Y/n]: ", true)
			if err != nil {
				return err
			}
			if yes {
				if err := cmdInstallSingBox(nil, stdout, stderr); err != nil {
					return err
				}
			} else {
				fmt.Fprintln(stderr, "warning: sing-box is not installed")
			}
		}
	}

	st, err := loadState(app.statePath)
	if err != nil {
		return err
	}
	configMissing := false
	if _, err := os.Stat(app.configPath); errors.Is(err, os.ErrNotExist) {
		configMissing = true
	} else if err != nil {
		return err
	}
	if st.Server != "" && !configMissing {
		return nil
	}

	server := st.Server
	if server == "" {
		value, err := promptValidated(reader, stdout, "Server domain/IP for generated links: ", validateServer)
		if err != nil {
			return err
		}
		server = value
	}
	args := []string{}
	if server != "" {
		args = append(args, "--server", server)
	}
	return cmdInit(app, args, stdout, stderr)
}

func restartSingBox(app appConfig, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if err := cmdCheck(app, nil, stdout, stderr); err != nil {
		return err
	}
	warnBBR(stderr)
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := runSystemctl(app.service, "restart", stdout, stderr); err == nil {
			return nil
		} else {
			fmt.Fprintf(stderr, "warning: systemctl restart failed, falling back: %v\n", err)
		}
	}
	if _, err := exec.LookPath("service"); err == nil {
		if err := runProgram(stdout, stderr, "service", app.service, "restart"); err == nil {
			return nil
		} else {
			fmt.Fprintf(stderr, "warning: service restart failed, falling back: %v\n", err)
		}
	}
	if err := stopManagedSingBox(app, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "warning: stop managed sing-box failed: %v\n", err)
	}
	return startManagedSingBox(app, stdout, stderr)
}

func startSingBox(app appConfig, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if err := cmdCheck(app, nil, stdout, stderr); err != nil {
		return err
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := runSystemctl(app.service, "start", stdout, stderr); err == nil {
			return nil
		} else {
			fmt.Fprintf(stderr, "warning: systemctl start failed, falling back: %v\n", err)
		}
	}
	if _, err := exec.LookPath("service"); err == nil {
		if err := runProgram(stdout, stderr, "service", app.service, "start"); err == nil {
			return nil
		} else {
			fmt.Fprintf(stderr, "warning: service start failed, falling back: %v\n", err)
		}
	}
	return startManagedSingBox(app, stdout, stderr)
}

func stopSingBox(app appConfig, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		if err := runSystemctl(app.service, "stop", stdout, stderr); err == nil {
			return nil
		} else {
			fmt.Fprintf(stderr, "warning: systemctl stop failed, falling back: %v\n", err)
		}
	}
	if _, err := exec.LookPath("service"); err == nil {
		if err := runProgram(stdout, stderr, "service", app.service, "stop"); err == nil {
			return nil
		} else {
			fmt.Fprintf(stderr, "warning: service stop failed, falling back: %v\n", err)
		}
	}
	return stopManagedSingBox(app, stdout, stderr)
}

func enableSingBoxAtBoot(app appConfig, stdout, stderr io.Writer) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		return runSystemctl(app.service, "enable", stdout, stderr)
	}
	if _, err := exec.LookPath("update-rc.d"); err == nil {
		return runProgram(stdout, stderr, "update-rc.d", app.service, "defaults")
	}
	if _, err := exec.LookPath("rc-update"); err == nil {
		return runProgram(stdout, stderr, "rc-update", "add", app.service, "default")
	}
	return errors.New("no supported boot manager found; current session can still run sing-box in hbot-managed background mode")
}

func startManagedSingBox(app appConfig, stdout, stderr io.Writer) error {
	if _, err := exec.LookPath("sing-box"); err != nil {
		return errors.New("sing-box binary not found in PATH")
	}
	if pid, ok := readManagedPID(app); ok && processAlive(pid) {
		fmt.Fprintf(stdout, "sing-box already running in hbot-managed mode, pid %d\n", pid)
		return nil
	}

	stateDir := filepath.Dir(app.statePath)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	logPath := managedLogPath(app)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}

	cmd := exec.Command("sing-box", "run", "-c", app.configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return err
	}
	if err := os.WriteFile(managedPIDPath(app), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		logFile.Close()
		return err
	}
	if err := cmd.Process.Release(); err != nil {
		logFile.Close()
		return err
	}
	logFile.Close()
	fmt.Fprintf(stdout, "sing-box started in hbot-managed background mode, pid %d\n", cmd.Process.Pid)
	fmt.Fprintf(stdout, "log: %s\n", logPath)
	return nil
}

func stopManagedSingBox(app appConfig, stdout, stderr io.Writer) error {
	pid, ok := readManagedPID(app)
	if !ok {
		fmt.Fprintln(stdout, "no hbot-managed sing-box pid file found")
		return nil
	}
	if !processAlive(pid) {
		_ = os.Remove(managedPIDPath(app))
		fmt.Fprintln(stdout, "hbot-managed sing-box is not running")
		return nil
	}
	if err := exec.Command("kill", "-TERM", strconv.Itoa(pid)).Run(); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			_ = os.Remove(managedPIDPath(app))
			fmt.Fprintf(stdout, "stopped hbot-managed sing-box, pid %d\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(stderr, "warning: sing-box pid %d did not stop after SIGTERM, sending SIGKILL\n", pid)
	if err := exec.Command("kill", "-KILL", strconv.Itoa(pid)).Run(); err != nil {
		return err
	}
	_ = os.Remove(managedPIDPath(app))
	fmt.Fprintf(stdout, "killed hbot-managed sing-box, pid %d\n", pid)
	return nil
}

func readManagedPID(app appConfig) (int, bool) {
	data, err := os.ReadFile(managedPIDPath(app))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return exec.Command("kill", "-0", strconv.Itoa(pid)).Run() == nil
}

func managedPIDPath(app appConfig) string {
	return filepath.Join(filepath.Dir(app.statePath), "sing-box.pid")
}

func managedLogPath(app appConfig) string {
	return filepath.Join(filepath.Dir(app.statePath), "sing-box.log")
}

func cmdInstallSingBox(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("install-sing-box", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", defaultSingBoxVersion, "sing-box version to install, for example 1.13.14")
	latest := fs.Bool("latest", false, "install latest stable version from the official installer")
	beta := fs.Bool("beta", false, "install latest beta version from the official installer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("install-sing-box does not accept positional arguments")
	}
	if runtime.GOOS != "linux" {
		return errors.New("install-sing-box is only supported on Linux servers")
	}

	installArgs, err := singBoxInstallArgs(*version, *latest, *beta)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "downloading sing-box installer: %s\n", singBoxInstallScriptURL)
	script, err := downloadFile(singBoxInstallScriptURL, 2<<20)
	if err != nil {
		return err
	}

	fmt.Fprintln(stdout, "running sing-box installer")
	cmd := exec.Command("sh", installArgs...)
	cmd.Stdin = bytes.NewReader(script)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "sing-box install finished")
	if _, err := exec.LookPath("sing-box"); err == nil {
		return runProgram(stdout, stderr, "sing-box", "version")
	}
	return nil
}

func singBoxInstallArgs(version string, latest, beta bool) ([]string, error) {
	if latest && beta {
		return nil, errors.New("--latest and --beta cannot be used together")
	}
	args := []string{"-s", "--"}
	if beta {
		return append(args, "--beta"), nil
	}
	if latest || strings.EqualFold(strings.TrimSpace(version), "latest") {
		return args, nil
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, errors.New("--version cannot be empty")
	}
	version = strings.TrimPrefix(version, "v")
	return append(args, "--version", version), nil
}

func downloadFile(rawURL string, maxBytes int64) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download failed: HTTP %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("download too large: %s", rawURL)
	}
	return data, nil
}

func cmdAdd(app appConfig, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sni := fs.String("sni", "", "Reality SNI override for interactive vless-reality")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return errors.New("add is available from the main menu; run `hbot` without commands")
	}
	return cmdAddInteractive(app, addOptions{SNI: *sni}, stdout, stderr)
}

func cmdAddInteractive(app appConfig, opts addOptions, stdout, stderr io.Writer) error {
	return addInteractive(app, opts, bufio.NewReader(os.Stdin), stdout, stderr)
}

func addInteractive(app appConfig, opts addOptions, reader *bufio.Reader, stdout, stderr io.Writer) error {
	fmt.Fprintln(stdout, "Select protocol:")
	fmt.Fprintln(stdout, "  1) ss")
	fmt.Fprintln(stdout, "  2) vless-reality")
	fmt.Fprintln(stdout, "  0) exit")

	var protocol string
	for {
		choice, err := promptLine(reader, stdout, "Choice: ")
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "1", "ss", "shadowsocks":
			protocol = "ss"
		case "2", "vless", "vless-reality", "reality":
			protocol = "vless-reality"
		case "0", "q", "quit", "exit":
			fmt.Fprintln(stdout, "cancelled")
			return nil
		default:
			fmt.Fprintln(stdout, "please choose ss, vless-reality, or exit")
			continue
		}
		break
	}

	name, err := promptValidated(reader, stdout, "Name: ", validateProfileName)
	if err != nil {
		return err
	}
	port, err := promptPort(reader, stdout)
	if err != nil {
		return err
	}

	if protocol == "ss" {
		return addSS(app, ssAddOptions{
			Name:    name,
			Port:    port,
			Method:  "aes-256-gcm",
			Network: "both",
		}, stdout, stderr)
	}

	sni := strings.TrimSpace(opts.SNI)
	if sni == "" {
		var err error
		sni, err = promptLine(reader, stdout, "SNI [www.nvidia.com]: ")
		if err != nil {
			return err
		}
	}
	if sni == "" {
		sni = defaultRealitySNI
	}
	return addVLESSReality(app, vlessRealityAddOptions{
		Name:        name,
		Port:        port,
		SNI:         sni,
		Fingerprint: "chrome",
	}, stdout, stderr)
}

func promptLine(reader *bufio.Reader, stdout io.Writer, prompt string) (string, error) {
	fmt.Fprint(stdout, prompt)
	line, err := reader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func promptYesNo(reader *bufio.Reader, stdout io.Writer, prompt string, defaultYes bool) (bool, error) {
	for {
		value, err := promptLine(reader, stdout, prompt)
		if err != nil {
			return false, err
		}
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return defaultYes, nil
		}
		switch value {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(stdout, "please answer y or n")
		}
	}
}

func promptValidated(reader *bufio.Reader, stdout io.Writer, prompt string, validate func(string) error) (string, error) {
	for {
		value, err := promptLine(reader, stdout, prompt)
		if err != nil {
			return "", err
		}
		if err := validate(value); err != nil {
			fmt.Fprintf(stdout, "invalid input: %v\n", err)
			continue
		}
		return value, nil
	}
}

func promptPort(reader *bufio.Reader, stdout io.Writer) (int, error) {
	for {
		value, err := promptLine(reader, stdout, "Port: ")
		if err != nil {
			return 0, err
		}
		port, err := strconv.Atoi(value)
		if err != nil {
			fmt.Fprintln(stdout, "invalid input: port must be a number")
			continue
		}
		if err := validatePort(port); err != nil {
			fmt.Fprintf(stdout, "invalid input: %v\n", err)
			continue
		}
		return port, nil
	}
}

func addSS(app appConfig, opts ssAddOptions, stdout, stderr io.Writer) error {
	opts.Name = strings.TrimSpace(opts.Name)
	if opts.Method == "" {
		opts.Method = "aes-256-gcm"
	}
	if opts.Network == "" {
		opts.Network = "both"
	}
	if opts.Name == "" {
		return errors.New("name is required")
	}
	if err := validateProfileName(opts.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if err := validatePort(opts.Port); err != nil {
		return err
	}
	if err := validateNetwork(opts.Network); err != nil {
		return err
	}
	if opts.Password == "" {
		p, err := randomBase64URL(32)
		if err != nil {
			return err
		}
		opts.Password = p
	}

	st, err := loadState(app.statePath)
	if err != nil {
		return err
	}
	linkServer := pickServer(opts.Server, st.Server)
	if linkServer != "" {
		if err := validateServer(linkServer); err != nil {
			return err
		}
	}

	tag := uniqueTag("ss", opts.Name)
	inbound := map[string]any{
		"type":        "shadowsocks",
		"tag":         tag,
		"listen":      "::",
		"listen_port": opts.Port,
		"method":      opts.Method,
		"password":    opts.Password,
	}
	if normalizedNetwork(opts.Network) != "both" {
		inbound["network"] = normalizedNetwork(opts.Network)
	}

	cfg, err := loadConfigOrBase(app.configPath)
	if err != nil {
		return err
	}
	if err := ensureNoConflict(cfg, tag, opts.Port); err != nil {
		return err
	}
	appendInbound(cfg, inbound)

	wr, err := writeConfig(app.configPath, cfg)
	if err != nil {
		return err
	}
	if err := checkSingBoxConfig(app.configPath); err != nil {
		restoreBackup(app.configPath, wr.BackupPath, stderr)
		return err
	}

	p := profile{
		Type:      "ss",
		Name:      opts.Name,
		Tag:       tag,
		Server:    linkServer,
		Port:      opts.Port,
		Method:    opts.Method,
		Password:  opts.Password,
		Network:   normalizedNetwork(opts.Network),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	st.Profiles = append(st.Profiles, p)
	if linkServer != "" && st.Server == "" {
		st.Server = linkServer
	}
	if err := saveState(app.statePath, st); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "added shadowsocks inbound: %s:%d\n", tag, opts.Port)
	printProfileLink(stdout, p)
	if opts.Restart {
		return restartSingBox(app, stdout, stderr)
	}
	return restartSingBox(app, stdout, stderr)
}

func addVLESSReality(app appConfig, opts vlessRealityAddOptions, stdout, stderr io.Writer) error {
	opts.Name = strings.TrimSpace(opts.Name)
	if opts.SNI == "" {
		opts.SNI = defaultRealitySNI
	}
	if opts.Fingerprint == "" {
		opts.Fingerprint = "chrome"
	}
	if opts.Name == "" {
		return errors.New("name is required")
	}
	if err := validateProfileName(opts.Name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	if err := validatePort(opts.Port); err != nil {
		return err
	}
	if err := validateServer(opts.SNI); err != nil {
		return fmt.Errorf("sni: %w", err)
	}
	if opts.RealityServer == "" {
		opts.RealityServer = opts.SNI
	}
	if err := validateServer(opts.RealityServer); err != nil {
		return fmt.Errorf("reality server: %w", err)
	}
	if opts.UUID == "" {
		id, err := newUUID()
		if err != nil {
			return err
		}
		opts.UUID = id
	} else if !isUUID(opts.UUID) {
		return errors.New("uuid must be an RFC 4122 UUID")
	}

	if opts.PrivateKey == "" {
		kp, err := generateRealityKeypair()
		if err != nil {
			return err
		}
		opts.PrivateKey = kp.privateKey
		opts.PublicKey = kp.publicKey
	} else if opts.PublicKey == "" {
		pub, err := deriveRealityPublicKey(opts.PrivateKey)
		if err != nil {
			return err
		}
		opts.PublicKey = pub
	}
	if opts.ShortID == "" {
		sid, err := randomHexChars(5)
		if err != nil {
			return err
		}
		opts.ShortID = sid
	}
	if err := validateShortID(opts.ShortID); err != nil {
		return err
	}
	if opts.SpiderX == "" {
		x, err := randomBase64URL(8)
		if err != nil {
			return err
		}
		opts.SpiderX = "/" + x
	}

	st, err := loadState(app.statePath)
	if err != nil {
		return err
	}
	linkServer := pickServer(opts.Server, st.Server)
	if linkServer != "" {
		if err := validateServer(linkServer); err != nil {
			return err
		}
	}

	tag := uniqueTag("vless", opts.Name)
	inbound := map[string]any{
		"type":        "vless",
		"tag":         tag,
		"listen":      "::",
		"listen_port": opts.Port,
		"users": []any{
			map[string]any{
				"name": opts.Name,
				"uuid": opts.UUID,
				"flow": "",
			},
		},
		"tls": map[string]any{
			"enabled":     true,
			"server_name": opts.SNI,
			"reality": map[string]any{
				"enabled": true,
				"handshake": map[string]any{
					"server":      opts.RealityServer,
					"server_port": 443,
				},
				"private_key":         opts.PrivateKey,
				"short_id":            []any{opts.ShortID},
				"max_time_difference": "1m",
			},
		},
	}

	cfg, err := loadConfigOrBase(app.configPath)
	if err != nil {
		return err
	}
	if err := ensureNoConflict(cfg, tag, opts.Port); err != nil {
		return err
	}
	appendInbound(cfg, inbound)

	wr, err := writeConfig(app.configPath, cfg)
	if err != nil {
		return err
	}
	if err := checkSingBoxConfig(app.configPath); err != nil {
		restoreBackup(app.configPath, wr.BackupPath, stderr)
		return err
	}

	p := profile{
		Type:          "vless-reality",
		Name:          opts.Name,
		Tag:           tag,
		Server:        linkServer,
		Port:          opts.Port,
		UUID:          opts.UUID,
		SNI:           opts.SNI,
		RealityServer: opts.RealityServer,
		PrivateKey:    opts.PrivateKey,
		PublicKey:     opts.PublicKey,
		ShortID:       opts.ShortID,
		SpiderX:       opts.SpiderX,
		Fingerprint:   opts.Fingerprint,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	st.Profiles = append(st.Profiles, p)
	if linkServer != "" && st.Server == "" {
		st.Server = linkServer
	}
	if err := saveState(app.statePath, st); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "added VLESS Reality inbound: %s:%d\n", tag, opts.Port)
	printProfileLink(stdout, p)
	if opts.Restart {
		return restartSingBox(app, stdout, stderr)
	}
	return restartSingBox(app, stdout, stderr)
}

func cmdList(app appConfig, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := loadState(app.statePath)
	if err != nil {
		return err
	}
	if len(st.Profiles) == 0 {
		fmt.Fprintln(stdout, "no profiles")
		return nil
	}
	for _, p := range st.Profiles {
		p.Server = firstNonEmpty(p.Server, st.Server)
		fmt.Fprintf(stdout, "%s  %s  %s:%d\n", p.Type, p.Name, firstNonEmpty(p.Server, "<server>"), p.Port)
		printProfileLink(stdout, p)
	}
	return nil
}

func cmdExport(app appConfig, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		if fs.NArg() != 1 || strings.ToLower(fs.Arg(0)) != "clash" {
			return errors.New("only clash export is supported")
		}
	}
	return exportClashInteractive(app, bufio.NewReader(os.Stdin), stdout, stderr)
}

func exportClashInteractive(app appConfig, reader *bufio.Reader, stdout, stderr io.Writer) error {
	st, err := loadState(app.statePath)
	if err != nil {
		return err
	}
	if len(st.Profiles) == 0 {
		return errors.New("no profiles to export")
	}

	selected, err := promptProfilesForExport(reader, stderr, st.Profiles)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		fmt.Fprintln(stderr, "cancelled")
		return nil
	}

	server := strings.TrimSpace(st.Server)
	if server == "" {
		return errors.New("server is not initialized; restart hbot and complete first-run setup")
	}
	config, err := buildClashConfig(selected, server)
	if err != nil {
		return err
	}
	fmt.Fprint(stdout, config)
	return nil
}

func promptProfilesForExport(reader *bufio.Reader, w io.Writer, profiles []profile) ([]profile, error) {
	fmt.Fprintln(w, "Select profiles to export:")
	fmt.Fprintln(w, "  a) all")
	fmt.Fprintln(w, "  0) exit")
	for i, p := range profiles {
		fmt.Fprintf(w, "  %d) %s  %s  :%d\n", i+1, p.Type, p.Name, p.Port)
	}
	for {
		choice, err := promptLine(reader, w, "Choice [all]: ")
		if err != nil {
			return nil, err
		}
		selected, err := selectProfiles(profiles, choice)
		if err != nil {
			fmt.Fprintf(w, "invalid input: %v\n", err)
			continue
		}
		return selected, nil
	}
}

func selectProfiles(profiles []profile, choice string) ([]profile, error) {
	choice = strings.TrimSpace(strings.ToLower(choice))
	if choice == "" || choice == "a" || choice == "all" || choice == "*" {
		return append([]profile(nil), profiles...), nil
	}
	if choice == "0" || choice == "q" || choice == "quit" || choice == "exit" {
		return nil, nil
	}

	parts := strings.FieldsFunc(choice, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return nil, errors.New("choose all, exit, or profile numbers")
	}
	selected := make([]profile, 0, len(parts))
	seen := map[int]bool{}
	for _, part := range parts {
		index, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a profile number", part)
		}
		if index < 1 || index > len(profiles) {
			return nil, fmt.Errorf("profile number %d is out of range", index)
		}
		if seen[index] {
			continue
		}
		seen[index] = true
		selected = append(selected, profiles[index-1])
	}
	return selected, nil
}

func buildClashConfig(profiles []profile, server string) (string, error) {
	if len(profiles) == 0 {
		return "", errors.New("no profiles selected")
	}
	server = strings.TrimSpace(server)
	if err := validateServer(server); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("proxies:\n")
	for _, p := range profiles {
		line, err := buildClashProxyLine(p, server)
		if err != nil {
			return "", err
		}
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func buildClashProxyLine(p profile, server string) (string, error) {
	switch p.Type {
	case "ss":
		if p.Password == "" {
			return "", fmt.Errorf("profile %s is missing shadowsocks password", p.Name)
		}
		return fmt.Sprintf("- {name: %s, server: %s, port: %d, type: %s, cipher: %s, password: %s, udp: true}",
			yamlString(p.Name),
			yamlString(server),
			p.Port,
			yamlString("ss"),
			yamlString(firstNonEmpty(p.Method, "aes-256-gcm")),
			yamlString(p.Password),
		), nil
	case "vless-reality":
		if p.UUID == "" {
			return "", fmt.Errorf("profile %s is missing VLESS UUID", p.Name)
		}
		if p.PublicKey == "" {
			return "", fmt.Errorf("profile %s is missing Reality public key", p.Name)
		}
		if p.ShortID == "" {
			return "", fmt.Errorf("profile %s is missing Reality short id", p.Name)
		}
		return fmt.Sprintf("- {name: %s, type: %s, server: %s, port: %d, uuid: %s, cipher: %s, tls: true, udp: false, network: %s, servername: %s, \"client-fingerprint\": %s, \"reality-opts\": {\"public-key\": %s, \"short-id\": %s}}",
			yamlString(p.Name),
			yamlString("vless"),
			yamlString(server),
			p.Port,
			yamlString(p.UUID),
			yamlString("auto"),
			yamlString("tcp"),
			yamlString(firstNonEmpty(p.SNI, defaultRealitySNI)),
			yamlString(firstNonEmpty(p.Fingerprint, "chrome")),
			yamlString(p.PublicKey),
			yamlString(p.ShortID),
		), nil
	default:
		return "", fmt.Errorf("unsupported profile type %q", p.Type)
	}
}

func yamlString(s string) string {
	return strconv.Quote(s)
}

func cmdBBR(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("bbr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	strict := fs.Bool("strict", false, "return an error if BBR cannot be enabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	errs := enableBBR()
	if len(errs) == 0 {
		fmt.Fprintln(stdout, "BBR enabled or already active")
		return nil
	}
	for _, err := range errs {
		fmt.Fprintf(stderr, "warning: %v\n", err)
	}
	if *strict {
		return errors.New("BBR setup failed")
	}
	return nil
}

func cmdCheck(app appConfig, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := exec.LookPath("sing-box"); err != nil {
		return errors.New("sing-box binary not found in PATH")
	}
	return runProgram(stdout, stderr, "sing-box", "check", "-c", app.configPath)
}

func loadConfigOrBase(path string) (map[string]any, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return baseConfig(), nil
	}
	return loadConfig(path)
}

func loadConfig(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return cfg, nil
}

func baseConfig() map[string]any {
	return map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"inbounds": []any{},
		"outbounds": []any{
			map[string]any{
				"type": "direct",
				"tag":  "direct",
			},
		},
	}
}

func appendInbound(cfg map[string]any, inbound map[string]any) {
	inbounds, _ := cfg["inbounds"].([]any)
	cfg["inbounds"] = append(inbounds, inbound)
	if _, ok := cfg["outbounds"]; !ok {
		cfg["outbounds"] = []any{map[string]any{"type": "direct", "tag": "direct"}}
	}
}

func ensureNoConflict(cfg map[string]any, tag string, port int) error {
	inbounds, _ := cfg["inbounds"].([]any)
	for _, raw := range inbounds {
		in, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if existing, _ := in["tag"].(string); existing == tag {
			return fmt.Errorf("inbound tag already exists: %s", tag)
		}
		if existingPort, ok := numberAsInt(in["listen_port"]); ok && existingPort == port {
			return fmt.Errorf("listen port already exists in config: %d", port)
		}
	}
	return nil
}

func writeConfig(path string, cfg map[string]any) (writeResult, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return writeResult{}, err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return writeResult{}, err
	}

	var wr writeResult
	if existing, err := os.ReadFile(path); err == nil {
		backup := path + ".bak." + time.Now().UTC().Format("20060102150405")
		if err := os.WriteFile(backup, existing, 0o600); err != nil {
			return writeResult{}, err
		}
		wr.BackupPath = backup
	} else if !errors.Is(err, os.ErrNotExist) {
		return writeResult{}, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return writeResult{}, err
	}
	return wr, nil
}

func restoreBackup(path, backup string, stderr io.Writer) {
	if backup == "" {
		return
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		fmt.Fprintf(stderr, "warning: cannot read backup %s: %v\n", backup, err)
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Fprintf(stderr, "warning: cannot restore backup %s: %v\n", backup, err)
	}
}

func checkSingBoxConfig(configPath string) error {
	if _, err := exec.LookPath("sing-box"); err != nil {
		return nil
	}
	cmd := exec.Command("sing-box", "check", "-c", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func loadState(path string) (stateFile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return stateFile{Profiles: []profile{}}, nil
	}
	if err != nil {
		return stateFile{}, err
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return stateFile{}, err
	}
	if st.Profiles == nil {
		st.Profiles = []profile{}
	}
	return st, nil
}

func saveState(path string, st stateFile) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func printProfileLink(w io.Writer, p profile) {
	link, err := buildLink(p)
	if err != nil {
		fmt.Fprintf(w, "  link: unavailable (%v)\n", err)
		return
	}
	fmt.Fprintf(w, "  link: %s\n", link)
}

func buildLink(p profile) (string, error) {
	if p.Server == "" {
		return "", errors.New("server is empty; run init --server or add with --server")
	}
	switch p.Type {
	case "ss":
		userInfo := base64.RawURLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password))
		u := url.URL{
			Scheme:   "ss",
			Host:     net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
			Fragment: p.Name,
		}
		u.User = url.User(userInfo)
		q := u.Query()
		if p.Network != "" && p.Network != "both" {
			q.Set("type", p.Network)
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	case "vless-reality":
		u := url.URL{
			Scheme:   "vless",
			User:     url.User(p.UUID),
			Host:     net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
			Fragment: p.Name,
		}
		q := u.Query()
		q.Set("encryption", "none")
		q.Set("security", "reality")
		q.Set("type", "tcp")
		q.Set("sni", p.SNI)
		q.Set("pbk", p.PublicKey)
		q.Set("sid", p.ShortID)
		q.Set("fp", firstNonEmpty(p.Fingerprint, "chrome"))
		if p.SpiderX != "" {
			q.Set("spx", p.SpiderX)
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	default:
		return "", fmt.Errorf("unsupported profile type %q", p.Type)
	}
}

func warnBBR(stderr io.Writer) {
	for _, err := range enableBBR() {
		fmt.Fprintf(stderr, "warning: %v\n", err)
	}
}

func enableBBR() []error {
	var errs []error
	commands := [][]string{
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
	}
	for _, c := range commands {
		cmd := exec.Command(c[0], c[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("%s failed: %v: %s", strings.Join(c, " "), err, strings.TrimSpace(string(out))))
		}
	}
	const sysctlPath = "/etc/sysctl.d/99-hbot-bbr.conf"
	const sysctlData = "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"
	if err := os.WriteFile(sysctlPath, []byte(sysctlData), 0o644); err != nil {
		errs = append(errs, fmt.Errorf("persist BBR config failed: %w", err))
	}
	return errs
}

func runSystemctl(service, action string, stdout, stderr io.Writer) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemctl not found; this command is for Linux systemd servers")
	}
	return runProgram(stdout, stderr, "systemctl", action, service)
}

func runProgram(stdout, stderr io.Writer, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

type realityKeypair struct {
	privateKey string
	publicKey  string
}

func generateRealityKeypair() (realityKeypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return realityKeypair{}, err
	}
	return realityKeypair{
		privateKey: base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		publicKey:  base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

func deriveRealityPublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid Reality private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("invalid Reality private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	), nil
}

func randomBase64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomHexChars(n int) (string, error) {
	if n < 0 {
		return "", errors.New("hex length cannot be negative")
	}
	if n == 0 {
		return "", nil
	}
	value, err := randomHex((n + 1) / 2)
	if err != nil {
		return "", err
	}
	return value[:n], nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	return nil
}

func validateNetwork(network string) error {
	switch normalizedNetwork(network) {
	case "tcp", "udp", "both":
		return nil
	default:
		return errors.New("--network must be tcp, udp, or both")
	}
}

func normalizedNetwork(network string) string {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		return "both"
	}
	return network
}

func validateProfileName(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if len(name) > 64 {
		return errors.New("name must be 64 characters or fewer")
	}
	if !isASCIIAlpha(name[0]) {
		return errors.New("name must start with an English letter")
	}
	for i := 1; i < len(name); i++ {
		if isASCIIAlpha(name[i]) || isASCIIDigit(name[i]) || name[i] == '_' || name[i] == '-' {
			continue
		}
		return errors.New("name may contain only English letters, numbers, '_' and '-'")
	}
	return nil
}

func validateServer(server string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return errors.New("server is empty")
	}
	if strings.Contains(server, "://") {
		return errors.New("server must be a host or IP, not a URL")
	}
	if strings.Contains(server, "/") {
		return errors.New("server must not contain a path")
	}
	if ip := net.ParseIP(strings.Trim(server, "[]")); ip != nil {
		return nil
	}
	if len(server) > 253 {
		return errors.New("server name is too long")
	}
	labels := strings.Split(server, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return errors.New("invalid domain label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("domain label cannot start or end with '-'")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return errors.New("server contains invalid characters")
		}
	}
	return nil
}

func validateShortID(shortID string) error {
	if len(shortID) > 16 {
		return errors.New("--short-id must be 0 to 16 hex characters")
	}
	for i := 0; i < len(shortID); i++ {
		if isASCIIDigit(shortID[i]) || (shortID[i] >= 'a' && shortID[i] <= 'f') || (shortID[i] >= 'A' && shortID[i] <= 'F') {
			continue
		}
		return errors.New("--short-id must be hex")
	}
	return nil
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isUUID(s string) bool {
	ok, _ := regexp.MatchString(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`, s)
	return ok
}

func uniqueTag(prefix, name string) string {
	return prefix + "-" + slug(name)
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "profile"
	}
	return out
}

func numberAsInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	default:
		return 0, false
	}
}

func pickServer(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
