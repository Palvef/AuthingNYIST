package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/Palvef/AuthingNYIST/libauth"
	"github.com/howeyc/gopass"
	"github.com/juju/loggo"
	"gopkg.in/urfave/cli.v1"
)

type Settings struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Ip       string `json:"ip"`
	Host     string `json:"host"`
	HookSucc string `json:"hook-success"`
	NoCheck  bool   `json:"noCheck"`
	KeepOn   bool   `json:"keepOnline"`
	V6       bool   `json:"useV6"`
	Insecure bool   `json:"insecure"`
	Daemon   bool   `json:"daemonize"`
	Debug    bool   `json:"debug"`
	AcID     string `json:"acId"`
	Campus   bool   `json:"campusOnly"`
}

var logger = loggo.GetLogger("auth-nyist")
var settings Settings

func parseSettingsFile(path string) error {
	sf, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read config file failed (%s)", err)
	}
	defer sf.Close()
	bv, _ := ioutil.ReadAll(sf)
	err = json.Unmarshal(bv, &settings)
	if err != nil {
		return fmt.Errorf("parse config file \"%s\" failed (%s)", path, err)
	}
	logger.Debugf("Read config file \"%s\" succeeded\n", path)
	return nil
}

func mergeCliSettings(c *cli.Context) {
	var merged Settings
	merged.Username = c.GlobalString("username")
	if len(merged.Username) == 0 {
		merged.Username = settings.Username
	}
	merged.Password = c.GlobalString("password")
	if len(merged.Password) == 0 {
		merged.Password = settings.Password
	}
	merged.Ip = c.String("ip")
	if len(merged.Ip) == 0 {
		merged.Ip = settings.Ip
	}
	merged.Host = c.String("host")
	if len(merged.Host) == 0 {
		merged.Host = settings.Host
	}
	merged.HookSucc = c.GlobalString("hook-success")
	if len(merged.HookSucc) == 0 {
		merged.HookSucc = settings.HookSucc
	}
	merged.NoCheck = settings.NoCheck || c.Bool("no-check")
	merged.V6 = settings.V6 || c.Bool("ipv6")
	merged.KeepOn = settings.KeepOn || c.Bool("keep-online")
	merged.Insecure = settings.Insecure || c.Bool("insecure")
	merged.Daemon = settings.Daemon || c.GlobalBool("daemonize")
	merged.Debug = settings.Debug || c.GlobalBool("debug")
	merged.AcID = c.String("ac-id")
	if len(merged.AcID) == 0 {
		merged.AcID = settings.AcID
	}
	merged.Campus = settings.Campus || c.Bool("campus-only")
	settings = merged
	logger.Debugf("Settings Username: \"%s\"\n", settings.Username)
	logger.Debugf("Settings Ip: \"%s\"\n", settings.Ip)
	logger.Debugf("Settings Host: \"%s\"\n", settings.Host)
	logger.Debugf("Settings HookSucc: \"%s\"\n", settings.HookSucc)
	logger.Debugf("Settings NoCheck: %t\n", settings.NoCheck)
	logger.Debugf("Settings V6: %t\n", settings.V6)
	logger.Debugf("Settings KeepOn: %t\n", settings.KeepOn)
	logger.Debugf("Settings Insecure: %t\n", settings.Insecure)
	logger.Debugf("Settings Daemon: %t\n", settings.Daemon)
	logger.Debugf("Settings Debug: %t\n", settings.Debug)
	logger.Debugf("Settings AcID: \"%s\"\n", settings.AcID)
	logger.Debugf("Settings Campus: %t\n", settings.Campus)
}

func requestUser() (err error) {
	if len(settings.Username) == 0 && !settings.Daemon {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Username: ")
		settings.Username, _ = reader.ReadString('\n')
		settings.Username = strings.TrimSpace(settings.Username)
	}
	if len(settings.Username) == 0 {
		err = fmt.Errorf("username can't be empty")
	}
	return
}

func requestPasswd() (err error) {
	if len(settings.Password) == 0 && !settings.Daemon {
		var b []byte
		fmt.Printf("Password: ")
		b, err = gopass.GetPasswdMasked()
		if err != nil {
			err = fmt.Errorf("interrupted")
			return
		}
		settings.Password = string(b)
	}
	if len(settings.Password) == 0 {
		err = fmt.Errorf("password can't be empty")
	}
	return
}

func setLoggerLevel(debug bool, daemon bool) {
	if daemon {
		_ = loggo.ConfigureLoggers("auth-nyist=ERROR;libauth=ERROR")
	} else if debug {
		_ = loggo.ConfigureLoggers("auth-nyist=DEBUG;libauth=DEBUG")
	} else {
		_ = loggo.ConfigureLoggers("auth-nyist=INFO;libauth=INFO")
	}
}

func locateConfigFile(c *cli.Context) (cf string) {
	cf = c.GlobalString("config-file")
	if len(cf) != 0 {
		return
	}

	xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
	homedir, _ := os.UserHomeDir()
	if len(xdgConfigHome) == 0 {
		xdgConfigHome = path.Join(homedir, ".config")
	}
	cf = path.Join(xdgConfigHome, "auth-nyist")
	_, err := os.Stat(cf)
	if !os.IsNotExist(err) {
		return
	}

	cf = path.Join(homedir, ".auth-nyist")
	_, err = os.Stat(cf)
	if !os.IsNotExist(err) {
		return
	}

	return ""
}

func parseSettings(c *cli.Context) (err error) {
	if c.Bool("help") {
		cli.ShowAppHelpAndExit(c, 0)
	}
	setLoggerLevel(c.GlobalBool("debug"), c.GlobalBool("daemonize"))

	cf := locateConfigFile(c)
	if len(cf) == 0 && c.GlobalBool("daemonize") {
		return fmt.Errorf("cannot find config file (it is necessary in daemon mode)")
	}
	if len(cf) != 0 {
		err = parseSettingsFile(cf)
		if err != nil {
			return err
		}
	}
	mergeCliSettings(c)
	setLoggerLevel(settings.Debug, settings.Daemon)
	return
}

func runHook() {
	if settings.HookSucc != "" {
		logger.Debugf("Run hook \"%s\"\n", settings.HookSucc)
		cmd := exec.Command(settings.HookSucc)
		if err := cmd.Run(); err != nil {
			logger.Errorf("Hook execution failed: %v\n", err)
		}
	}
}
func cmdAuth(c *cli.Context) {
	logout := c.Bool("logout")
	err := authUtil(c, logout)
	if err != nil {
		logger.Errorf("Auth error: %s", err)
		os.Exit(1)
	}
}

func cmdDeauth(c *cli.Context) {
	err := authUtil(c, true)
	if err != nil {
		logger.Errorf("Deauth error: %s\n", err)
		os.Exit(1)
	}
}
func cmdKeepalive(c *cli.Context) {
	err := parseSettings(c)
	if err != nil {
		logger.Errorf("Parse setting error: %s\n", err)
		os.Exit(1)
	}
	err = keepAliveLoop(c.Bool("auth"))
	if err != nil {
		logger.Errorf("Keepalive error: %s\n", err)
		os.Exit(1)
	}
}
func authUtil(c *cli.Context, logout bool) error {
	err := parseSettings(c)
	if err != nil {
		return err
	}
	acID := "1"
	if len(settings.AcID) != 0 {
		acID = settings.AcID
	}
	domain := settings.Host
	if len(settings.Host) == 0 {
		if settings.V6 {
			domain = "auth.nyist.edu.cn"
		} else {
			domain = "auth.nyist.edu.cn"
		}
	}

	host := libauth.NewUrlProvider(domain, settings.Insecure)
	if len(settings.Ip) == 0 && !settings.NoCheck {
		online, _, username := libauth.IsOnline(host, acID)
		if logout && online {
			settings.Username = username
		}
		if online && !logout {
			logger.Infof("Currently online!")
			return nil
		} else if !online && logout {
			logger.Infof("Currently offline!")
			return nil
		}
	}
	err = requestUser()
	if err != nil {
		return err
	}
	if !logout {
		err = requestPasswd()
		if err != nil {
			return err
		}
	}

	// if settings.Campus {
	// 	settings.Username += "@tsinghua"
	// }

	err = libauth.LoginLogout(settings.Username, settings.Password, host, logout, settings.Ip, acID)
	action := "Login"
	if logout {
		action = "Logout"
	}
	if err == nil {
		logger.Infof("%s Successfully!\n", action)
		runHook()
		if settings.KeepOn {
			if len(settings.Ip) != 0 {
				logger.Errorf("Cannot keep another IP online\n")
			} else {
				return keepAliveLoop(true)
			}
		}
	} else {
		err = fmt.Errorf("%s Failed: %w", action, err)
	}
	return err
}

func keepAliveLoop(campusOnly bool) (ret error) {
	logger.Infof("Accessing websites periodically to keep you online")

	accessTarget := func(url string, ipv6 bool) (ret error) {
		network := "tcp4"
		if ipv6 {
			network = "tcp6"
		}
		netClient := &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _network, addr string) (net.Conn, error) {
					logger.Debugf("DialContext %s (%s)\n", addr, network)
					myDial := &net.Dialer{
						Timeout:       6 * time.Second,
						KeepAlive:     0,
						FallbackDelay: -1,
					}
					return myDial.DialContext(ctx, network, addr)
				},
			},
		}
		resp, ret := netClient.Head(url)
		if ret != nil {
			return
		}
		defer resp.Body.Close()
		logger.Debugf("HTTP status code %d\n", resp.StatusCode)
		return
	}
	targetInside := "https://www.nyist.edu.cn/"
	targetOutside := "https://www.baidu.com/"

	stop := make(chan int, 1)
	defer func() { stop <- 1 }()
	go func() {
		for {
			select {
			case <-stop:
				return // Exits the goroutine when receiving a stop signal
			case <-time.After(13 * time.Minute):
				_ = accessTarget(targetInside, true)
			}
		}
	}()

	// Label for the outer loop
loop:
	for {
		target := targetOutside
		if campusOnly || settings.V6 {
			target = targetInside
		}
		if ret = accessTarget(target, settings.V6); ret != nil {
			ret = fmt.Errorf("accessing %s failed (re-login might be required): %w", target, ret)
			break loop // Break out of the outer loop using the label
		}
		time.Sleep(3 * time.Second)
	}
	return
}

func main() {
	app := &cli.App{
		Name: "auth-nyist",
		UsageText: `auth-nyist [options]
	 auth-nyist [options] auth [auth_options]
	 auth-nyist [options] deauth [auth_options]
	 auth-nyist [options] online [online_options]`,
		Usage:    "Authenticating utility for NYIST",
		Version:  "2.0.0",
		HideHelp: true,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "username, u", Usage: "your TUNET account `name`"},
			&cli.StringFlag{Name: "password, p", Usage: "your TUNET `password`"},
			&cli.StringFlag{Name: "config-file, c", Usage: "`path` to your config file, default ~/.auth-nyist"},
			&cli.StringFlag{Name: "hook-success", Usage: "command line to be executed in shell after successful login/out"},
			&cli.BoolFlag{Name: "daemonize, D", Usage: "run without reading username/password from standard input; less log"},
			&cli.BoolFlag{Name: "debug", Usage: "print debug messages"},
			&cli.BoolFlag{Name: "help, h", Usage: "print the help"},
		},
		Commands: []cli.Command{
			{
				Name:  "auth",
				Usage: "(default) Auth via auth.nyist.edu.cn",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "ip", Usage: "authenticating for specified IP address"},
					&cli.BoolFlag{Name: "no-check, n", Usage: "skip online checking, always send login request"},
				},
				Action: cmdAuth,
			},
			{
				Name:   "deauth",
				Usage:  "De-authenticate via auth.nyist.edu.cn",
				Action: cmdDeauth,
			},
			{
				Name:   "keepalive",
				Usage:  "Keep the connection alive by pinging a server",
				Action: cmdKeepalive,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Errorf("Run error: %s\n", err)
		os.Exit(1)
	}
}
