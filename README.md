# AuthingNYIST

[![Build Status](https://github.com/Palvef/AuthingNYIST/actions/workflows/go.yml/badge.svg)](https://github.com/Palvef/AuthingNYIST/actions)
![GPLv3](https://img.shields.io/badge/license-GPLv3-blue.svg)

A command-line NYIST (auth.nyist.edu.cn) authentication tool.

## Download Binary

Download prebuilt binaries from <https://github.com/Palvef/AuthingNYIST/releases>

## Usage

Simply try `./auth-nyist`, then enter your user name and password.

```help
NAME:
   auth-nyist - Authenticating utility for NYIST

USAGE:
   auth-nyist [options]
   auth-nyist [options] auth [auth_options]
   auth-nyist [options] deauth [auth_options]
   auth-nyist [options] online [online_options]

VERSION:
   2.0.0

COMMANDS:
     auth       (default) Auth via auth.nyist.edu.cn
     deauth     De-authenticate via auth.nyist.edu.cn
     keepalive  Keep the connection alive by pinging a server

GLOBAL OPTIONS:
   --username name, -u name          your portal account name
   --password password, -p password  your portal password
   --config-file path, -c path       path to your config file, default ~/.auth-nyist
   --hook-success value              command line to be executed in shell after successful login/out
   --daemonize, -D                   run without reading username/password from standard input; less log
   --debug                           print debug messages
   --help, -h                        print the help
   --version, -v                     print the version
```

The program looks for a config file in `$XDG_CONFIG_HOME/auth-nyist`, `~/.config/auth-nyist`, `~/.auth-nyist` in order.
Write a config file to store your username & password or other options in the following format.

```json
{
  "username": "your-username",
  "password": "your-password",
  "host": "",
  "ip": "166.xxx.xx.xx",
  "debug": false,
  "useV6": false,
  "noCheck": false,
  "insecure": false,
  "daemonize": false,
  "acId": "",
  "campusOnly": false
}
```

Unless you have special need, you can only have `username` and `password` field in your config file. For `host`, the default value defined in code should be sufficient hence there should be no need to fill it. `UseV6` automatically determine the `host` to use. For `ip`, unless you are auth/login the other boxes you have(not the box `auth-nyist` is running on), you can leave it blank. For those boxes unable to get correct acid themselves, we can specify the acid for them by using `acId`. Other options are self-explanatory.

## Autostart

It is suggested that one configures and runs it manually first with `debug` flag turned on, which ensures the correctness of one's config, then start it as system service. For `daemonize` flag, it forces the program to only log errors, hence debugging should be done earlier and manually. `daemonize` is automatically turned on for system service (ref to associated systemd unit files).

### Systemd

To configure automatic authentication on systemd-based Linux distro, take a look at `docs/systemd` folder. Just modify the path in configuration files, then copy them to `/etc/systemd` folder.

Note that the program should have access to the configuration file.
For `system/goauthing.service`, since it is run as `nobody`, `/etc/goauthing.json` can not be read by it, hence you can use the following command to enable access:

```shell
setfacl -m u:nobody:r /etc/goauthing.json
```

Or, to be more secure, you can choose `system/goauthing@.service` or `user/goauthing.service` and store the configuration file in the home directory.

### OpenWRT

For OpenWRT users, there are two options available: `goauthing` loading the configuration file, and `goauthing@` interacting with the UCI. The init script should go to the `/etc/init.d/` folder. With the latter, use the following procedure to set up:

```shell
touch /etc/config/goauthing
uci set goauthing.config.username='<YOUR-TUNET-ACCOUNT-NAME>'
uci set goauthing.config.password='<YOUR-TUNET-PASSWORD>'
uci commit goauthing
/etc/init.d/goauthing enable
/etc/init.d/goauthing start
```

## Build

Requires Go 1.11 or above

```shell
export GO111MODULE=on
go build -o auth-nyist github.com/Palvef/AuthingNYIST/cli
```

## Acknowledgments

This project was inspired by the following projects:

- <https://github.com/jiegec/auth-tsinghua>
- <https://github.com/Berrysoft/TsinghuaNet>
- <https://github.com/z4yx/GoAuthing>