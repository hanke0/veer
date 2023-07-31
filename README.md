# Welcom to Veer

## Introduction

Veer is a tool for tunneling SSH through proxies.

Veer support proxy types:
- socks5
- http

Veer support auth methods:
- http with basic auth
- socks with username and password.

Please open a pull request if you get it working on
other proxies or other auth methods.

## How do I install it?

It esaily to get it if you have Go installed
```
go install github.com/hanke0/veer@latest
```
Or you can download from release page.

## Related works

- `nc`, Netcat is an immensely potent networking utility. It boasts a plethora of implementations across diverse platforms, but inevitably, variations and discrepancies within each platform often result in a less-than-desirable user experience.
- `corkscrew`, Corkscrew is common used for SSH proxies, but it only support http proxy and it is not
every easy to install.
