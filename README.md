# tcpraw

[![GoDoc][1]][2] [![Build Status][3]][4] [![Go Report Card][5]][6] [![Coverage Statusd][7]][8] [![MIT licensed][9]][10] 

[1]: https://godoc.org/github.com/xtaci/tcpraw?status.svg
[2]: https://godoc.org/github.com/xtaci/tcpraw
[3]: https://img.shields.io/github/created-at/xtaci/tcpraw
[4]: https://img.shields.io/github/created-at/xtaci/tcpraw
[5]: https://goreportcard.com/badge/github.com/xtaci/tcpraw
[6]: https://goreportcard.com/report/github.com/xtaci/tcpraw
[7]: https://codecov.io/gh/xtaci/tcpraw/branch/master/graph/badge.svg
[8]: https://codecov.io/gh/xtaci/tcpraw
[9]: https://img.shields.io/badge/license-MIT-blue.svg
[10]: LICENSE



# Introduction

A packet-oriented connection by simulating TCP protocol with some improvements.

## Features

0. Tiny
1. Support IPv4 and IPv6.
2. Realistic sliding window, NAT friendly.
3. Pure golang without cgo, available on all architecture.


## Benchmark

**xtaci**
```
goos: linux
goarch: amd64
pkg: github.com/xtaci/tcpraw
BenchmarkEcho-4            15074             79522 ns/op          12.88 MB/s        6114 B/op         56 allocs/op
PASS
```


**Musixal**
```
goos: linux
goarch: amd64
pkg: github.com/Musixal/tcpraw
BenchmarkEcho-4            18313             62983 ns/op          16.26 MB/s        2698 B/op         14 allocs/op
PASS
```


## Status

Stable


