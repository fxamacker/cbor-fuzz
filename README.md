# cbor-fuzz

cbor-fuzz performs fuzzing for my CBOR library ([fxamacker/cbor](https://github.com/fxamacker/cbor)).  It may be useful for other CBOR libraries. 

The corpus folder contains [RFC 7049 test data](https://tools.ietf.org/html/rfc7049#appendix-A) as seed (except test value -18446744073709551616, which cannot fit into Go's int64 data type.)

## Installation 

```
go get github.com/fxamacker/cbor-fuzz
``` 

## Usage

```
go-fuzz-build .
go-fuzz
```

## Example output (fxamacker/cbor v1.1.1)

```
2019/10/20 18:12:03 workers: 2, corpus: 493 (19h3m ago), crashers: 0, restarts: 1/10000, execs: 1432146987 (13825/sec), cover: 1431, uptime: 28h46m
2019/10/20 18:12:06 workers: 2, corpus: 494 (1s ago), crashers: 0, restarts: 1/10000, execs: 1432193155 (13825/sec), cover: 1431, uptime: 28h46m
2019/10/20 18:12:09 workers: 2, corpus: 495 (0s ago), crashers: 0, restarts: 1/10000, execs: 1432239767 (13825/sec), cover: 1431, uptime: 28h46m
...
2019/10/20 22:26:24 workers: 2, corpus: 495 (4h14m ago), crashers: 0, restarts: 1/10000, execs: 1642869630 (13823/sec), cover: 1431, uptime: 33h0m
2019/10/20 22:26:27 workers: 2, corpus: 495 (4h14m ago), crashers: 0, restarts: 1/10000, execs: 1642906722 (13823/sec), cover: 1431, uptime: 33h0m
2019/10/20 22:26:30 workers: 2, corpus: 495 (4h14m ago), crashers: 0, restarts: 1/10000, execs: 1642945269 (13823/sec), cover: 1431, uptime: 33h0m
```

## License 

Copyright (c) 2019 [Faye Amacker](https://github.com/fxamacker)

Licensed under [MIT License](LICENSE)
