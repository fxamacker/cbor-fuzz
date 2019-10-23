# cbor-fuzz

cbor-fuzz performs fuzzing for my [CBOR library](https://github.com/fxamacker/cbor) (fxamacker/cbor).  It may be useful for other CBOR libraries. 

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

## Example output 
Output from cbor-fuzz v0.6.0 fuzzing fxamacker/cbor v1.1.2.

```
2019/10/23 00:11:35 workers: 2, corpus: 506 (4h8m ago), crashers: 0, restarts: 1/10000, execs: 365720137 (14707/sec), cover: 1437, uptime: 6h54m
2019/10/23 00:11:38 workers: 2, corpus: 507 (2s ago), crashers: 0, restarts: 1/10000, execs: 365757046 (14707/sec), cover: 1437, uptime: 6h54m
2019/10/23 00:11:41 workers: 2, corpus: 507 (5s ago), crashers: 0, restarts: 1/10000, execs: 365801516 (14707/sec), cover: 1437, uptime: 6h54m
...
2019/10/23 17:27:32 workers: 2, corpus: 507 (17h15m ago), crashers: 0, restarts: 1/10000, execs: 1222929112 (14053/sec), cover: 1437, uptime: 24h10m
2019/10/23 17:27:35 workers: 2, corpus: 507 (17h15m ago), crashers: 0, restarts: 1/10000, execs: 1222972965 (14053/sec), cover: 1437, uptime: 24h10m
2019/10/23 17:27:38 workers: 2, corpus: 507 (17h16m ago), crashers: 0, restarts: 1/10000, execs: 1223010097 (14053/sec), cover: 1437, uptime: 24h10m
```

## License 

Copyright (c) 2019 [Faye Amacker](https://github.com/fxamacker)

Licensed under [MIT License](LICENSE)
