# cbor-fuzz

#### :warning: This project was deprecated and replaced by a private project to test [fxamacker/cbor](https://github.com/fxamacker/cbor) (years ago).  The new fuzz tests are written to be more effective at detecting codec issues and uses fewer hardcoded initial corpus.

cbor-fuzz performs coverage-guided fuzzing for a [CBOR library](https://github.com/fxamacker/cbor) (fxamacker/cbor).

Input data for fuzzing is inside the corpus folder: 
* 2 files related to WebAuthn (FIDO U2F key).
* 3 files with custom struct.
* 9 files with [CWT examples (RFC 8392 Appendix A)](https://tools.ietf.org/html/rfc8392#appendix-A)
* 17 files with [COSE examples (RFC 8152 Appendix B & C)](https://github.com/cose-wg/Examples/tree/master/RFC8152).
* 81 files with [CBOR examples (RFC 7049 Appendix A) ](https://tools.ietf.org/html/rfc7049#appendix-A).

During fuzzing, new files are created in these folders:
* corpus -- input data 
* crashers -- crash reports
* suppressions -- stacktraces to ignore 

## Installation
cbor-fuzz uses dvyukov/go-fuzz.
```
go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
go get -u github.com/fxamacker/cbor github.com/fxamacker/cbor-fuzz
``` 

## Usage
Reusing the same corpus folder is recommended, to benefit from corpus generated during prior fuzzing.

```
cd cbor-fuzz
go-fuzz-build .
go-fuzz
```

## Example output 
Output from cbor-fuzz fuzzing fxamacker/cbor.

```
2019/11/03 09:05:24 workers: 2, corpus: 409 (1h55m ago), crashers: 0, restarts: 1/10000, execs: 976487338 (7135/sec), cover: 1464, uptime: 38h1m
2019/11/03 09:05:27 workers: 2, corpus: 410 (2s ago), crashers: 0, restarts: 1/10000, execs: 976498523 (7135/sec), cover: 1464, uptime: 38h1m
2019/11/03 09:05:30 workers: 2, corpus: 410 (5s ago), crashers: 0, restarts: 1/10000, execs: 976507522 (7135/sec), cover: 1481, uptime: 38h1m
```

## System requirements
* Go 1.12 (or newer) is required for cbor v1 and cbor-fuzz.

## License 

Copyright (c) 2019 [Faye Amacker](https://github.com/fxamacker)

Licensed under [MIT License](LICENSE)
