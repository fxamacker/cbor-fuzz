# cbor-fuzz

`cbor-fuzz` performs fuzz testing for package [`cbor`](https://github.com/fxamacker/cbor), a [CBOR](http://tools.ietf.org/html/rfc7049) encoding and decoding package written in Go.  `corpus` folder contains [RFC 7049 test examples](https://tools.ietf.org/html/rfc7049#appendix-A).

## Installation 

```
go get github.com/fxamacker/cbor-fuzz
``` 

## Usage

```
go-fuzz-build .
go-fuzz
```

## License 

Copyright (c) 2019 [Faye Amacker](https://github.com/fxamacker)

Licensed under [MIT License](LICENSE)