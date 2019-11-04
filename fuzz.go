// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

package cbor

import (
	"fmt"
	"time"

	"github.com/fxamacker/cbor"
)

func Fuzz(data []byte) int {
	var i interface{}
	if cbor.Unmarshal(data, &i) != nil {
		return 0
	}
	_, err := cbor.Marshal(i, cbor.EncOptions{Canonical: false})
	if err != nil {
		panic(err)
	}
	b, err := cbor.Marshal(i, cbor.EncOptions{Canonical: true})
	if err != nil {
		panic(err)
	}
	// b is stripped of tag and indefinite-length.
	fuzz(b)
	return 1
}

// fuzz deserializes-serializes-deserializes cbor data into different types of
// Go values and checks that results of first and second deserialization are equal.
func fuzz(b1 []byte) {
	var err error
	for _, ctor := range []func() interface{}{
		func() interface{} { return new(interface{}) },
		func() interface{} { return new(bool) },
		func() interface{} { return new(uint) },
		func() interface{} { return new(uint8) },
		func() interface{} { return new(uint16) },
		func() interface{} { return new(uint32) },
		func() interface{} { return new(uint64) },
		func() interface{} { return new(int) },
		func() interface{} { return new(int8) },
		func() interface{} { return new(int16) },
		func() interface{} { return new(int32) },
		func() interface{} { return new(int64) },
		func() interface{} { return new(float32) },
		func() interface{} { return new(float64) },
		func() interface{} { return new(string) },
		func() interface{} { return new([]byte) },
		func() interface{} { return new([]interface{}) },
		func() interface{} { return new([]int) },
		func() interface{} { return new([]string) },
		func() interface{} { return new(map[interface{}]interface{}) },
		func() interface{} { return new(map[int]interface{}) },
		func() interface{} { return new(map[string]interface{}) },
		func() interface{} { return new(cbor.RawMessage) },
		func() interface{} { return new(time.Time) },
	} {
		v1 := ctor()
		if cbor.Unmarshal(b1, v1) != nil {
			continue
		}
		if _, ok := v1.(*time.Time); ok {
			fuzzTime(b1)
			continue
		}
		var b2 []byte
		if _, err = cbor.Marshal(v1, cbor.EncOptions{Canonical: false}); err != nil {
			panic(err)
		}
		if b2, err = cbor.Marshal(v1, cbor.EncOptions{Canonical: true}); err != nil {
			panic(err)
		}
		v2 := ctor()
		if err = cbor.Unmarshal(b2, v2); err != nil {
			panic(err)
		}
		if !DeepEqual(v1, v2) {
			panic(fmt.Sprintf("not equal: v1 %v, v2 %v", v1, v2))
		}
	}
}

// fuzzTime deserializes-serializes-deserializes cbor data into time.Time.
func fuzzTime(data []byte) {
	var t time.Time
	if err := cbor.Unmarshal(data, &t); err != nil {
		panic(err)
	}

	b1, err := cbor.Marshal(t, cbor.EncOptions{TimeRFC3339: false})
	if err != nil {
		panic(err)
	}
	var t1 time.Time
	if err = cbor.Unmarshal(b1, &t1); err != nil {
		panic(err)
	}
	if t.Year() >= 0 && t.Year() < 10000 {
		b2, err := cbor.Marshal(t, cbor.EncOptions{TimeRFC3339: true})
		if err != nil {
			panic(err)
		}
		var t2 time.Time
		if err = cbor.Unmarshal(b2, &t2); err != nil {
			panic(err)
		}
	}
}
