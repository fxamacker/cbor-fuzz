// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

package fuzz

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
		func() interface{} { return nil },
		func() interface{} { b := true; return b },
		func() interface{} { b := true; return &b },
		func() interface{} { i := uint(0); return i },
		func() interface{} { i := uint(0); return &i },
		func() interface{} { i := uint8(0); return i },
		func() interface{} { i := uint8(0); return &i },
		func() interface{} { i := uint16(0); return i },
		func() interface{} { i := uint16(0); return &i },
		func() interface{} { i := uint32(0); return i },
		func() interface{} { i := uint32(0); return &i },
		func() interface{} { i := uint64(0); return i },
		func() interface{} { i := uint64(0); return &i },
		func() interface{} { i := int(0); return i },
		func() interface{} { i := int(0); return &i },
		func() interface{} { i := int8(0); return i },
		func() interface{} { i := int8(0); return &i },
		func() interface{} { i := int16(0); return i },
		func() interface{} { i := int16(0); return &i },
		func() interface{} { i := int32(0); return i },
		func() interface{} { i := int32(0); return &i },
		func() interface{} { i := int64(0); return i },
		func() interface{} { i := int64(0); return &i },
		func() interface{} { f := float32(0.0); return f },
		func() interface{} { f := float32(0.0); return &f },
		func() interface{} { f := float64(0.0); return f },
		func() interface{} { f := float64(0.0); return &f },
		func() interface{} { s := ""; return s },
		func() interface{} { s := ""; return &s },
		func() interface{} { b := []byte{}; return b },
		func() interface{} { b := []byte{}; return &b },
		func() interface{} { arr := []interface{}{}; return arr },
		func() interface{} { arr := []interface{}{}; return &arr },
		func() interface{} { arr := []int{}; return arr },
		func() interface{} { arr := []int{}; return &arr },
		func() interface{} { arr := []string{}; return arr },
		func() interface{} { arr := []string{}; return &arr },
		func() interface{} { m := map[interface{}]interface{}{}; return m },
		func() interface{} { m := map[interface{}]interface{}{}; return &m },
		func() interface{} { m := map[int]interface{}{}; return m },
		func() interface{} { m := map[int]interface{}{}; return &m },
		func() interface{} { m := map[string]interface{}{}; return m },
		func() interface{} { m := map[string]interface{}{}; return &m },
		func() interface{} { t := time.Time{}; return t },
	} {
		v1 := ctor()
		if cbor.Unmarshal(b1, &v1) != nil {
			continue
		}
		if _, ok := v1.(time.Time); ok {
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
		if err = cbor.Unmarshal(b2, &v2); err != nil {
			panic(err)
		}
		if !DeepEqual(v1, v2) {
			panic(fmt.Sprintf("not equal: v1 %v, v2 %v", v1, v2))
		}
	}
}

// fuzzTime deserializes-serializes-deserializes cbor data into time.Time
// and checks that results of first and second deserialization are equal.
func fuzzTime(data []byte) {
	var t, t1, t2 time.Time
	var b1, b2 []byte
	var err error
	if err = cbor.Unmarshal(data, &t); err != nil {
		panic(err)
	}
	if b1, err = cbor.Marshal(t, cbor.EncOptions{TimeRFC3339: false}); err != nil {
		panic(err)
	}
	if b2, err = cbor.Marshal(t, cbor.EncOptions{TimeRFC3339: true}); err != nil {
		panic(err)
	}
	if err = cbor.Unmarshal(b1, &t1); err != nil {
		panic(err)
	}
	if err = cbor.Unmarshal(b2, &t2); err != nil {
		panic(err)
	}
	if !t.Equal(t1) {
		panic(fmt.Sprintf("not equal: t %v, t1 %v", t, t1))
	}
	if !t1.Equal(t2) {
		panic(fmt.Sprintf("not equal: t1 %v, t2 %v", t1, t2))
	}
}
