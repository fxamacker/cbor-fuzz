// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

package cbor

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/big"
	"reflect"
	"time"

	"github.com/fxamacker/cbor"
)

type (
	claims struct {
		Iss string  `cbor:"1,keyasint"`
		Sub string  `cbor:"2,keyasint"`
		Aud string  `cbor:"3,keyasint"`
		Exp float64 `cbor:"4,keyasint"`
		Nbf float64 `cbor:"5,keyasint"`
		Iat float64 `cbor:"6,keyasint"`
		Cti []byte  `cbor:"7,keyasint"`
	}
	coseHeader struct {
		Alg int    `cbor:"1,keyasint,omitempty"`
		Kid []byte `cbor:"4,keyasint,omitempty"`
		IV  []byte `cbor:"5,keyasint,omitempty"`
	}
	signedCWT struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected coseHeader
		Payload     []byte
		Signature   []byte
	}
	nestedCWT struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected coseHeader
		Ciphertext  []byte
	}
	coseKey struct {
		Kty       int             `cbor:"1,keyasint,omitempty"`
		Kid       []byte          `cbor:"2,keyasint,omitempty"`
		Alg       int             `cbor:"3,keyasint,omitempty"`
		KeyOpts   int             `cbor:"4,keyasint,omitempty"`
		IV        []byte          `cbor:"5,keyasint,omitempty"`
		CrvOrNOrK cbor.RawMessage `cbor:"-1,keyasint,omitempty"` // K for symmetric keys, Crv for elliptic curve keys, N for RSA modulus
		XOrE      cbor.RawMessage `cbor:"-2,keyasint,omitempty"` // X for curve x-coordinate, E for RSA public exponent
		Y         cbor.RawMessage `cbor:"-3,keyasint,omitempty"` // Y for curve y-cooridate
		D         []byte          `cbor:"-4,keyasint,omitempty"`
	}
	attestationObject struct {
		AuthnData []byte          `cbor:"authData"`
		Fmt       string          `cbor:"fmt"`
		AttStmt   cbor.RawMessage `cbor:"attStmt"`
	}
	t1 struct {
		T    bool
		Ui   uint
		I    int
		F    float64
		B    []byte
		S    string
		Slci []int
		Mss  map[string]string
	}
	t2 struct {
		T    bool              `cbor:"1,keyasint"`
		Ui   uint              `cbor:"2,keyasint"`
		I    int               `cbor:"3,keyasint"`
		F    float64           `cbor:"4,keyasint"`
		B    []byte            `cbor:"5,keyasint"`
		S    string            `cbor:"6,keyasint"`
		Slci []int             `cbor:"7,keyasint"`
		Mss  map[string]string `cbor:"8,keyasint"`
	}
	t3 struct {
		_    struct{} `cbor:",toarray"`
		T    bool
		Ui   uint
		I    int
		F    float64
		B    []byte
		S    string
		Slci []int
		Mss  map[string]string
	}
	marshaller struct {
		v string
	}
)

func (m *marshaller) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(m.v)
}

func (m *marshaller) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, &m.v)
}

var (
	typeTime   = reflect.TypeOf(time.Time{})
	typeBigInt = reflect.TypeOf(big.Int{})
	typeTag    = reflect.TypeOf(cbor.Tag{})
	typeRawTag = reflect.TypeOf(cbor.RawTag{})
)

var (
	dmDupMapKeyEnforcedAPF, _   = cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}.DecMode()
	dmIntDecConvertSigned, _    = cbor.DecOptions{IntDec: cbor.IntDecConvertSigned}.DecMode()
	dmExtraErrorUnknownField, _ = cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()
)

var (
	emPreferred, _             = cbor.PreferredUnsortedEncOptions().EncMode()
	emCanonical, _             = cbor.CanonicalEncOptions().EncMode()
	emCoreDeterministic, _     = cbor.CoreDetEncOptions().EncMode()
	emTimeUnix, _              = cbor.EncOptions{Time: cbor.TimeUnix}.EncMode()
	emTimeUnixMicro, _         = cbor.EncOptions{Time: cbor.TimeUnixMicro}.EncMode()
	emTimeUnixDynamic, _       = cbor.EncOptions{Time: cbor.TimeUnixDynamic}.EncMode()
	emTimeRFC3339, _           = cbor.EncOptions{Time: cbor.TimeRFC3339}.EncMode()
	emTimeRFC3339Nano, _       = cbor.EncOptions{Time: cbor.TimeRFC3339Nano}.EncMode()
	emBigIntConvertShortest, _ = cbor.EncOptions{BigIntConvert: cbor.BigIntConvertShortest}.EncMode()
	emBigIntConvertNone, _     = cbor.EncOptions{BigIntConvert: cbor.BigIntConvertNone}.EncMode()
)

// Fuzz decodes->encodes->decodes CBOR data into different Go types and
// compares the results.
func Fuzz(data []byte) int {
	score := 0
	for _, ctor := range []func() interface{}{
		func() interface{} { return nil },
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
		func() interface{} { return new([1]byte) },
		func() interface{} { return new([10]byte) },
		func() interface{} { return new([]interface{}) },
		func() interface{} { return new([1]interface{}) },
		func() interface{} { return new([10]interface{}) },
		func() interface{} { return new([]bool) },
		func() interface{} { return new([1]bool) },
		func() interface{} { return new([10]bool) },
		func() interface{} { return new([]*bool) },
		func() interface{} { return new([1]*bool) },
		func() interface{} { return new([10]*bool) },
		func() interface{} { return new([]uint) },
		func() interface{} { return new([1]uint) },
		func() interface{} { return new([10]uint) },
		func() interface{} { return new([]*uint) },
		func() interface{} { return new([1]*uint) },
		func() interface{} { return new([10]*uint) },
		func() interface{} { return new([]uint8) },
		func() interface{} { return new([1]uint8) },
		func() interface{} { return new([10]uint8) },
		func() interface{} { return new([]*uint8) },
		func() interface{} { return new([1]*uint8) },
		func() interface{} { return new([10]*uint8) },
		func() interface{} { return new([]uint16) },
		func() interface{} { return new([1]uint16) },
		func() interface{} { return new([10]uint16) },
		func() interface{} { return new([]*uint16) },
		func() interface{} { return new([1]*uint16) },
		func() interface{} { return new([10]*uint16) },
		func() interface{} { return new([]uint32) },
		func() interface{} { return new([1]uint32) },
		func() interface{} { return new([10]uint32) },
		func() interface{} { return new([]*uint32) },
		func() interface{} { return new([1]*uint32) },
		func() interface{} { return new([10]*uint32) },
		func() interface{} { return new([]uint64) },
		func() interface{} { return new([1]uint64) },
		func() interface{} { return new([10]uint64) },
		func() interface{} { return new([]*uint64) },
		func() interface{} { return new([1]*uint64) },
		func() interface{} { return new([10]*uint64) },
		func() interface{} { return new([]int) },
		func() interface{} { return new([1]int) },
		func() interface{} { return new([10]int) },
		func() interface{} { return new([]*int) },
		func() interface{} { return new([1]*int) },
		func() interface{} { return new([10]*int) },
		func() interface{} { return new([]int8) },
		func() interface{} { return new([1]int8) },
		func() interface{} { return new([10]int8) },
		func() interface{} { return new([]*int8) },
		func() interface{} { return new([1]*int8) },
		func() interface{} { return new([10]*int8) },
		func() interface{} { return new([]int16) },
		func() interface{} { return new([1]int16) },
		func() interface{} { return new([10]int16) },
		func() interface{} { return new([]*int16) },
		func() interface{} { return new([1]*int16) },
		func() interface{} { return new([10]*int16) },
		func() interface{} { return new([]int32) },
		func() interface{} { return new([1]int32) },
		func() interface{} { return new([10]int32) },
		func() interface{} { return new([]*int32) },
		func() interface{} { return new([1]*int32) },
		func() interface{} { return new([10]*int32) },
		func() interface{} { return new([]int64) },
		func() interface{} { return new([1]int64) },
		func() interface{} { return new([10]int64) },
		func() interface{} { return new([]*int64) },
		func() interface{} { return new([1]*int64) },
		func() interface{} { return new([10]*int64) },
		func() interface{} { return new([]float32) },
		func() interface{} { return new([1]float32) },
		func() interface{} { return new([10]float32) },
		func() interface{} { return new([]*float32) },
		func() interface{} { return new([1]*float32) },
		func() interface{} { return new([10]*float32) },
		func() interface{} { return new([]float64) },
		func() interface{} { return new([1]float64) },
		func() interface{} { return new([10]float64) },
		func() interface{} { return new([]*float64) },
		func() interface{} { return new([1]*float64) },
		func() interface{} { return new([10]*float64) },
		func() interface{} { return new([]string) },
		func() interface{} { return new([1]string) },
		func() interface{} { return new([10]string) },
		func() interface{} { return new([]*string) },
		func() interface{} { return new([1]*string) },
		func() interface{} { return new([10]*string) },
		func() interface{} { return new(map[interface{}]interface{}) },
		func() interface{} { return new(map[int]interface{}) },
		func() interface{} { return new(map[string]interface{}) },
		func() interface{} { return new(map[int]int) },
		func() interface{} { return new(map[int]*int) },
		func() interface{} { return new(map[string]string) },
		func() interface{} { return new(map[string]*string) },
		func() interface{} { return new(cbor.RawMessage) },
		func() interface{} { return new(cbor.Tag) },
		func() interface{} { return new(cbor.RawTag) },
		func() interface{} { return new(marshaller) },
		func() interface{} { return new(time.Time) },
		func() interface{} { return new(big.Int) },
		func() interface{} { return new(claims) },
		func() interface{} { return new(signedCWT) },
		func() interface{} { return new(nestedCWT) },
		func() interface{} { return new(coseKey) },
		func() interface{} { return new(attestationObject) },
		func() interface{} { return new(t1) },
		func() interface{} { return new(t2) },
		func() interface{} { return new(t3) },
	} {
		// Decode with default options
		v1 := ctor()
		dec := cbor.NewDecoder(bytes.NewReader(data))
		if dec.Decode(v1) != nil {
			continue
		}
		score = 1

		// Decode with IntDec set to IntDecConvertSigned.
		fuzzIntDecoding(data, ctor())

		// Decode with DupMapKey set to DupMapKeyEnforcedAPF.
		fuzzDuplicateMapKeyDecoding(data, ctor())

		// Decode with ExtraReturnErrors set to ExtraDecErrorUnknownField.
		fuzzUnknownField(data, ctor())

		switch v := v1.(type) {
		case *time.Time:
			fuzzTime(v)
			continue
		case *big.Int:
			fuzzBigInt(v)
			continue
		}

		// Encode with default options
		enc := cbor.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		// Encode with "Preferred" encoding options
		enc = emPreferred.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		// Encode with "Canonical" encoding options
		enc = emCanonical.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		// Encode with "CTAP2 Canonical" encoding options (TagsAllowed is needed to avoid error when encoding CBOR tags)
		ctap2Opts := cbor.CTAP2EncOptions()
		ctap2Opts.TagsMd = cbor.TagsAllowed
		emCTAP2, err := ctap2Opts.EncMode()
		if err != nil {
			panic(err)
		}
		enc = emCTAP2.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		// Encode with BigIntConvert set to BigIntConvertNone (encode big.Int as CBOR tag 2/3)
		enc = emBigIntConvertNone.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		// Encode with "Core Deterministic" encoding options
		var buf bytes.Buffer
		enc = emCoreDeterministic.NewEncoder(&buf)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		v2 := ctor()
		dec = cbor.NewDecoder(&buf)
		if dec.Decode(v2) != nil {
			panic(err)
		}

		// Empty RawMessage can't be round tripped.
		switch x := v1.(type) {
		case *coseKey:
			if x.CrvOrNOrK == nil {
				v2.(*coseKey).CrvOrNOrK = nil
			}
			if x.XOrE == nil {
				v2.(*coseKey).XOrE = nil
			}
			if x.Y == nil {
				v2.(*coseKey).Y = nil
			}
		case *attestationObject:
			if x.AttStmt == nil {
				v2.(*attestationObject).AttStmt = nil
			}
		}

		// Skip equal test for objects with time.Time or big.Int as an element
		if !hasType(reflect.ValueOf(v1), typeTime) && !hasType(reflect.ValueOf(v1), typeBigInt) && !DeepEqual(v1, v2) {
			rv1, rv2 := reflect.ValueOf(v1), reflect.ValueOf(v2)
			for rv1.Kind() == reflect.Ptr || rv1.Kind() == reflect.Interface {
				rv1 = rv1.Elem()
			}
			for rv2.Kind() == reflect.Ptr || rv2.Kind() == reflect.Interface {
				rv2 = rv2.Elem()
			}
			panic(fmt.Sprintf("not equal: v1 %v (%s), v2 %v (%s)", rv1.Interface(), rv1.Type(), rv2.Interface(), rv2.Type()))
		}
	}
	return score
}

func fuzzDuplicateMapKeyDecoding(data []byte, v interface{}) {
	dec := dmDupMapKeyEnforcedAPF.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		if _, ok := err.(*cbor.DupMapKeyError); !ok {
			panic(err)
		}
	}
}

func fuzzIntDecoding(data []byte, v interface{}) {
	dec := dmIntDecConvertSigned.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		if _, ok := err.(*cbor.UnmarshalTypeError); !ok {
			panic(err)
		}
	}
}

func fuzzUnknownField(data []byte, v interface{}) {
	dec := dmExtraErrorUnknownField.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		if _, ok := err.(*cbor.UnknownFieldError); !ok {
			panic(err)
		}
	}
}

func fuzzTime(t *time.Time) {
	// Fuzz unix time with second precision.
	var b1 bytes.Buffer
	enc := emTimeUnix.NewEncoder(&b1)
	if err := enc.Encode(t); err != nil {
		panic(err)
	}
	var t1 time.Time
	dec := cbor.NewDecoder(&b1)
	if err := dec.Decode(&t1); err != nil {
		panic(err)
	}

	// Fuzz unix time with microsecond precision.
	b1.Reset()
	enc = emTimeUnixMicro.NewEncoder(&b1)
	if err := enc.Encode(t); err != nil {
		panic(err)
	}
	dec = cbor.NewDecoder(&b1)
	if err := dec.Decode(&t1); err != nil {
		panic(err)
	}

	// Fuzz unix time with second/microsecond precision.
	b1.Reset()
	enc = emTimeUnixDynamic.NewEncoder(&b1)
	if err := enc.Encode(t); err != nil {
		panic(err)
	}
	dec = cbor.NewDecoder(&b1)
	if err := dec.Decode(&t1); err != nil {
		panic(err)
	}

	if t.Year() >= 0 && t.Year() < 10000 {
		// Fuzz time in RFC3339 format.
		var b2 bytes.Buffer
		enc = emTimeRFC3339.NewEncoder(&b2)
		if err := enc.Encode(t); err != nil {
			panic(err)
		}
		var t2 time.Time
		dec = cbor.NewDecoder(&b2)
		if err := dec.Decode(&t2); err != nil {
			panic(err)
		}

		// Fuzz time in RFC3339 nano format.
		b2.Reset()
		enc = emTimeRFC3339Nano.NewEncoder(&b2)
		if err := enc.Encode(t); err != nil {
			panic(err)
		}
		dec = cbor.NewDecoder(&b2)
		if err := dec.Decode(&t2); err != nil {
			panic(err)
		}
	}
}

func fuzzBigInt(bi *big.Int) {
	// Encode big.Int to shortest int representation, decode it, and compare results.
	var b bytes.Buffer
	enc := emBigIntConvertShortest.NewEncoder(&b)
	if err := enc.Encode(bi); err != nil {
		panic(err)
	}
	bib := b.Bytes()
	if len(bib) < 1 {
		panic(fmt.Sprintf("BigIntConvertShortest encoding doesn't produce CBOR integer data: 0x%x", bib))
	}
	if bib[0]&0xe0 != 0x00 && bib[0]&0xe0 != 0x20 && bib[0] != 0xc2 && bib[0] != 0xc3 {
		panic(fmt.Sprintf("BigIntConvertShortest encoding doesn't produce CBOR integer data: 0x%x", bib))
	}
	var bi1 big.Int
	dec := cbor.NewDecoder(&b)
	if err := dec.Decode(&bi1); err != nil {
		panic(err)
	}
	if bi.Cmp(&bi1) != 0 {
		panic(fmt.Sprintf("not equal: v1 %v (big.Int), v2 %v (big.Int)", bi, bi1))
	}

	// Encode big.Int to CBOR tag 2/3 data, decode it, and compare results.
	b.Reset()
	enc = emBigIntConvertNone.NewEncoder(&b)
	if err := enc.Encode(bi); err != nil {
		panic(err)
	}
	bib = b.Bytes()
	if len(bib) < 2 {
		panic(fmt.Sprintf("BigIntConvertNone encoding doesn't produce CBOR tag 2/3 data: 0x%x", bib))
	}
	if bib[0] != 0xc2 && bib[0] != 0xc3 {
		panic(fmt.Sprintf("BigIntConvertNone encoding doesn't produce CBOR tag 2/3 data: 0x%x", bib))
	}
	var bi2 big.Int
	dec = cbor.NewDecoder(&b)
	if err := dec.Decode(&bi2); err != nil {
		panic(err)
	}
	if bi.Cmp(&bi2) != 0 {
		panic(fmt.Sprintf("not equal: v1 %v (big.Int), v2 %v (big.Int)", bi, bi2))
	}
}

func hasType(rv reflect.Value, rt reflect.Type) bool {
	if !rv.IsValid() {
		return false
	}

	if rv.Type() == rt {
		return true
	}

	switch rv.Kind() {
	case reflect.Interface, reflect.Ptr:
		if rv.IsNil() {
			return false
		}
		return hasType(rv.Elem(), rt)
	case reflect.Struct:
		for i, n := 0, rv.NumField(); i < n; i++ {
			if hasType(rv.Field(i), rt) {
				return true
			}
		}
		return false
	case reflect.Array, reflect.Slice:
		for i := 0; i < rv.Len(); i++ {
			if hasType(rv.Index(i), rt) {
				return true
			}
		}
		return false
	case reflect.Map:
		for _, k := range rv.MapKeys() {
			if hasType(k, rt) || hasType(rv.MapIndex(k), rt) {
				return true
			}
		}
		return false
	default:
		return false
	}
}
