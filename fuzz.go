// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

package cbor

import (
	"bytes"
	"fmt"
	"io/ioutil"
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

func (m *marshaller) MarshalCBOR(em cbor.EncMode) ([]byte, error) {
	return em.Marshal(m.v)
}

func (m *marshaller) UnmarshalCBOR(dm cbor.DecMode, data []byte) error {
	return dm.Unmarshal(data, &m.v)
}

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
		func() interface{} { return new([]interface{}) },
		func() interface{} { return new([]bool) },
		func() interface{} { return new([]uint) },
		func() interface{} { return new([]uint8) },
		func() interface{} { return new([]uint16) },
		func() interface{} { return new([]uint32) },
		func() interface{} { return new([]uint64) },
		func() interface{} { return new([]int) },
		func() interface{} { return new([]int8) },
		func() interface{} { return new([]int16) },
		func() interface{} { return new([]int32) },
		func() interface{} { return new([]int64) },
		func() interface{} { return new([]float32) },
		func() interface{} { return new([]float64) },
		func() interface{} { return new([]string) },
		func() interface{} { return new(map[interface{}]interface{}) },
		func() interface{} { return new(map[int]interface{}) },
		func() interface{} { return new(map[string]interface{}) },
		func() interface{} { return new(cbor.RawMessage) },
		func() interface{} { return new(marshaller) },
		func() interface{} { return new(time.Time) },
		func() interface{} { return new(claims) },
		func() interface{} { return new(signedCWT) },
		func() interface{} { return new(nestedCWT) },
		func() interface{} { return new(coseKey) },
		func() interface{} { return new(attestationObject) },
		func() interface{} { return new(t1) },
		func() interface{} { return new(t2) },
		func() interface{} { return new(t3) },
	} {
		v1 := ctor()
		dec := cbor.NewDecoder(bytes.NewReader(data))
		if dec.Decode(v1) != nil {
			continue
		}
		score = 1

		if t, ok := v1.(*time.Time); ok {
			fuzzTime(t)
			continue
		}

		// Encode with default options
		enc := cbor.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}
		// Encode with "Preferred" encoding options
		em, err := cbor.PreferredUnsortedEncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		enc = em.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}
		// Encode with "Canonical" encoding options
		em, err = cbor.CanonicalEncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		enc = em.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}
		// Encode with "CTAP2 Canonical" encoding options
		em, err = cbor.CTAP2EncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		enc = em.NewEncoder(ioutil.Discard)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}
		// Encode with "Core Deterministic" encoding options
		em, err = cbor.CoreDetEncOptions().EncMode()
		if err != nil {
			panic(err)
		}
		var buf bytes.Buffer
		enc = em.NewEncoder(&buf)
		if err := enc.Encode(v1); err != nil {
			panic(err)
		}

		v2 := ctor()
		dec = cbor.NewDecoder(&buf)
		if dec.Decode(v2) != nil {
			panic(err)
		}

		// Empty RawMessage can't be round tripped.
		if x, ok := v1.(*coseKey); ok {
			if x.CrvOrNOrK == nil {
				v2.(*coseKey).CrvOrNOrK = nil
			}
			if x.XOrE == nil {
				v2.(*coseKey).XOrE = nil
			}
			if x.Y == nil {
				v2.(*coseKey).Y = nil
			}
		}
		if x, ok := v1.(*attestationObject); ok {
			if x.AttStmt == nil {
				v2.(*attestationObject).AttStmt = nil
			}
		}
		if !DeepEqual(v1, v2) {
			panic(fmt.Sprintf("Go type %s not equal: v1 %v, v2 %v", reflect.TypeOf(v1), v1, v2))
		}
	}
	return score
}

func fuzzTime(t *time.Time) {
	em, err := cbor.EncOptions{Time: cbor.TimeUnix}.EncMode()
	if err != nil {
		panic(err)
	}
	// Fuzz unix time with second precision.
	var b1 bytes.Buffer
	enc := em.NewEncoder(&b1)
	if err := enc.Encode(t); err != nil {
		panic(err)
	}
	var t1 time.Time
	dec := cbor.NewDecoder(&b1)
	if err := dec.Decode(&t1); err != nil {
		panic(err)
	}

	em, err = cbor.EncOptions{Time: cbor.TimeUnixMicro}.EncMode()
	if err != nil {
		panic(err)
	}
	// Fuzz unix time with microsecond precision.
	b1.Reset()
	enc = em.NewEncoder(&b1)
	if err := enc.Encode(t); err != nil {
		panic(err)
	}
	dec = cbor.NewDecoder(&b1)
	if err := dec.Decode(&t1); err != nil {
		panic(err)
	}

	em, err = cbor.EncOptions{Time: cbor.TimeUnixDynamic}.EncMode()
	if err != nil {
		panic(err)
	}
	// Fuzz unix time with second/microsecond precision.
	b1.Reset()
	enc = em.NewEncoder(&b1)
	if err := enc.Encode(t); err != nil {
		panic(err)
	}
	dec = cbor.NewDecoder(&b1)
	if err := dec.Decode(&t1); err != nil {
		panic(err)
	}

	if t.Year() >= 0 && t.Year() < 10000 {
		// Fuzz time in RFC3339 format.
		em, err = cbor.EncOptions{Time: cbor.TimeRFC3339}.EncMode()
		if err != nil {
			panic(err)
		}
		var b2 bytes.Buffer
		enc = em.NewEncoder(&b2)
		if err := enc.Encode(t); err != nil {
			panic(err)
		}
		var t2 time.Time
		dec = cbor.NewDecoder(&b2)
		if err := dec.Decode(&t2); err != nil {
			panic(err)
		}

		// Fuzz time in RFC3339 nano format.
		em, err = cbor.EncOptions{Time: cbor.TimeRFC3339Nano}.EncMode()
		if err != nil {
			panic(err)
		}
		b2.Reset()
		enc = em.NewEncoder(&b2)
		if err := enc.Encode(t); err != nil {
			panic(err)
		}
		dec = cbor.NewDecoder(&b2)
		if err := dec.Decode(&t2); err != nil {
			panic(err)
		}
	}
}
