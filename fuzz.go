// Copyright (c) 2019 Faye Amacker. All rights reserved.
// Use of this source code is governed by a MIT license found in the LICENSE file.

package cbor

import "github.com/fxamacker/cbor"

func Fuzz(data []byte) int {
	var i interface{}
	if unmarshalErr := cbor.Unmarshal(data, &i); unmarshalErr != nil {
		return 0
	}
	if _, marshalErr := cbor.Marshal(i, cbor.EncOptions{Canonical: true}); marshalErr != nil {
		panic(marshalErr)
	}
	if _, marshalErr := cbor.Marshal(i, cbor.EncOptions{Canonical: false}); marshalErr != nil {
		panic(marshalErr)
	}
	return 1
}
