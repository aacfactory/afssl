// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smx509

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/var/ssl/certs/ca-bundle.crt",
}

// Possible directories with certificate files; all will be read.
var certDirectories = []string{
	"/var/ssl/certs",
}
