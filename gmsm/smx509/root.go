// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smx509

import (
	"sync"
)

var (
	once           sync.Once
	systemRootsMu  sync.RWMutex
	systemRoots    *CertPool
	systemRootsErr error
)

func systemRootsPool() *CertPool {
	once.Do(initSystemRoots)
	systemRootsMu.RLock()
	defer systemRootsMu.RUnlock()
	return systemRoots
}

func initSystemRoots() {
	systemRootsMu.Lock()
	defer systemRootsMu.Unlock()
	systemRoots, systemRootsErr = loadSystemRoots()
	if systemRootsErr != nil {
		systemRoots = nil
	}
}
