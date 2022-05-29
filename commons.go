package afssl

import "os"

func pathExist(v string) (ok bool) {
	_, err := os.Stat(v)
	if err == nil {
		ok = true
		return
	}
	ok = !os.IsNotExist(err)
	return
}
