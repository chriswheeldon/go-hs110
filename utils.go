package hs110

import "crypto/md5"

// Credentials hash
func Credentials() [md5.Size]byte {
	empty := []byte{}
	username := md5.Sum(empty)
	password := md5.Sum(empty)
	return md5.Sum(append(username[:], password[:]...)) // is this idiomatic?
}
