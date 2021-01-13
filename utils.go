package hs110

import "crypto/md5"

// Credentials hash
func Credentials() []byte {
	empty := []byte{}
	username := md5.Sum(empty)
	password := md5.Sum(empty)
	credentials := md5.Sum(append(username[:], password[:]...)) // is this idiomatic?
	return credentials[:]
}
