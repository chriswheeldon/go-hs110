package hs110

import "crypto/md5"

// HandshakeState holds the state accumulated during the handshake process
type HandshakeState struct {
	Credentials [16]byte
	LocalSeed   [16]byte
	RemoteSeed  [16]byte
}

// Credentials hash
func Credentials() [16]byte {
	empty := []byte{}
	username := md5.Sum(empty)
	password := md5.Sum(empty)
	return md5.Sum(append(username[:], password[:]...))
}

// Concat n byte slices
func Concat(slices ...[]byte) []byte {
	length := 0
	for _, slice := range slices {
		length += len(slice)
	}
	result := make([]byte, length)

	length = 0
	for _, slice := range slices {
		copy(result[length:], slice)
		length += len(slice)
	}
	return result
}
