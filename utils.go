package hs110

import (
	"bytes"
	"crypto/md5"
	"errors"
	"net/url"
)

// HandshakeState holds the state accumulated during the handshake process
type HandshakeState struct {
	Credentials [16]byte
	LocalSeed   [16]byte
	RemoteSeed  [16]byte
}

func MakeURL(device *Device, path string) url.URL {
	url := url.URL{}
	url.Host = device.Addr.String()
	url.Scheme = "http"
	url.Path = path
	return url
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

// PKCS7 padding.

// PKCS7 errors.
var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

// PKCS7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func PKCS7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// PKCS7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func PKCS7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}
