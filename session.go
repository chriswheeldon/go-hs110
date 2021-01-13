package hs110

import (
	"crypto/sha256"
	"encoding/binary"
	"net/http"
)

// Session manages the stateful plug encryption
type Session struct {
	client    *http.Client
	key       [16]byte
	iv        [12]byte
	counter   uint32
	signature [28]byte
}

// NewSession constructs a Session struct
func NewSession(handshake HandshakeState, client *http.Client) *Session {
	session := new(Session)
	session.client = client
	session.key = deriveKey(handshake)
	session.iv, session.counter = deriveIv(handshake)
	session.signature = deriveSig(handshake)
	return session
}

// Private methods

func getRequestIv(session Session) [16]byte {
	var iv [16]byte
	copy(iv[:], session.iv[:])
	binary.BigEndian.PutUint32(iv[12:], session.counter)
	return iv
}

func getRequestMAC(session Session, message []byte) [32]byte {
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], session.counter)
	return sha256.Sum256(Concat(session.signature[:], counter[:], message))
}

// Private helpers

func deriveKey(handshake HandshakeState) [16]byte {
	hash := sha256.Sum256(Concat(
		[]byte("lsk"),
		handshake.LocalSeed[:],
		handshake.RemoteSeed[:],
		handshake.Credentials[:]))
	var key [16]byte
	copy(key[:], hash[0:16])
	return key
}

func deriveIv(handshake HandshakeState) ([12]byte, uint32) {
	hash := sha256.Sum256(Concat(
		[]byte("iv"),
		handshake.LocalSeed[:],
		handshake.RemoteSeed[:],
		handshake.Credentials[:]))
	var iv [12]byte
	copy(iv[:], hash[0:12])
	return iv, binary.BigEndian.Uint32(hash[12:16]) & 0x7fffffff
}

func deriveSig(handshake HandshakeState) [28]byte {
	hash := sha256.Sum256(Concat(
		[]byte("ldk"),
		handshake.LocalSeed[:],
		handshake.RemoteSeed[:],
		handshake.Credentials[:]))
	var sig [28]byte
	copy(sig[:], hash[0:28])
	return sig
}
