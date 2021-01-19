package hs110

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
)

// Session manages the stateful plug encryption
type Session struct {
	device    *Device
	client    *http.Client
	key       [16]byte
	iv        [12]byte
	counter   uint32
	signature [28]byte
}

// NewSession constructs a Session struct
func NewSession(device *Device, handshake HandshakeState, client *http.Client) *Session {
	session := new(Session)
	session.device = device
	session.client = client
	session.key = deriveKey(handshake)
	session.iv, session.counter = deriveIv(handshake)
	session.signature = deriveSig(handshake)
	return session
}

// Send a message over the given session
func Send(session Session, message []byte) error {
	session.counter++
	session.counter &= 0x7fffffff
	ciphertext, err := encrypt(session, message)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/app/request?seq=%d", session.counter)
	url := MakeURL(session.device, path)
	response, err := session.client.Post(
		url.String(),
		"application/octet-stream",
		bytes.NewReader(ciphertext))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func encrypt(session Session, message []byte) ([]byte, error) {
	plaintext, err := PKCS7Pad(message, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	iv := getRequestIv(session)
	mac := getRequestMAC(session, message)
	ciphertext := make([]byte, len(plaintext))

	block, _ := aes.NewCipher(session.key[:])
	mode := cipher.NewCBCEncrypter(block, iv[:])
	mode.CryptBlocks(ciphertext, plaintext)
	return Concat(mac[:], ciphertext), nil
}

func decrypt(session Session, ciphertext []byte) ([]byte, error) {
	iv := getRequestIv(session)
	plaintext := make([]byte, len(ciphertext))

	block, _ := aes.NewCipher(session.key[:])
	mode := cipher.NewCBCEncrypter(block, iv[:])
	mode.CryptBlocks(plaintext, ciphertext[32:]) // TODO: check mac
	return PKCS7Unpad(plaintext, aes.BlockSize)
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
