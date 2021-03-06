package hs110

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
)

func handshake1(device *Device, state *HandshakeState, client *http.Client) error {
	_, err := rand.Read(state.LocalSeed[:])
	if err != nil {
		return err
	}

	path := "/app/handshake1"
	url := MakeURL(device, path)
	response, err := client.Post(
		url.String(),
		"application/octet-stream",
		bytes.NewReader(state.LocalSeed[:]))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.ContentLength != 48 {
		return fmt.Errorf("Invalid %s response length", path)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Failed /app/handshake1, status %d", response.StatusCode)
	}

	body := make([]byte, 48)
	_, err = io.ReadFull(response.Body, body)
	if err != nil {
		return err
	}

	copy(state.RemoteSeed[:], body)
	state.Credentials = Credentials()

	signature := sha256.Sum256(Concat(state.LocalSeed[:], state.Credentials[:]))
	if !bytes.Equal(signature[:], body[16:]) {
		return fmt.Errorf("Invalid signature")
	}
	return nil
}

func handshake2(device *Device, state *HandshakeState, client *http.Client) error {
	signature := sha256.Sum256(Concat(state.RemoteSeed[:], state.Credentials[:]))

	path := "/app/handshake2"
	url := MakeURL(device, path)
	response, err := client.Post(
		url.String(),
		"application/octet-stream",
		bytes.NewReader(signature[:]))
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return fmt.Errorf("Failed /app/handshake2, %d", response.StatusCode)
	}

	return nil
}

// Handshake with the given device
func Handshake(device *Device) (*Plug, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := http.Transport{DisableCompression: true}
	client := &http.Client{
		Jar:       jar,
		Transport: &transport,
	}
	var state HandshakeState
	err = handshake1(device, &state, client)
	if err != nil {
		return nil, err
	}
	err = handshake2(device, &state, client)
	if err != nil {
		return nil, err
	}
	return NewPlug(NewSession(device, state, client)), nil
}
