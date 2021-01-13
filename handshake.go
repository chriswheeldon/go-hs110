package hs110

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

type handshakeData struct {
	localSeed  []byte
	remoteSeed []byte
}

func makeURL(device *Device, path string) url.URL {
	url := url.URL{}
	url.Host = device.Addr.String()
	url.Scheme = "http"
	url.Path = path
	return url
}

func handshake1(device *Device, client *http.Client) (*handshakeData, error) {
	localSeed := make([]byte, 16)
	_, err := rand.Read(localSeed)
	if err != nil {
		return nil, err
	}

	path := "/app/handshake1"
	url := makeURL(device, path)
	response, err := client.Post(
		url.String(),
		"application/octet-stream",
		bytes.NewReader(localSeed))
	if err != nil {
		return nil, err
	}

	if response.ContentLength != 48 {
		return nil, fmt.Errorf("Invalid %s response length", path)
	}

	body := make([]byte, 48)
	_, err = io.ReadFull(response.Body, body)
	if err != nil {
		return nil, err
	}

	credentials := Credentials()
	signature := sha256.Sum256(append(localSeed, credentials[:]...))
	if !bytes.Equal(signature[:], body[16:]) {
		return nil, fmt.Errorf("Invalid signature")
	}

	data := new(handshakeData)
	data.localSeed = localSeed
	data.remoteSeed = body[0:16]

	return data, nil
}

// Handshake with the given device
func Handshake(device *Device) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Jar: jar,
	}
	_, err = handshake1(device, client)
	if err != nil {
		return err
	}
	return nil
}
