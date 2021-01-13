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
	credentials []byte
	localSeed   []byte
	remoteSeed  []byte
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
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Status %d", response.StatusCode)
	}

	body := make([]byte, 48)
	_, err = io.ReadFull(response.Body, body)
	if err != nil {
		return nil, err
	}

	data := new(handshakeData)
	data.localSeed = localSeed
	data.remoteSeed = body[0:16]
	data.credentials = Credentials()

	signature := sha256.Sum256(append(localSeed, data.credentials...))
	if !bytes.Equal(signature[:], body[16:]) {
		return nil, fmt.Errorf("Invalid signature")
	}

	return data, nil
}

func handshake2(device *Device, data *handshakeData, client *http.Client) error {
	signature := sha256.Sum256(append(data.remoteSeed, data.credentials...))

	path := "/app/handshake1"
	url := makeURL(device, path)
	response, err := client.Post(
		url.String(),
		"application/octet-stream",
		bytes.NewReader(signature[:]))

	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Status %d", response.StatusCode)
	}

	return nil
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
	data, err := handshake1(device, client)
	if err != nil {
		return err
	}
	err = handshake2(device, data, client)
	return nil
}
