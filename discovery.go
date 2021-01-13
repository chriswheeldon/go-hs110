package hs110

import (
	"encoding/json"
	"net"
	"time"
)

type deviceResult struct {
	Addr  string `json:"ip"`
	Model string `json:"device_model"`
}

type deviceJSON struct {
	Result deviceResult `json:"result"`
}

// Device discovery response
type Device struct {
	Addr  net.IP
	Model string
}

func broadcastMagic(conn *net.UDPConn) error {
	broadcast, err := net.ResolveUDPAddr("udp4", "255.255.255.255:20002")
	if err != nil {
		return err
	}

	magic := []byte{
		0x02, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x46, 0x3c, 0xb5, 0xd3}

	_, err = conn.WriteTo(magic, broadcast)
	if err != nil {
		return err
	}
	return nil
}

func readResponse(conn *net.UDPConn) (*Device, error) {
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	response := deviceJSON{}
	err = json.Unmarshal(buffer[16:n], &response)
	if err != nil {
		return nil, err
	}

	device := new(Device)
	device.Model = response.Result.Model
	device.Addr = net.ParseIP(response.Result.Addr)

	return device, nil
}

// Discover smart plugs on the local network
func Discover() (*Device, error) {
	listen, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", listen)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil, err
	}

	err = broadcastMagic(conn)
	if err != nil {
		return nil, err
	}
	return readResponse(conn)
}
