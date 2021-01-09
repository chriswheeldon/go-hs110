package hs110

import (
	"fmt"
	"net"
)

// Discover smart plugs on the local network
func Discover() error {
	addr, err := net.ResolveUDPAddr("udp", "255.255.255.255")
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	magic := []byte{
		0x02, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x46, 0x3c, 0xb5, 0xd3}

	_, err = conn.Write(magic)
	if err != nil {
		return err
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}

	response := string(buffer[:n])
	fmt.Println("Discovered", response)

	return nil
}
