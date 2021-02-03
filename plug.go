package hs110

import "encoding/json"

// Plug is a higher level wrapper around a session
type Plug struct {
	session *Session
}

// NewPlug constructs a Plug from a Session
func NewPlug(session *Session) *Plug {
	plug := new(Plug)
	plug.session = session
	return plug
}

// PowerResponse holds power, voltage and current
// readings obtained from the device's energy meter.
type PowerResponse struct {
	PowerMilliwatts   int `json:"power_mw"`
	VoltageMillivolts int `json:"voltage_mv"`
	CurrentMilliamps  int `json:"current_ma"`
}

type emeterResponse struct {
	Emeter struct {
		GetRealtime PowerResponse `json:"get_realtime"`
	} `json:"emeter"`
}

// On turns the plug on
func (plug *Plug) On() error {
	_, err := plug.session.Send([]byte(`{"system":{"set_relay_state":{"state":1}}}`))
	if err != nil {
		return err
	}
	return nil
}

// Off turns the plug on
func (plug *Plug) Off() error {
	_, err := plug.session.Send([]byte(`{"system":{"set_relay_state":{"state":0}}}`))
	if err != nil {
		return err
	}
	return nil
}

// PowerMeter obtains readings from the device's energy meter.
func (plug *Plug) PowerMeter() (*PowerResponse, error) {
	buf, err := plug.session.Send([]byte(`{"emeter":{"get_realtime":{}}}`))
	if err != nil {
		return nil, err
	}

	response := emeterResponse{}
	err = json.Unmarshal(buf, &response)
	if err != nil {
		return nil, err
	}
	return &response.Emeter.GetRealtime, nil
}
