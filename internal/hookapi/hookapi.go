package hookapi

import (
	"encoding/json"
	"net"
	"time"
)

const (
	EventConnect    = "connect"
	EventDisconnect = "disconnect"
)

type Request struct {
	Event    string `json:"event"`
	CN       string `json:"cn"`
	Instance string `json:"instance"`
}

type Response struct {
	Allow bool     `json:"allow"`
	Push  []string `json:"push,omitempty"`
}

func Ask(socket string, req Request, timeout time.Duration) (Response, error) {
	conn, err := net.DialTimeout("unix", socket, timeout)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
