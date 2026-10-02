package ovpn

import "errors"

var ErrNoInstance = errors.New("no openvpn instance reachable")

type Multi struct {
	Clients []*Client
}

func (m *Multi) Online() (map[string]bool, error) {
	out := map[string]bool{}
	ok := false
	for _, c := range m.Clients {
		on, err := c.Online()
		if err != nil {
			continue
		}
		ok = true
		for cn := range on {
			out[cn] = true
		}
	}
	if !ok {
		return nil, ErrNoInstance
	}
	return out, nil
}

func (m *Multi) Kill(cn string) error {
	if !validName(cn) {
		return ErrBadName
	}
	var last error = ErrNoInstance
	killed := false
	for _, c := range m.Clients {
		if err := c.Kill(cn); err != nil {
			last = err
			continue
		}
		killed = true
	}
	if killed {
		return nil
	}
	return last
}
