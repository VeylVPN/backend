package store

import "strings"

func (s *Store) AddDeviceNamed(key string, d Device, pick func(taken map[string]bool) string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Device{}, err
	}
	a := s.find(key)
	if a == nil {
		return Device{}, ErrBadCredentials
	}
	if err := a.Active(s.now().Unix()); err != nil {
		return Device{}, err
	}
	if len(a.Devices) >= a.EffectiveLimit(s.limit) {
		return Device{}, ErrDeviceLimit
	}
	if d.Name == "" {
		taken := map[string]bool{}
		for _, x := range a.Devices {
			taken[strings.ToLower(x.Name)] = true
		}
		n, err := CleanName(pick(taken))
		if err != nil {
			return Device{}, err
		}
		d.Name = n
	}
	d.Created = Day(d.Created)
	if d.Created == 0 {
		d.Created = s.today()
	}
	a.Devices = append(a.Devices, d)
	return d, s.save()
}

func (s *Store) RenameDevice(key, id, name string) (Device, error) {
	n, err := CleanName(name)
	if err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return Device{}, err
	}
	a := s.find(key)
	if a == nil {
		return Device{}, ErrNoAccount
	}
	for i := range a.Devices {
		if a.Devices[i].ID == id {
			a.Devices[i].Name = n
			return a.Devices[i], s.save()
		}
	}
	return Device{}, ErrNoDevice
}
