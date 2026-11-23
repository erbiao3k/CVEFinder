package store

import (
	"encoding/json"
	"os"
	"time"
)

type State struct {
	Cursor   time.Time         `json:"cursor"`
	Notified map[string]string `json:"notified"`
}

type StateFile struct {
	path string
}

func OpenState(path string) *StateFile {
	return &StateFile{path: path}
}

func (s *StateFile) Load() (State, error) {
	body, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{Notified: map[string]string{}}, nil
		}
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(body, &st); err != nil {
		return State{}, err
	}
	if st.Notified == nil {
		st.Notified = map[string]string{}
	}
	return st, nil
}

func (s *StateFile) Save(st State) error {
	if st.Notified == nil {
		st.Notified = map[string]string{}
	}
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		if werr := os.WriteFile(s.path, body, 0o600); werr != nil {
			return err
		}
		_ = os.Remove(tmp)
	}
	return nil
}

func Prune(st *State, now time.Time) {
	cutoff := now.Add(-90 * 24 * time.Hour)
	for id, raw := range st.Notified {
		notifiedAt, err := time.Parse(time.RFC3339, raw)
		if err != nil || notifiedAt.Before(cutoff) {
			delete(st.Notified, id)
		}
	}
}
