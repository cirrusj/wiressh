package recorder

import (
	"encoding/json"
	"os"
	"time"
)

// AsciicastHeader represents the header of an asciicast v2 file
type AsciicastHeader struct {
	Version   int    `json:"version"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Title     string `json:"title,omitempty"`
	Env       struct {
		Term string `json:"TERM"`
	} `json:"env"`
}

// AsciicastEvent represents a single event in an asciicast v2 file
type AsciicastEvent struct {
	Time float64 `json:"time"`
	Type string  `json:"type"`
	Data string  `json:"data"`
}

// Recorder handles recording terminal sessions in asciicast v2 format
type Recorder struct {
	file   *os.File
	start  time.Time
	width  int
	height int
	term   string
	title  string
}

// NewRecorder creates a new recorder that writes to the specified file
func NewRecorder(filename string, width, height int, term, title string) (*Recorder, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	header := AsciicastHeader{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: time.Now().Unix(),
		Title:     title,
	}
	header.Env.Term = term

	headerJSON, err := json.Marshal(header)
	if err != nil {
		file.Close()
		return nil, err
	}

	_, err = file.Write(headerJSON)
	if err != nil {
		file.Close()
		return nil, err
	}

	_, err = file.WriteString("\n")
	if err != nil {
		file.Close()
		return nil, err
	}

	return &Recorder{
		file:   file,
		start:  time.Now(),
		width:  width,
		height: height,
		term:   term,
		title:  title,
	}, nil
}

// WriteOutput records terminal output
func (r *Recorder) WriteOutput(data []byte) error {
	event := []interface{}{
		time.Since(r.start).Seconds(),
		"o",
		string(data),
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = r.file.Write(eventJSON)
	if err != nil {
		return err
	}

	_, err = r.file.WriteString("\n")
	return err
}

// WriteInput records terminal input
func (r *Recorder) WriteInput(data []byte) error {
	event := []interface{}{
		time.Since(r.start).Seconds(),
		"i",
		string(data),
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	_, err = r.file.Write(eventJSON)
	if err != nil {
		return err
	}

	_, err = r.file.WriteString("\n")
	return err
}

// Close closes the recorder and its underlying file
func (r *Recorder) Close() error {
	return r.file.Close()
}
