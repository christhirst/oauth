package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

func renderJSON(w http.ResponseWriter, v interface{}, statusCode int) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("failed to encode object to json: %v", err)
	}
	return nil
}

// renderJSON marshals 'v' to JSON, automatically escaping HTML, setting the
// Content-Type as application/json, and sending the status code header.
func renderJSON2(w http.ResponseWriter, v interface{}, statusCode int) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal object to json")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	_, err = w.Write(b)
	if err != nil {
		log.Error().Err(err).Msg("render json failed")
	}
}
