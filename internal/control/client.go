package control

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Do sends one request to the daemon at socket path and returns its response.
func Do(path string, req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("cannot reach phaged at %s: %w", path, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
