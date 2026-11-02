package control

import (
	"context"
	"encoding/json"
	"net"
	"os"
)

// Handler is implemented by the daemon to answer control requests.
type Handler interface {
	Status() Status
	RecentAlerts(n int) []Alert
	Thaw(pid int32) error
}

// Server accepts CLI connections on a Unix socket and dispatches to a Handler.
type Server struct {
	ln net.Listener
}

// Serve starts a control server on the Unix socket at path. An empty path
// disables the server (returns nil, nil). The server stops when ctx is done.
func Serve(ctx context.Context, path string, h Handler) (*Server, error) {
	if path == "" {
		return nil, nil
	}
	_ = os.Remove(path) // clear a stale socket from a previous run
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)

	s := &Server{ln: ln}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go s.accept(h)
	return s, nil
}

func (s *Server) accept(h Handler) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go serveConn(conn, h)
	}
}

func serveConn(conn net.Conn, h Handler) {
	defer conn.Close()
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResp(conn, Response{OK: false, Error: "bad request"})
		return
	}
	writeResp(conn, dispatch(req, h))
}

func dispatch(req Request, h Handler) Response {
	switch req.Cmd {
	case "status":
		st := h.Status()
		return Response{OK: true, Status: &st}
	case "events":
		n := req.N
		if n <= 0 {
			n = 20
		}
		return Response{OK: true, Alerts: h.RecentAlerts(n)}
	case "thaw":
		if err := h.Thaw(req.PID); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Message: "thawed and released"}
	default:
		return Response{OK: false, Error: "unknown command: " + req.Cmd}
	}
}

// Close stops the server and removes the socket.
func (s *Server) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

func writeResp(conn net.Conn, r Response) {
	_ = json.NewEncoder(conn).Encode(r)
}
