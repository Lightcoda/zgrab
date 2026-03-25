// Package sip provides a zgrab2 module for scanning SIP (Session Initiation Protocol) servers.
//
// The module sends SIP requests (OPTIONS, REGISTER, or INVITE) to targets and parses the
// structured response, extracting security-relevant information such as:
//   - Server vendor/version from User-Agent and Server headers
//   - Supported SIP methods from the Allow header
//   - SDP media details including codec information
//   - Security features: SRTP, DTLS-SRTP, ICE support
//   - Vendor-specific headers (X-Serialnumber, etc.)
//
// Usage examples:
//
//	echo "192.168.1.1" | zgrab2 sip --port 5060 --method OPTIONS
//	echo "192.168.1.1" | zgrab2 sip --port 5060 --method OPTIONS --udp
//	echo "192.168.1.1" | zgrab2 sip --port 5061 --method REGISTER --tls --from "sip:scanner@example.com"
//	echo "192.168.1.1" | zgrab2 sip --port 5060 --method INVITE --domain example.com --user alice
//
// Example JSON output (abbreviated):
//
//	{
//	  "ip": "192.168.1.1",
//	  "data": {
//	    "sip": {
//	      "status": "success",
//	      "protocol": "sip",
//	      "result": {
//	        "response": {
//	          "status_line": { "version": "SIP/2.0", "status_code": 200, "reason": "OK" },
//	          "headers": {
//	            "user_agent": "Asterisk PBX 18.0.0",
//	            "server": "Asterisk PBX 18.0.0",
//	            "allow": "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO",
//	            "supported": "replaces, timer"
//	          },
//	          "sdp": {
//	            "connection_ip": "192.168.1.1",
//	            "media_streams": [{ "type": "audio", "port": 10000, "protocol": "RTP/AVP", ... }],
//	            "supports_srtp": false
//	          }
//	        },
//	        "transport": "udp"
//	      }
//	    }
//	  }
//	}
//
// Security analysis notes:
//   - User-Agent/Server headers reveal vendor and firmware version for CVE matching
//   - Allow header shows which methods are enabled (INVITE, REGISTER, etc.)
//   - SDP analysis reveals media encryption support (SRTP, DTLS-SRTP, ICE)
//   - X-Serialnumber and other vendor headers can fingerprint device models
//   - Responses to REGISTER may reveal authentication requirements
package sip

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/zmap/zgrab2"
)

// Flags contains the command-line flags for the SIP module.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.UDPFlags  `group:"UDP Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	// Transport selection
	UseUDP bool `long:"udp" description:"Use UDP transport (default is TCP)"`
	UseTLS bool `long:"tls" description:"Use TLS transport (SIPS). Implies TCP."`

	// SIP method(s) — comma-separated list, e.g. "OPTIONS,REGISTER,INVITE"
	Method string `long:"method" default:"OPTIONS" description:"SIP method(s), comma-separated: OPTIONS, REGISTER, INVITE (e.g. OPTIONS,REGISTER)"`

	// SIP URI/header fields
	From    string `long:"from" description:"SIP From URI (e.g. sip:scanner@example.com). Auto-generated if empty."`
	To      string `long:"to" description:"SIP To URI. Auto-generated from target if empty."`
	Contact string `long:"contact" description:"SIP Contact URI. Auto-generated if empty."`
	User    string `long:"user" default:"probe" description:"Username part for SIP URIs"`
	Domain  string `long:"domain" description:"Domain part for SIP URIs. Uses target host if empty."`

	// SDP
	NoSDP bool `long:"no-sdp" description:"Do not include SDP body in INVITE requests"`

	// Timeouts and retries for UDP
	ReadTimeout int `long:"read-timeout" default:"5000" description:"Read timeout in milliseconds"`
	MaxTries    int `long:"max-tries" default:"3" description:"Number of retries for UDP transport"`

	// Custom User-Agent
	UserAgent string `long:"user-agent" default:"zgrab2/sip" description:"User-Agent header value"`
}

// Module implements the zgrab2.ScanModule interface.
type Module struct{}

// Scanner implements the zgrab2.Scanner interface for SIP.
type Scanner struct {
	config *Flags
}

// MethodResult holds the result of a single SIP method request.
type MethodResult struct {
	Method      string       `json:"method"`
	Response    *SIPResponse `json:"response,omitempty"`
	Fingerprint *ProductInfo `json:"fingerprint,omitempty"`
	RawRequest  string       `json:"raw_request,omitempty" zgrab:"debug"`
	RawResponse string       `json:"raw_response,omitempty" zgrab:"debug"`
	Error       string       `json:"error,omitempty"`
}

// Results is the top-level result returned by the SIP scan.
type Results struct {
	// Responses holds one entry per requested method (preserves order).
	Responses []*MethodResult `json:"responses,omitempty"`
	Transport string          `json:"transport,omitempty"`
	TLSLog    *zgrab2.TLSLog  `json:"tls,omitempty"`
}

// RegisterModule is called by modules/sip.go to register the SIP scanner.
func RegisterModule() {
	var m Module
	_, err := zgrab2.AddCommand("sip", "SIP", m.Description(), 5060, &m)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a new default flags object.
func (m *Module) NewFlags() any {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (m *Module) Description() string {
	return "Send SIP requests (OPTIONS/REGISTER/INVITE) and parse structured responses for security analysis"
}

// Methods returns the list of SIP methods parsed from the comma-separated flag.
func (f *Flags) Methods() []string {
	raw := strings.Split(f.Method, ",")
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		m = strings.TrimSpace(strings.ToUpper(m))
		if m != "" {
			out = append(out, m)
		}
	}
	return out
}

// Validate checks that the flags are consistent.
func (f *Flags) Validate(args []string) error {
	methods := f.Methods()
	if len(methods) == 0 {
		return fmt.Errorf("at least one SIP method is required")
	}
	for _, m := range methods {
		switch m {
		case "OPTIONS", "REGISTER", "INVITE":
			// valid
		default:
			return fmt.Errorf("unsupported SIP method %q: must be OPTIONS, REGISTER, or INVITE", m)
		}
	}
	if f.UseTLS && f.UseUDP {
		return fmt.Errorf("--tls and --udp are mutually exclusive")
	}
	return nil
}

// Help returns module help text.
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the parsed flags.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

// InitPerSender is called once per worker goroutine.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the scanner name.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the trigger tag.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier.
func (s *Scanner) Protocol() string {
	return "sip"
}

// Scan performs the SIP scan against the target.
// When multiple methods are specified (e.g. OPTIONS,REGISTER), each is sent
// sequentially and results are collected per method.
func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	methods := s.config.Methods()

	results := &Results{}

	// Determine transport label
	if s.config.UseTLS {
		results.Transport = "tls"
	} else if s.config.UseUDP {
		results.Transport = "udp"
	} else {
		results.Transport = "tcp"
	}

	overallStatus := zgrab2.SCAN_SUCCESS
	var overallErr error

	for _, method := range methods {
		mr := &MethodResult{Method: method}

		// Build a per-method copy of flags so BuildSIPRequest uses the right method
		methodFlags := *s.config
		methodFlags.Method = method

		reqBytes, err := BuildSIPRequest(&methodFlags, target)
		if err != nil {
			mr.Error = fmt.Sprintf("building request: %v", err)
			results.Responses = append(results.Responses, mr)
			overallStatus = zgrab2.SCAN_UNKNOWN_ERROR
			overallErr = err
			continue
		}
		mr.RawRequest = string(reqBytes)

		// Send and receive
		var status zgrab2.ScanStatus
		var resp *SIPResponse
		var rawResp string

		switch results.Transport {
		case "tls":
			status, resp, rawResp, err = s.doScanTLS(target, reqBytes, results)
		case "udp":
			status, resp, rawResp, err = s.doScanUDP(target, reqBytes)
		default:
			status, resp, rawResp, err = s.doScanTCP(target, reqBytes)
		}

		mr.RawResponse = rawResp
		if err != nil {
			mr.Error = err.Error()
			if overallStatus == zgrab2.SCAN_SUCCESS {
				overallStatus = status
				overallErr = err
			}
		}
		if resp != nil {
			mr.Response = resp
			mr.Fingerprint = FingerprintSIPResponse(resp)
		}

		results.Responses = append(results.Responses, mr)
	}

	return overallStatus, results, overallErr
}

// doScanUDP sends req over UDP and returns the parsed response, raw bytes, and any error.
func (s *Scanner) doScanUDP(target zgrab2.ScanTarget, req []byte) (zgrab2.ScanStatus, *SIPResponse, string, error) {
	readTimeout := time.Duration(s.config.ReadTimeout) * time.Millisecond

	var lastErr error
	for try := 0; try < s.config.MaxTries; try++ {
		conn, err := target.OpenUDP(&s.config.BaseFlags, &s.config.UDPFlags)
		if err != nil {
			lastErr = err
			continue
		}

		conn.SetDeadline(time.Now().Add(readTimeout))

		_, err = conn.Write(req)
		if err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}

		raw := buf[:n]
		resp, parseErr := ParseSIPResponse(raw)
		if parseErr != nil {
			return zgrab2.SCAN_PROTOCOL_ERROR, nil, string(raw), parseErr
		}
		return zgrab2.SCAN_SUCCESS, resp, string(raw), nil
	}
	return zgrab2.TryGetScanStatus(lastErr), nil, "", lastErr
}

// doScanTCP sends req over TCP and returns the parsed response.
func (s *Scanner) doScanTCP(target zgrab2.ScanTarget, req []byte) (zgrab2.ScanStatus, *SIPResponse, string, error) {
	conn, err := target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, "", err
	}
	defer conn.Close()

	return s.doScanStream(conn, req)
}

// doScanTLS sends req over TLS and returns the parsed response.
// It also populates results.TLSLog on successful handshake.
func (s *Scanner) doScanTLS(target zgrab2.ScanTarget, req []byte, results *Results) (zgrab2.ScanStatus, *SIPResponse, string, error) {
	conn, err := target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, "", err
	}

	tlsConn, err := s.config.TLSFlags.GetTLSConnectionForTarget(conn, &target)
	if err != nil {
		conn.Close()
		return zgrab2.TryGetScanStatus(err), nil, "", err
	}
	if err = tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return zgrab2.TryGetScanStatus(err), nil, "", err
	}
	results.TLSLog = tlsConn.GetLog()

	status, resp, rawResp, scanErr := s.doScanStream(tlsConn, req)
	tlsConn.Close()
	return status, resp, rawResp, scanErr
}

// doScanStream performs the write/read cycle on a stream (TCP or TLS) connection.
func (s *Scanner) doScanStream(conn net.Conn, req []byte) (zgrab2.ScanStatus, *SIPResponse, string, error) {
	readTimeout := time.Duration(s.config.ReadTimeout) * time.Millisecond

	_, err := conn.Write(req)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, "", err
	}

	data, err := zgrab2.ReadAvailableWithOptions(conn, 8209, readTimeout, 0, 65535)
	if err != nil && err != io.EOF {
		if len(data) == 0 {
			return zgrab2.TryGetScanStatus(err), nil, "", err
		}
	}

	if len(data) == 0 {
		return zgrab2.SCAN_IO_TIMEOUT, nil, "", fmt.Errorf("no response received")
	}

	rawStr := string(data)
	resp, parseErr := ParseSIPResponse(data)
	if parseErr != nil {
		return zgrab2.SCAN_PROTOCOL_ERROR, nil, rawStr, parseErr
	}
	return zgrab2.SCAN_SUCCESS, resp, rawStr, nil
}
