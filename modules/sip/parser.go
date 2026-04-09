package sip

import (
	"fmt"
	"strconv"
	"strings"
)

// SIPResponse represents a parsed SIP response message.
type SIPResponse struct {
	StatusLine *StatusLine      `json:"status_line"`
	Headers    *SIPHeaders      `json:"headers"`
	SDP        *SDPInfo         `json:"sdp,omitempty"`
	RawHeaders map[string][]string `json:"raw_headers,omitempty" zgrab:"debug"`
}

// StatusLine represents the first line of a SIP response: SIP/2.0 200 OK
type StatusLine struct {
	Version    string `json:"version"`
	StatusCode int    `json:"status_code"`
	Reason     string `json:"reason"`
}

// SIPHeaders contains the most important SIP headers as typed fields.
type SIPHeaders struct {
	From          string   `json:"from,omitempty"`
	To            string   `json:"to,omitempty"`
	CallID        string   `json:"call_id,omitempty"`
	CSeq          string   `json:"cseq,omitempty"`
	Via           []string `json:"via,omitempty"`
	Allow         []string   `json:"allow,omitempty"`
	Supported     []string   `json:"supported,omitempty"`
	UserAgent     string   `json:"user_agent,omitempty"`
	Server        string   `json:"server,omitempty"`
	XSerialNumber string   `json:"x_serialnumber,omitempty"`
	Accept        string   `json:"accept,omitempty"`
	AcceptContact string   `json:"accept_contact,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentLength int      `json:"content_length"`
	Contact       string   `json:"contact,omitempty"`
	WWWAuthenticate string `json:"www_authenticate,omitempty"`

	// Vendor-specific extension headers collected as a map
	XHeaders map[string]string `json:"x_headers,omitempty"`
}

// SDPInfo contains parsed SDP (Session Description Protocol) data.
type SDPInfo struct {
	Version      string         `json:"version,omitempty"`
	Origin       string         `json:"origin,omitempty"`
	SessionName  string         `json:"session_name,omitempty"`
	ConnectionIP string         `json:"connection_ip,omitempty"`
	MediaStreams  []*MediaStream `json:"media_streams,omitempty"`

	// Security indicators
	SupportsSRTP     bool `json:"supports_srtp"`
	SupportsDTLSSRTP bool `json:"supports_dtls_srtp"`
	SupportsICE      bool `json:"supports_ice"`
}

// MediaStream represents an SDP media line (m=) and its attributes.
type MediaStream struct {
	Type     string   `json:"type"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Formats  []string `json:"formats,omitempty"`
	Codecs   []*Codec `json:"codecs,omitempty"`

	// Per-stream attributes
	Direction    string            `json:"direction,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
	ICEUfrag     string            `json:"ice_ufrag,omitempty"`
	ICEPwd       string            `json:"ice_pwd,omitempty"`
	Fingerprint  string            `json:"fingerprint,omitempty"`
	Setup        string            `json:"setup,omitempty"`
}

// Codec represents a single codec from a=rtpmap and a=fmtp lines.
type Codec struct {
	PayloadType int    `json:"payload_type"`
	Name        string `json:"name"`
	ClockRate   int    `json:"clock_rate,omitempty"`
	Params      string `json:"params,omitempty"`
	Fmtp        string `json:"fmtp,omitempty"`
}

// ParseSIPResponse parses a raw SIP response into a structured SIPResponse.
func ParseSIPResponse(data []byte) (*SIPResponse, error) {
	raw := string(data)
	// Split headers and body by double CRLF
	headerBody := strings.SplitN(raw, "\r\n\r\n", 2)
	if len(headerBody) == 0 || len(headerBody[0]) == 0 {
		return nil, fmt.Errorf("empty SIP response")
	}

	headerSection := headerBody[0]
	var body string
	if len(headerBody) > 1 {
		body = headerBody[1]
	}

	// Parse status line
	lines := strings.SplitN(headerSection, "\r\n", 2)
	statusLine, err := parseStatusLine(lines[0])
	if err != nil {
		return nil, err
	}

	// Parse headers
	var headerLines string
	if len(lines) > 1 {
		headerLines = lines[1]
	}
	rawHeaders := parseRawHeaders(headerLines)
	headers := extractHeaders(rawHeaders)

	resp := &SIPResponse{
		StatusLine: statusLine,
		Headers:    headers,
		RawHeaders: rawHeaders,
	}

	// Parse SDP if present
	if strings.Contains(strings.ToLower(headers.ContentType), "application/sdp") && body != "" {
		resp.SDP = parseSDP(body)
	}

	return resp, nil
}

func parseStatusLine(line string) (*StatusLine, error) {
	// Expected format: SIP/2.0 200 OK
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SIP status line: %q", line)
	}

	version := parts[0]
	if !strings.HasPrefix(version, "SIP/") {
		return nil, fmt.Errorf("not a SIP response: %q", line)
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code in %q: %w", line, err)
	}

	reason := ""
	if len(parts) > 2 {
		reason = parts[2]
	}

	return &StatusLine{
		Version:    version,
		StatusCode: code,
		Reason:     reason,
	}, nil
}

func parseRawHeaders(headerSection string) map[string][]string {
	headers := make(map[string][]string)
	if headerSection == "" {
		return headers
	}

	// Handle header line folding (continuation lines starting with space/tab)
	var unfolded []string
	for _, line := range strings.Split(headerSection, "\r\n") {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Continuation of previous header
			if len(unfolded) > 0 {
				unfolded[len(unfolded)-1] += " " + strings.TrimSpace(line)
			}
		} else {
			unfolded = append(unfolded, line)
		}
	}

	for _, line := range unfolded {
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		// Normalize header name to lowercase for consistent lookup
		key := strings.ToLower(name)
		headers[key] = append(headers[key], value)
	}
	return headers
}

func extractHeaders(raw map[string][]string) *SIPHeaders {
	h := &SIPHeaders{
		XHeaders: make(map[string]string),
	}

	getFirst := func(key string) string {
		if vals, ok := raw[key]; ok && len(vals) > 0 {
			return vals[0]
		}
		return ""
	}

	h.From = getFirst("from")
	h.To = getFirst("to")
	h.CallID = getFirst("call-id")
	h.CSeq = getFirst("cseq")
	h.Via = raw["via"]
	h.Allow = strings.Split(getFirst("allow"), ", ")
	h.Supported = strings.Split(getFirst("supported"), ", ")
	h.UserAgent = getFirst("user-agent")
	h.Server = getFirst("server")
	h.Accept = getFirst("accept")
	h.AcceptContact = getFirst("accept-contact")
	h.ContentType = getFirst("content-type")
	h.Contact = getFirst("contact")
	h.WWWAuthenticate = getFirst("www-authenticate")
	h.XSerialNumber = getFirst("x-serialnumber")

	if cl := getFirst("content-length"); cl != "" {
		h.ContentLength, _ = strconv.Atoi(cl)
	}

	// Collect all X- and P- vendor extension headers
	for key, vals := range raw {
		if (strings.HasPrefix(key, "x-") || strings.HasPrefix(key, "p-")) && key != "x-serialnumber" {
			h.XHeaders[key] = vals[0]
		}
	}
	if len(h.XHeaders) == 0 {
		h.XHeaders = nil
	}

	return h
}

func parseSDP(body string) *SDPInfo {
	sdp := &SDPInfo{}

	lines := strings.Split(body, "\r\n")
	if len(lines) <= 1 {
		// Try LF-only line endings
		lines = strings.Split(body, "\n")
	}

	var currentStream *MediaStream

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		field := line[0]
		value := line[2:]

		switch field {
		case 'v':
			sdp.Version = value
		case 'o':
			sdp.Origin = value
		case 's':
			sdp.SessionName = value
		case 'c':
			// c=IN IP4 192.168.1.1
			sdp.ConnectionIP = parseConnectionIP(value)
		case 'm':
			currentStream = parseMediaLine(value)
			if currentStream != nil {
				sdp.MediaStreams = append(sdp.MediaStreams, currentStream)
				// Check for SRTP in media protocol
				proto := strings.ToUpper(currentStream.Protocol)
				if strings.Contains(proto, "SAVP") || strings.Contains(proto, "SAVPF") {
					sdp.SupportsSRTP = true
				}
			}
		case 'a':
			parseAttribute(sdp, currentStream, value)
		}
	}

	return sdp
}

func parseConnectionIP(value string) string {
	// c=IN IP4 192.168.1.1
	parts := strings.Fields(value)
	if len(parts) >= 3 {
		return parts[2]
	}
	return value
}

func parseMediaLine(value string) *MediaStream {
	// m=audio 49170 RTP/AVP 0 8 101
	parts := strings.Fields(value)
	if len(parts) < 3 {
		return nil
	}

	port, _ := strconv.Atoi(parts[1])
	stream := &MediaStream{
		Type:       parts[0],
		Port:       port,
		Protocol:   parts[2],
		Attributes: make(map[string]string),
	}

	if len(parts) > 3 {
		stream.Formats = parts[3:]
	}

	return stream
}

func parseAttribute(sdp *SDPInfo, stream *MediaStream, value string) {
	parts := strings.SplitN(value, ":", 2)
	attrName := parts[0]
	attrValue := ""
	if len(parts) > 1 {
		attrValue = parts[1]
	}

	switch attrName {
	case "rtpmap":
		if stream != nil {
			codec := parseRtpmap(attrValue)
			if codec != nil {
				stream.Codecs = append(stream.Codecs, codec)
			}
		}
	case "fmtp":
		if stream != nil {
			applyFmtp(stream, attrValue)
		}
	case "sendrecv", "sendonly", "recvonly", "inactive":
		if stream != nil {
			stream.Direction = attrName
		}
	case "ice-ufrag":
		sdp.SupportsICE = true
		if stream != nil {
			stream.ICEUfrag = attrValue
		}
	case "ice-pwd":
		sdp.SupportsICE = true
		if stream != nil {
			stream.ICEPwd = attrValue
		}
	case "fingerprint":
		sdp.SupportsDTLSSRTP = true
		if stream != nil {
			stream.Fingerprint = attrValue
		}
	case "setup":
		if stream != nil {
			stream.Setup = attrValue
		}
	default:
		if stream != nil {
			stream.Attributes[attrName] = attrValue
		}
	}
}

func parseRtpmap(value string) *Codec {
	// rtpmap:0 PCMU/8000
	parts := strings.SplitN(value, " ", 2)
	if len(parts) < 2 {
		return nil
	}

	pt, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil
	}

	codec := &Codec{PayloadType: pt}

	nameRate := strings.SplitN(parts[1], "/", 3)
	codec.Name = nameRate[0]
	if len(nameRate) > 1 {
		codec.ClockRate, _ = strconv.Atoi(nameRate[1])
	}
	if len(nameRate) > 2 {
		codec.Params = nameRate[2]
	}

	return codec
}

func applyFmtp(stream *MediaStream, value string) {
	// fmtp:101 0-16
	parts := strings.SplitN(value, " ", 2)
	if len(parts) < 2 {
		return
	}

	pt, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return
	}

	for _, codec := range stream.Codecs {
		if codec.PayloadType == pt {
			codec.Fmtp = parts[1]
			return
		}
	}
}
