package sip

import (
	"regexp"
	"strings"
)

// ProductInfo holds the result of fingerprinting a SIP server.
type ProductInfo struct {
	Product     string `json:"product"`
	Version     string `json:"version,omitempty"`
	FullName    string `json:"fullname,omitempty"`
	CPE         string `json:"possible CPEs,omitempty"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
}

// fingerprint defines a single product signature.
type fingerprint struct {
	product     string
	fullname    string
	description string
	possiblevendors []string
	cpe         string // CPE template, use {version} as placeholder
	category    string
	// headerPatterns maps lowercase header name → compiled regex.
	// Named group "version" captures the version string.
	headerPatterns map[string]*regexp.Regexp
}

// fingerprintDB is the database of known SIP products.
// Patterns are matched against Server, User-Agent, and other headers.
var fingerprintDB = buildFingerprintDB()

func buildFingerprintDB() []fingerprint {
	return []fingerprint{
		//
		// ===== PBX / Soft-switch =====
		{
			product:     "asterisk",
			fullname:    "Asterisk PBX",
			description: "Asterisk is an open-source PBX and telephony toolkit.",
			cpe:         "cpe:2.3:a:{vendor}:asterisk:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"digium", "sangoma"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)Asterisk[\s/]*(?:PBX[\s/]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)Asterisk[\s/]*(?:PBX[\s/]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "freeswitch",
			fullname:    "FreeSWITCH",
			description: "FreeSWITCH is a free and open-source communications platform.",
			cpe:         "cpe:2.3:a:{vendor}:freeswitch:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"freeswitch"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)FreeSWITCH[\s/~-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)FreeSWITCH[\s/~-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "opensips",
			fullname:    "OpenSIPS",
			description: "OpenSIPS is an open-source SIP server/proxy for voice, video, and IM.",
			cpe:         "cpe:2.3:a:{vendor}:opensips:{version}:*:*:*:*:*:*:*",
			category:    "SIP Proxy",
			possiblevendors: []string{"opensips"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)OpenSIPS[\s/(]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)OpenSIPS[\s/(]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "kamailio",
			fullname:    "Kamailio SIP Server",
			description: "Kamailio is an open-source SIP server (proxy, registrar, redirect, etc.).",
			cpe:         "cpe:2.3:a:{vendor}:kamailio:{version}:*:*:*:*:*:*:*",
			category:    "SIP Proxy",
			possiblevendors: []string{"kamailio"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)Kamailio[\s/(]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)Kamailio[\s/(]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "3cx",
			fullname:    "3CX Phone System",
			description: "3CX is a software-based PBX for VoIP communications.",
			cpe:         "cpe:2.3:a:{vendor}:3cx:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"3cx"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)3CX[\s/]*(?:Phone[\s]*System[\s/]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)3CX[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "freepbx",
			fullname:    "FreePBX",
			description: "FreePBX is a web-based open-source GUI that manages Asterisk.",
			cpe:         "cpe:2.3:a:{vendor}:freepbx:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"sangoma"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)(f(?:ree)?PBX)[\s/-]*((?P<version>[\d]+(?:\.[\d]+)*)\([\d]+(?:\.[\d]+)*\))?`),
				"user-agent": regexp.MustCompile(`(?i)(f(?:ree)?PBX)[\s/-]*((?P<version>[\d]+(?:\.[\d]+)*)\([\d]+(?:\.[\d]+)*\))?`),
			},
		},
		// ===== VoIP Platforms =====
		{
			product:     "avaya",
			fullname:    "Avaya Aura Communication Manager",
			description: "Avaya Aura is a unified communications platform.",
			cpe:         "cpe:2.3:a:{vendor}:aura_communication_manager:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"avaya"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)Avaya[\s/-]*(?:Aura[\s/-]*)?(?:CM[\s/-]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)Avaya[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "cisco_unified_cm",
			fullname:    "Cisco Unified Communications Manager",
			description: "Cisco Unified CM is an enterprise IP telephony call-processing system.",
			cpe:         "cpe:2.3:a:{vendor}:unified_communications_manager:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"cisco"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)Cisco[\s/-]*(?:Unified[\s]*(?:CM|Communications[\s]*Manager)?)[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)Cisco[\s/-]*(?:Unified[\s]*(?:CM|Communications))[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},

		// ===== SIP Proxies =====
		{
			product:     "opal",
			fullname:    "OPAL SIP",
			description: "OPAL is an open-source C++ library for SIP/H.323 communications.",
			cpe:         "cpe:2.3:a:{vendor}:opal:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Library",
			possiblevendors: []string{"opalvoip"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)OPAL[\s/]*(?:SIP[\s/]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "ser",
			fullname:    "SIP Express Router",
			description: "SER (SIP Express Router) is a high-performance SIP server.",
			cpe:         "cpe:2.3:a:{vendor}:ser:{version}:*:*:*:*:*:*:*",
			category:    "SIP Proxy",
			possiblevendors: []string{"iptel"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)(?:^|\b)(?:SIP[\s]*Express[\s]*Router|SER)[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)(?:^|\b)(?:SIP[\s]*Express[\s]*Router|SER)[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "repro",
			fullname:    "reSIProcate repro",
			description: "repro is an open-source SIP proxy from the reSIProcate project.",
			cpe:         "cpe:2.3:a:{vendor}:repro:{version}:*:*:*:*:*:*:*",
			category:    "SIP Proxy",
			possiblevendors: []string{"resiprocate"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)repro[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)repro[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},

		// ===== VoIP Phones / Endpoints =====
		{
			product:     "polycom",
			fullname:    "Polycom VoIP Phone",
			description: "Polycom phones are enterprise VoIP endpoints.",
			cpe:         "cpe:2.3:h:{vendor}:soundpoint_ip:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Phone",
			possiblevendors: []string{"polycom"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)Polycom[\s/-]*(?:SoundPoint|SoundStation|VVX|SPIP|RealPresence)?[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"server":     regexp.MustCompile(`(?i)Polycom[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "yealink",
			fullname:    "Yealink VoIP Phone",
			description: "Yealink phones are enterprise VoIP endpoints.",
			cpe:         "cpe:2.3:h:{vendor}:sip_phone:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Phone",
			possiblevendors: []string{"yealink"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)Yealink[\s/-]*(?:SIP[\s-]*)?(?:T\d+\w*[\s/-]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "grandstream",
			fullname:    "Grandstream VoIP Device",
			description: "Grandstream produces VoIP phones and gateways.",
			cpe:         "cpe:2.3:h:{vendor}:gxp:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Phone",
			possiblevendors: []string{"grandstream"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)Grandstream[\s/-]*(?:GXP|GRP|GXV|HT|DP)?[\s/-]*\d*[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "snom",
			fullname:    "Snom VoIP Phone",
			description: "Snom produces enterprise VoIP phones.",
			cpe:         "cpe:2.3:h:{vendor}:snom_phone:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Phone",
			possiblevendors: []string{"snom"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)(?:^|\b)snom[\s/-]*(?:\d+[\s/-]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "cisco_sip_phone",
			fullname:    "Cisco SIP Phone",
			description: "Cisco IP phones with SIP firmware.",
			cpe:         "cpe:2.3:h:{vendor}:ip_phone:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Phone",
			possiblevendors: []string{"cisco"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)Cisco[\s/-]*(?:SIP[\s/-]*)?(?:IP[\s/-]*)?(?:Phone|CP-)[\s/-]*(?:\w+[\s/-]*)?(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "linphone",
			fullname:    "Opal",
			description: "Opal is a free and open-source SIP client.",
			cpe:         "cpe:2.3:a:{vendor}:opal:{version}:*:*:*:*:*:*:*",
			category:    "Opal",
			possiblevendors: []string{"opal"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)Opal[\s/-]*(?:Desktop|Android|iPhone)?[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},

		// ===== VoIP Gateways / SBC =====
		{
			product:     "audiocodes",
			fullname:    "AudioCodes SBC/Gateway",
			description: "AudioCodes produces session border controllers and media gateways.",
			cpe:         "cpe:2.3:h:{vendor}:mediant:{version}:*:*:*:*:*:*:*",
			category:    "SBC/Gateway",
			possiblevendors: []string{"audiocodes"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)AudioCodes[\s/-]*(?:Mediant)?[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)AudioCodes[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "sonus",
			fullname:    "Sonus/Ribbon SBC",
			description: "Sonus (now Ribbon) session border controllers.",
			cpe:         "cpe:2.3:a:{vendor}:sbc:{version}:*:*:*:*:*:*:*",
			category:    "SBC/Gateway",
			possiblevendors: []string{"ribbon"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)(?:Sonus|Ribbon)[\s/-]*(?:SBC)?[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)(?:Sonus|Ribbon)[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},

		// ===== Opal Software =====
		{
			product:     "microsip",
			fullname:    "MicroSIP",
			description: "MicroSIP is a lightweight open-source SIP softphone for Windows.",
			cpe:         "cpe:2.3:a:{vendor}:microsip:{version}:*:*:*:*:*:*:*",
			category:    "Opal",
			possiblevendors: []string{"microsip"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)MicroSIP[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "pjsip",
			fullname:    "PJSIP",
			description: "PJSIP is an open-source SIP library used by many VoIP applications.",
			cpe:         "cpe:2.3:a:{vendor}:pjsip:{version}:*:*:*:*:*:*:*",
			category:    "VoIP Library",
			possiblevendors: []string{"pjsip"},
			headerPatterns: map[string]*regexp.Regexp{
				"user-agent": regexp.MustCompile(`(?i)(?:^|\b)PJ[\s-]*SIP[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "twilio",
			fullname:    "Twilio",
			description: "Twilio is a cloud communications platform providing SIP trunking.",
			cpe:         "cpe:2.3:a:{vendor}:twilio:{version}:*:*:*:*:*:*:*",
			category:    "Cloud Platform",
			possiblevendors: []string{"twilio"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)Twilio[\s/]*(?P<version>[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)Twilio[\s/]*(?P<version>[\d]+[\d.]*)?`),
			},
		},

		// ===== Other / Generic =====
		{
			product:     "miniSIPServer",
			fullname:    "miniSIPServer",
			description: "miniSIPServer is a lightweight SIP server.",
			cpe:         "cpe:2.3:a:{vendor}:minisipserver:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"myvoipapp"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)miniSIPServer[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)miniSIPServer[\s/]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
		{
			product:     "mitel",
			fullname:    "Mitel MiVoice",
			description: "Mitel MiVoice is an enterprise communications platform.",
			cpe:         "cpe:2.3:a:{vendor}:mivoice:{version}:*:*:*:*:*:*:*",
			category:    "PBX",
			possiblevendors: []string{"mitel"},
			headerPatterns: map[string]*regexp.Regexp{
				"server":     regexp.MustCompile(`(?i)Mitel[\s/-]*(?:MiVoice)?[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
				"user-agent": regexp.MustCompile(`(?i)Mitel[\s/-]*(?P<version>[\d]+\.[\d]+[\d.]*)?`),
			},
		},
	}
}

// FingerprintSIPResponse attempts to identify the product and version from SIP response headers.
// It checks Server and User-Agent headers against the fingerprint database.
// Returns nil if no match is found.
func FingerprintSIPResponse(resp *SIPResponse) *ProductInfo {
	if resp == nil || resp.Headers == nil {
		return nil
	}

	// Headers to check, in priority order
	headersToCheck := map[string]string{
		"server":     resp.Headers.Server,
		"user-agent": resp.Headers.UserAgent,
	}

	for _, fp := range fingerprintDB {
		for headerName, pattern := range fp.headerPatterns {
			headerValue, ok := headersToCheck[headerName]
			if !ok || headerValue == "" {
				continue
			}

			match := pattern.FindStringSubmatch(headerValue)
			if match == nil {
				continue
			}

			// Extract version from named group
			version := ""
			for i, name := range pattern.SubexpNames() {
				if name == "version" && i < len(match) && match[i] != "" {
					version = match[i]
					break
				}
			}

			info := &ProductInfo{
				Product:     fp.product,
				FullName:    fp.fullname,
				Description: fp.description,
				Category:    fp.category,
				Version:     version,
			}
			
			// Build CPE with version
			if fp.cpe != "" {
				info.CPE = ""
				var temp string
				if version != "" {
					temp = strings.Replace(fp.cpe, "{version}", version, 1)
				} else {
					temp = strings.Replace(fp.cpe, "{version}", "*", 1)
				}
				
				for _, vend := range fp.possiblevendors{
					info.CPE+=strings.Replace(temp, "{vendor}", vend, 1)
					info.CPE+=" "
				}
			}
			return info
		}
	}

	return nil
}
