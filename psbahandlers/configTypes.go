package psbahandlers

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/handlerfunctions"
	"github.com/francistor/igor/instrumentation"
	"github.com/francistor/igor/radiuscodec"
)

type CDRDirectory struct {
	Path            string
	FilenamePattern string
	CheckerName     string
}

type AccountingCopyTarget struct {
	// Only for logging purposes
	TargetName string

	// The name of the radius group where to send the copies
	RadiusGroupName string

	// Checker name to use to select what packets are copied
	CheckerName string

	// AVP Filter to use
	FilterName string
}

type HandlerConfig struct {
	// CDR Writing
	// Directories where the Session CDR should be written
	SessionCDRDirectories []CDRDirectory
	// Directories where the Service CDR should be written
	ServiceCDRDirectories []CDRDirectory
	WriteSessionCDR       bool
	WriteServiceCDR       bool
	CdrFilenamePattern    string

	// Accounting Copy
	SessionAccountingCopyTargets []AccountingCopyTarget
	ServiceAccountingCopyTargets []AccountingCopyTarget

	// Inline proxy
	ProxyGroupName         string
	AcceptOnProxyError     bool
	ProxySessionAccounting bool
	ProxyServiceAccounting bool

	// Normally overriden in a per-domain basis
	ProxyTimeoutMillis int
	ProxyRetries       int
	AuthProxyFilterOut string
	AuthProxyFilterIn  string
	AcctProxyFilterOut string

	// May be "database", "file" or "radius". In this case, a "ProxyGroupName" must be configured
	ProvisionType string
	// Whether to validate the credentials locally, irrespective of whether a proxy is performed. May be "provision" or "file"
	AuthLocal string

	// Whether to send Access-Reject to users not provisioned or with bad credentials
	UseRejectService  bool
	RejectServiceName string
	// The reject service may replace the basic service or be configured as an addon service
	RejectIsAddon bool

	// Whether to send Access-Reject to blocked user
	BlockingWithService bool
	BlockingServiceName string
	BlockingIsAddon     bool

	// Global Radius attributes to send
	RadiusAttrs               []radiuscodec.RadiusAVP
	NonOverridableRadiusAttrs []radiuscodec.RadiusAVP
}

// Stringer iterface
func (g HandlerConfig) String() string {
	var jBytes bytes.Buffer
	enc := json.NewEncoder(&jBytes)
	enc.SetIndent("", "    ")
	if err := enc.Encode(g); err != nil {
		return "<error>"
	}
	return jBytes.String()
}

// Overrides the configuration properties with other taken from userfile config items
func (g HandlerConfig) OverrideWith(props handlerfunctions.Properties, logLines *instrumentation.LogLines) HandlerConfig {
	for key := range props {
		lowerKey := strings.ToLower(key)

		switch lowerKey {
		case "writesessioncdr":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.WriteSessionCDR = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for WriteSessionCDR %s %s", props[key], err)
			}
		case "writeservicecdr":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.WriteServiceCDR = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for WriteServiceCDR %s", props[key])
			}
		case "proxygroupname":
			g.ProxyGroupName = props[key]
		case "acceptonproxyerror":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.AcceptOnProxyError = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for AcceptOnProxyError %s", props[key])
			}
		case "proxysessionaccounting":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.ProxySessionAccounting = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for ProxySessionAccounting %s", props[key])
			}
		case "proxyserviceaccounting":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.ProxyServiceAccounting = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for ProxyServiceAccounting %s", props[key])
			}
		case "proxytimeoutmillis":
			if v, err := strconv.ParseInt(props[key], 10, 32); err == nil {
				g.ProxyTimeoutMillis = int(v)
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for ProxyTimeoutMillis %s", props[key])
			}
		case "proxyretries":
			if v, err := strconv.ParseInt(props[key], 10, 32); err == nil {
				g.ProxyRetries = int(v)
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for ProxyRetries %s", props[key])
			}
		case "authproxyfilterout":
			g.AuthProxyFilterOut = props[key]
		case "authproxyfilterin":
			g.AuthProxyFilterIn = props[key]
		case "acctproxyfilterout":
			g.AcctProxyFilterOut = props[key]
		case "provisiontype":
			g.ProvisionType = props[key]
		case "authlocal":
			g.AuthLocal = props[key]
		case "userejectservice":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.UseRejectService = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for UseRejectService %s", props[key])
			}
		case "rejectisaddon":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.RejectIsAddon = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for RejectIsAddon %s", props[key])
			}
		case "rejectservicename":
			g.RejectServiceName = props[key]
		case "blockingwithservice":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.BlockingWithService = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for BlockingWithService %s", props[key])
			}
		case "blockingisaddon":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.BlockingIsAddon = v
			} else {
				logLines.WLogEntry(config.LEVEL_ERROR, "bad format for BlockingIsAddon %s", props[key])
			}
		case "blockingservicename":
			g.BlockingServiceName = props[key]
		}
	}

	return g
}

type DatabaseConfig struct {
	Url        string
	Driver     string
	NumThreads int
}
