package psbahandlers

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/handler"
)

type DatabaseConfig struct {
	Url          string
	Driver       string
	MaxOpenConns int
	MaxIdleConns int
}

type PlanTemplateParams struct {
	Speed   int
	Message string
}

type CDRWriter struct {
	Path            string
	FileNamePattern string
	Format          string
	Attributes      string
	CheckerName     string
	RotateSeconds   int64
}

type CopyTarget struct {
	// Only for logging purposes
	TargetName string

	// The name of the radius group where to send the copies
	ProxyGroupName string

	// Checker name to use to select what packets are copied
	CheckerName string

	// AVP Filter to use
	FilterName string

	// Timeout
	ProxyTimeoutMillis int

	// Tries to the proxy group
	ProxyRetries int

	// Tries for each server in proxy group
	ProxyServerRetries int
}

type HandlerConfig struct {
	// CDR Writing
	CDRWriters         []CDRWriter
	WriteSessionCDR    bool
	WriteServiceCDR    bool
	CdrFilenamePattern string

	// Accounting Copy
	CopyTargets []CopyTarget

	// Inline proxy
	ProxyGroupName         string
	AcceptOnProxyError     bool
	ProxySessionAccounting bool
	ProxyServiceAccounting bool

	// Normally overriden in a per-domain basis
	ProxyTimeoutMillis int
	ProxyRetries       int
	ProxyServerRetries int
	AuthProxyFilterOut string
	AuthProxyFilterIn  string
	AcctProxyFilterOut string

	// May be "database", "file" or "radius". In this case, a "ProxyGroupName" must be configured
	ProvisionType string
	// Whether to validate the credentials locally, irrespective of whether a proxy is performed. May be "provision" or "file"
	AuthLocal string

	// Users not found in database
	PermissiveProfile string

	// Whether to send Access-Reject to users not provisioned or with bad credentials
	RejectProfile string

	// Whether to send Access-Reject to blocked user
	BlockingProfile               string
	BlockingIsAddon               bool
	BlockingSessionTimeoutSeconds int

	// To be used in the domain configuration, to override the basic profile
	RealmProfile string

	// Advertising service could be basic
	NotificationIsAddon bool

	// Global Radius attributes to send
	RadiusAttrs               []core.RadiusAVP
	NonOverridableRadiusAttrs []core.RadiusAVP
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
func (g HandlerConfig) OverrideWith(props handler.Properties, hl *core.HandlerLogger) HandlerConfig {

	l := hl.L

	for key := range props {
		lowerKey := strings.ToLower(key)

		switch lowerKey {
		case "writesessioncdr":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.WriteSessionCDR = v
			} else {
				l.Errorf("bad format for WriteSessionCDR %s %s", props[key], err)
			}
		case "writeservicecdr":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.WriteServiceCDR = v
			} else {
				l.Errorf("bad format for WriteServiceCDR %s", props[key])
			}
		case "proxygroupname":
			g.ProxyGroupName = props[key]
		case "acceptonproxyerror":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.AcceptOnProxyError = v
			} else {
				l.Errorf("bad format for AcceptOnProxyError %s", props[key])
			}
		case "proxysessionaccounting":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.ProxySessionAccounting = v
			} else {
				l.Errorf("bad format for ProxySessionAccounting %s", props[key])
			}
		case "proxyserviceaccounting":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.ProxyServiceAccounting = v
			} else {
				l.Errorf("bad format for ProxyServiceAccounting %s", props[key])
			}
		case "proxytimeoutmillis":
			if v, err := strconv.ParseInt(props[key], 10, 32); err == nil {
				g.ProxyTimeoutMillis = int(v)
			} else {
				l.Errorf("bad format for ProxyTimeoutMillis %s", props[key])
			}
		case "proxyretries":
			if v, err := strconv.ParseInt(props[key], 10, 32); err == nil {
				g.ProxyRetries = int(v)
			} else {
				l.Errorf("bad format for ProxyRetries %s", props[key])
			}
		case "proxyserverretries":
			if v, err := strconv.ParseInt(props[key], 10, 32); err == nil {
				g.ProxyServerRetries = int(v)
			} else {
				l.Errorf("bad format for ProxyServerRetries %s", props[key])
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
		case "rejectprofile":
			g.RejectProfile = props[key]
		case "permissiveprofile":
			g.PermissiveProfile = props[key]
		case "blockingisaddon":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.BlockingIsAddon = v
			} else {
				l.Errorf("bad format for BlockingIsAddon %s", props[key])
			}
		case "blockingprofile":
			g.BlockingProfile = props[key]
		case "blockingsessiontimeoutseconds":
			if v, err := strconv.ParseInt(props[key], 10, 32); err == nil {
				g.BlockingSessionTimeoutSeconds = int(v)
			} else {
				l.Errorf("bad format for BlockingSessionTimeoutSeconds %s", props[key])
			}
		case "realmprofile":
			g.RealmProfile = props[key]
		case "notificationisaddon":
			if v, err := strconv.ParseBool(props[key]); err == nil {
				g.NotificationIsAddon = v
			} else {
				l.Errorf("bad format for NotificationIsAddon %s", props[key])
			}
		}
	}

	return g
}
