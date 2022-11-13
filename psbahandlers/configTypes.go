package psbahandlers

import "github.com/francistor/igor/radiuscodec"

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

type GlobalConfig struct {
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
	// Whether to validate the credentials locally, irrespective of whether a proxy is performed
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

type DatabaseConfig struct {
	Url        string
	Driver     string
	NumThreads int
}
