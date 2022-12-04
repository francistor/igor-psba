package psbahandlers

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/francistor/igor/cdrwriter"
	"github.com/francistor/igor/config"
	"github.com/francistor/igor/handler"
	"github.com/francistor/igor/radiuscodec"
	"github.com/francistor/igor/router"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

// Regex for the nas-port-id in pseudowire format
var pwRegex = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(([0-9]+)-)?([0-9]+)$`)

// To pass info from the Main handler to the packet-type specific handlers
type RequestContext struct {
	accessId         string
	accessPort       int64
	userName         string
	realm            string
	radiusClientType string
	macAddress       string

	// Merged configuration from realm > client > global
	config HandlerConfig

	// Attributes merged from realm > client > global
	radiusAttributes   handler.AVPItems
	noRadiusAttributes handler.AVPItems
}

// Handler variables. Populated on initialization
var radiusRouter *router.RadiusRouter
var confMgr *config.PolicyConfigurationManager

var databaseConfig *config.ConfigObject[DatabaseConfig]
var dbHandle *sql.DB

// Configuration files
var handlerConfig *config.ConfigObject[HandlerConfig]
var realms *config.ConfigObject[handler.RadiusUserFile]
var specialUsers *config.ConfigObject[handler.RadiusUserFile]
var addonProfiles *config.ConfigObject[handler.RadiusUserFile]
var basicProfiles *config.TemplatedConfigObject[handler.RadiusUserFile, PlanTemplateParams]

var radiusCheckers handler.RadiusPacketChecks
var radiusFilters handler.AVPFilters

// CDR Writers
var cdrWriters []*cdrwriter.FileCDRWriter
var cdrWriteCheckers []string

// Populates database config
func InitHandler(ci *config.PolicyConfigurationManager, r *router.RadiusRouter) error {

	var err error

	// Set the router variable
	radiusRouter = r

	// Set the configuration instance variable
	confMgr = ci

	// Read database configuration
	databaseConfig = config.NewConfigObject[DatabaseConfig]("clientsDatabase.json")
	if err := databaseConfig.Update(&ci.CM); err != nil {
		return fmt.Errorf("could not read clientsDatabase.json file %w", err)
	}

	// Create the database object
	var dbCfg = databaseConfig.Get()
	dbHandle, err = sql.Open(dbCfg.Driver, dbCfg.Url)
	if err != nil {
		return fmt.Errorf("could not create database object %w", err)
	}
	dbHandle.SetMaxOpenConns(dbCfg.MaxOpenConns)
	dbHandle.SetMaxIdleConns(dbCfg.MaxIdleConns)

	// Check the database connection
	err = dbHandle.Ping()
	if err != nil {
		// If the database is not available, die
		config.GetLogger().Errorf("could not ping database %s %s", dbCfg.Driver, dbCfg.Url)
		panic("could not ping database")
	}

	////////////////////////////////////////////////////////////////////////
	// Initialize configuration objects
	////////////////////////////////////////////////////////////////////////

	// These configuration items are updateable

	// Global configuration
	handlerConfig = config.NewConfigObject[HandlerConfig]("globalConfig.json")
	if err = handlerConfig.Update(&ci.CM); err != nil {
		return fmt.Errorf("could not read globalConfig.json: %w", err)
	}
	hc := handlerConfig.Get()

	// special users
	specialUsers = config.NewConfigObject[handler.RadiusUserFile]("specialUsers.json")
	if err = specialUsers.Update(&ci.CM); err != nil {
		return fmt.Errorf("could not get special users configuration: %w", err)
	}

	// Realm config
	realms = config.NewConfigObject[handler.RadiusUserFile]("realms.json")
	if err = realms.Update(&ci.CM); err != nil {
		return fmt.Errorf("could not get realm configuration: %w", err)
	}

	// Service configuration
	basicProfiles = config.NewTemplatedConfigObject[handler.RadiusUserFile, PlanTemplateParams]("basicProfiles.txt", "planparameters")
	if err = basicProfiles.Update(&ci.CM); err != nil {
		return fmt.Errorf("could not get basic profiles: %w", err)
	}

	addonProfiles = config.NewConfigObject[handler.RadiusUserFile]("addonProfiles.json")
	if err = addonProfiles.Update(&ci.CM); err != nil {
		return fmt.Errorf("could not get addon profiles: %w", err)
	}

	fmt.Printf("%v\n", basicProfiles)

	// Radius Checks
	radiusCheckers, err = handler.NewRadiusPacketChecks("radiusCheckers.json", ci)
	if err != nil {
		return fmt.Errorf("could not get radius checks: %w", err)
	}

	// Radius Filters
	radiusFilters, err = handler.NewAVPFilters("radiusFilters.json", ci)
	if err != nil {
		return fmt.Errorf("could not get radius filters: %w", err)
	}

	// Sanity checks copy targets
	for _, ct := range hc.CopyTargets {
		if _, found := radiusCheckers[ct.CheckerName]; !found {
			panic(fmt.Sprintf("checker %s not found", ct.CheckerName))
		}
		if _, found := radiusFilters[ct.FilterName]; !found {
			panic(fmt.Sprintf("checker %s not found", ct.FilterName))
		}
		if _, found := ci.RadiusServers().ServerGroups[ct.ProxyGroupName]; !found {
			panic(fmt.Sprintf("proxy group %s not found", ct.ProxyGroupName))
		}
	}

	// Sanity checks for global config
	if _, found := radiusFilters[hc.AuthProxyFilterIn]; !found {
		panic(fmt.Sprintf("filter %s not found", hc.AuthProxyFilterIn))
	}
	if _, found := radiusFilters[hc.AuthProxyFilterOut]; !found {
		panic(fmt.Sprintf("filter %s not found", hc.AuthProxyFilterOut))
	}
	if _, found := radiusFilters[hc.AcctProxyFilterOut]; !found {
		panic(fmt.Sprintf("filter %s not found", hc.AcctProxyFilterOut))
	}
	if hc.ProxyGroupName != "" {
		if _, found := ci.RadiusServers().ServerGroups[hc.ProxyGroupName]; !found {
			panic(fmt.Sprintf("proxy group %s not found", hc.ProxyGroupName))
		}
	}

	////////////////////////////////////////////////////////////////////////
	// Create CDR writers
	////////////////////////////////////////////////////////////////////////
	for _, w := range hc.CDRWriters {
		var cdrf cdrwriter.CDRFormatter
		var attrs []string
		if w.Attributes != "" {
			attrs = strings.Split(w.Attributes, ",")
		}

		if strings.EqualFold("csv", w.Format) {
			cdrf = cdrwriter.NewCSVWriter(attrs, ";", ",", "2006-01-02T15:04:05 MST", true, true)
		} else if strings.EqualFold("livingstone", w.Format) {
			cdrf = cdrwriter.NewLivingstoneWriter(attrs, nil, "2006-01-02T15:04:05 MST", "2006-01-02T15:04:05 MST")
		} else if strings.EqualFold("json", w.Format) {
			cdrf = cdrwriter.NewJSONWriter(attrs, nil)
		} else {
			panic("unrecognized format for CDR: " + w.Format)
		}
		cdrWriters = append(cdrWriters, cdrwriter.NewFileCDRWriter(w.Path, w.FileNamePattern, cdrf, w.RotateSeconds))
		cdrWriteCheckers = append(cdrWriteCheckers, w.CheckerName)

		// Sanity check for checker name
		if _, found := radiusCheckers[w.CheckerName]; !found {
			panic(fmt.Sprintf("checker %s not found", w.CheckerName))
		}
	}

	return nil
}

func CloseHandler() {
	if dbHandle != nil {
		dbHandle.Close()
	}
}

// Main entry point
func RequestHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {

	// Get my copy of the configuration
	var handlerConfig = handlerConfig.Get()

	hl := config.NewHandlerLogger()
	l := hl.L
	l.Debug("")

	defer func(h *config.HandlerLogger) {
		h.L.Debug("---[END REQUEST]-----")
		h.L.Debug("")
		h.WriteLog()
	}(hl)

	l.Debug("---[START REQUEST]-----")
	if config.IsDebugEnabled() {
		l.Debug(request.String())
	}

	// Detect client type based on the attributes received
	var radiusClientType = "DEFAULT"
	if len(request.GetAllAVP("Unisphere-PPPoE-Description")) > 0 {
		radiusClientType = "HUAWEI"
	} else if len(request.GetAllAVP("Alc-Client-Hardware-Addr")) > 0 {
		radiusClientType = "ALU"
	} else if len(request.GetAllAVP("Cico-AVPair")) > 0 {
		radiusClientType = "CISCO"
	} else if len(request.GetAllAVP("Unishpere-PPPoE-Description")) > 0 {
		radiusClientType = "MX"
	} else {
		radiusClientType = "DEFAULT"
	}
	l.Debugf("radius client type: %s", radiusClientType)

	// Normalize request data
	var userName = strings.ToLower(request.GetStringAVP("User-Name"))
	var userNameComponents = strings.Split(userName, "@")
	var realm = "NONE"
	if len(userNameComponents) > 1 {
		realm = userNameComponents[1]
	}
	l.Debugf("realm: %s", realm)

	// Get my realm
	realmEntry := realms.Get()[realm]

	var macAddress = ""
	if addr := request.GetStringAVP("Hw-User-MAC"); addr != "" {
		macAddress = addr
	} else if addr := request.GetStringAVP("Alc-Client-Hardware-Addr"); addr != "" {
		macAddress = addr
	} else if addr := request.GetStringAVP("Unishpere-PPPoE-Description"); addr != "" {
		macAddress = addr[6:]
	} else if addr := request.GetCiscoAVPair("macaddress"); addr != "" {
		// TODO: Correct this!
		macAddress = addr
	}

	// Add attribute to request
	if macAddress != "" {
		request.Add("PSA-MAC-Address", macAddress)
	}

	// Get the AccessPort and AccessId
	var accessPort int64
	var accessId string
	var nasPortId = request.GetStringAVP("NAS-Port-Id")
	if nasPortId != "" && (radiusClientType == "MX" || radiusClientType == "HUAWEI") {
		m := pwRegex.FindStringSubmatch(nasPortId)
		dslamIPAddr := m[1]
		svlan := m[2]
		cvlan := m[3]
		l.Debugf("Decoded NAS-Port-Id %s:%s-%s", dslamIPAddr, svlan, cvlan)

		svlanInt, err := strconv.ParseInt(svlan, 10, 64)
		if err != nil {
			l.Errorf("Bad svlan: %s", svlan)
		}
		cvlanInt, err := strconv.ParseInt(cvlan, 10, 64)
		if err != nil {
			l.Errorf("Bad cvlan: %s", cvlan)
		}
		accessPort = svlanInt*4096 + cvlanInt
		accessId = dslamIPAddr
		l.Debugf("access line with pseudowire format. port %d - accessId %s", accessPort, accessId)
	}

	// If the above did not produce a result
	if accessId == "" {
		accessPort = request.GetIntAVP("NAS-Port")
		accessId = request.GetStringAVP("NAS-IP-Address")
		l.Debugf("access line with nasport/nasip format. port %d - accessId %s", accessPort, accessId)
	}

	// To look for client configuration
	var nasipAddr = request.GetStringAVP("NAS-IP-Address")

	// Push attributes with cooked access identifiers
	request.Add("PSA-AccessId", accessId)
	request.Add("PSA-AccessPort", int(accessPort))

	// Merge the configuration. Priority is realm > client > global
	var clientConfig handler.Properties = confMgr.RadiusClients()[nasipAddr].ClientProperties
	var realmConfig handler.Properties = realmEntry.ConfigItems
	requestConfig := handlerConfig.OverrideWith(clientConfig.OverrideWith(realmConfig), hl)

	if config.IsDebugEnabled() {
		l.Debugf("global config: %s", handlerConfig)
		l.Debugf("realm config: %s", realmConfig)
		l.Debugf("client config: %s", clientConfig)
		l.Debugf("merged config: %s", requestConfig)
	}

	// Merge the reply attributes. Priority is realm > global
	// TODO: Get attributes from radius client
	var radiusAttributes handler.AVPItems = handlerConfig.RadiusAttrs
	radiusAttributes = radiusAttributes.OverrideWith(realmEntry.ReplyItems)

	var noRadiusAttributes handler.AVPItems = handlerConfig.NonOverridableRadiusAttrs
	noRadiusAttributes = realmEntry.NonOverridableReplyItems.Add(handlerConfig.NonOverridableRadiusAttrs)

	if config.IsDebugEnabled() {
		l.Debugf("handler attributes: %s", handlerConfig.RadiusAttrs)
		l.Debugf("realm attributes: %s", realmEntry.ReplyItems)
		l.Debugf("merged attributes: %s", radiusAttributes)
		l.Debugf("no-handler attributes: %s", handlerConfig.NonOverridableRadiusAttrs)
		l.Debugf("no-realm attributes: %s", realmEntry.NonOverridableReplyItems)
		l.Debugf("no-merged attributes: %s", noRadiusAttributes)
	}

	// Build Request context
	ctx := RequestContext{
		accessId:           accessId,
		accessPort:         accessPort,
		userName:           userName,
		realm:              realm,
		radiusClientType:   radiusClientType,
		macAddress:         macAddress,
		radiusAttributes:   radiusAttributes,
		noRadiusAttributes: noRadiusAttributes,
		config:             requestConfig,
	}

	// Call the corresponding handler
	switch request.Code {
	case radiuscodec.ACCESS_REQUEST:
		return AccessRequestHandler(request, &ctx, hl)
	case radiuscodec.ACCOUNTING_REQUEST:
		// To avoid issues when sending packets in copy mode
		var wg sync.WaitGroup
		resp, err := AccountingRequestHandler(request, &ctx, hl, &wg)
		wg.Wait()
		return resp, err
	}

	// If here, the packet was not recognized
	return nil, fmt.Errorf("unrecognized code %d for radius packet", request.Code)
}
