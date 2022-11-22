package psbahandlers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/francistor/igor/cdrwriter"
	"github.com/francistor/igor/config"
	"github.com/francistor/igor/handlerfunctions"
	"github.com/francistor/igor/radiuscodec"
	"github.com/francistor/igor/router"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

type RequestContext struct {
	accessId         string
	accessPort       int64
	userName         string
	realm            string
	radiusClientType string
	macAddress       string
	radiusAttributes handlerfunctions.AVPItems
	config           HandlerConfig
}

// Handler variables. Populated on initialization
var radiusRouter *router.RadiusRouter

var databaseConfig DatabaseConfig
var dbHandle *sql.DB

// Configuration files
var handlerConfig HandlerConfig
var radiusClients config.RadiusClients
var radiusServers config.RadiusServers
var realms handlerfunctions.RadiusUserFile
var services handlerfunctions.RadiusUserFile

var radiusCheckers handlerfunctions.RadiusPacketChecks
var radiusFilters handlerfunctions.AVPFilters

var pwRegex = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(([0-9]+)-)?([0-9]+)$`)

// CDR Writers
var cdrWriters []*cdrwriter.FileCDRWriter
var cdrWriteCheckers []string

// PlanParameter cache
var planCache *PlanCache

// Populates database config
func InitHandler(ci *config.PolicyConfigurationManager, r *router.RadiusRouter) error {

	var err error

	// Read database configuration
	if jc, err := ci.CM.GetConfigObjectAsText("clientsDatabase.json", true); err != nil {
		return fmt.Errorf("could not read clientsDatabase.json file %w", err)
	} else {
		if err = json.Unmarshal(jc, &databaseConfig); err != nil {
			return fmt.Errorf("could not unmarshal clientsDatabase.json %w", err)
		}
	}

	// Set the router variable
	radiusRouter = r

	// Create the database object
	dbHandle, err = sql.Open(databaseConfig.Driver, databaseConfig.Url)
	if err != nil {
		return fmt.Errorf("could not create database object %w", err)
	}
	err = dbHandle.Ping()
	if err != nil {
		// Just log. The database may be available later
		config.GetLogger().Warnf("could not ping database %s %s", databaseConfig.Driver, databaseConfig.Url)
	}

	////////////////////////////////////////////////////////////////////////
	// Start the cache
	////////////////////////////////////////////////////////////////////////
	planCache = NewPlanCache(dbHandle, 1*time.Second)
	planCache.Start()

	////////////////////////////////////////////////////////////////////////
	// Populate the configuration files
	////////////////////////////////////////////////////////////////////////

	// Radius Clients
	radiusClients = ci.RadiusClientsConf()

	// Radius Servers
	radiusServers = ci.RadiusServersConf()

	// Realm config
	realms, err = handlerfunctions.NewRadiusUserFile("realms.json", ci)
	if err != nil {
		return fmt.Errorf("could not get realm configuration: %w", err)
	}

	// Service configuration
	services, err = handlerfunctions.NewRadiusUserFile("services.json", ci)
	if err != nil {
		return fmt.Errorf("could not get service configuration.json: %w", err)
	}

	// Radius Checks
	radiusCheckers, err = handlerfunctions.NewRadiusPacketChecks("radiusCheckers.json", ci)
	if err != nil {
		return fmt.Errorf("could not get radius checks: %w", err)
	}

	// Radius Filters
	radiusFilters, err = handlerfunctions.NewAVPFilters("radiusFilters.json", ci)
	if err != nil {
		return fmt.Errorf("could not get radius filters: %w", err)
	}

	// Global configuration
	gJson, err := ci.CM.GetConfigObjectAsText("globalConfig.json", true)
	if err != nil {
		return fmt.Errorf("could not read globalConfig.json: %w", err)
	}
	err = json.Unmarshal(gJson, &handlerConfig)
	if err != nil {
		return fmt.Errorf("could not unmarshal globalConfig.json: %w", err)
	}

	// Sanity checks copy targets
	for _, ct := range handlerConfig.CopyTargets {
		if _, found := radiusCheckers[ct.CheckerName]; !found {
			panic(fmt.Sprintf("checker %s not found", ct.CheckerName))
		}
		if _, found := radiusFilters[ct.FilterName]; !found {
			panic(fmt.Sprintf("checker %s not found", ct.FilterName))
		}
		if _, found := radiusServers.ServerGroups[ct.ProxyGroupName]; !found {
			panic(fmt.Sprintf("proxy group %s not found", ct.ProxyGroupName))
		}
	}

	// Sanity checks for global config
	if _, found := radiusFilters[handlerConfig.AuthProxyFilterIn]; !found {
		panic(fmt.Sprintf("filter %s not found", handlerConfig.AuthProxyFilterIn))
	}
	if _, found := radiusFilters[handlerConfig.AuthProxyFilterOut]; !found {
		panic(fmt.Sprintf("filter %s not found", handlerConfig.AuthProxyFilterOut))
	}
	if _, found := radiusFilters[handlerConfig.AcctProxyFilterOut]; !found {
		panic(fmt.Sprintf("filter %s not found", handlerConfig.AcctProxyFilterOut))
	}
	if handlerConfig.ProxyGroupName != "" {
		if _, found := radiusServers.ServerGroups[handlerConfig.ProxyGroupName]; !found {
			panic(fmt.Sprintf("proxy group %s not found", handlerConfig.ProxyGroupName))
		}
	}

	////////////////////////////////////////////////////////////////////////
	// Create CDR writers
	////////////////////////////////////////////////////////////////////////
	for _, w := range handlerConfig.CDRWriters {
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
	if planCache != nil {
		planCache.Close()
	}
}

// Main entry point
func RequestHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {

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
	var clientConfig handlerfunctions.Properties = radiusClients[nasipAddr].ClientProperties
	var realmConfig handlerfunctions.Properties = realms[realm].ConfigItems
	requestConfig := handlerConfig.OverrideWith(clientConfig.OverrideWith(realmConfig), hl)

	if config.IsDebugEnabled() {
		l.Debugf("global config: %s", handlerConfig)
		l.Debugf("realm config: %s", realmConfig)
		l.Debugf("client config: %s", clientConfig)
		l.Debugf("merged config: %s", requestConfig)
	}

	// Merge the reply attributes. Priority is realm > global
	// TODO: Get attributes from radius client
	var radiusAttributes handlerfunctions.AVPItems = handlerConfig.RadiusAttrs
	radiusAttributes = radiusAttributes.OverrideWith(realms[realm].ReplyItems)

	var noRadiusAttributes handlerfunctions.AVPItems = handlerConfig.NonOverridableRadiusAttrs
	noRadiusAttributes = realms[realm].NonOverridableReplyItems.Add(handlerConfig.NonOverridableRadiusAttrs)

	if config.IsDebugEnabled() {
		l.Debugf("handler attributes: %s", handlerConfig.RadiusAttrs)
		l.Debugf("realm attributes: %s", realms[realm].ReplyItems)
		l.Debugf("merged attributes: %s", radiusAttributes)
		l.Debugf("no-handler attributes: %s", handlerConfig.NonOverridableRadiusAttrs)
		l.Debugf("no-realm attributes: %s", realms[realm].NonOverridableReplyItems)
		l.Debugf("no-merged attributes: %s", noRadiusAttributes)
	}

	// Build Request context
	ctx := RequestContext{
		accessId:         accessId,
		accessPort:       accessPort,
		userName:         userName,
		realm:            realm,
		radiusClientType: radiusClientType,
		macAddress:       macAddress,
		radiusAttributes: radiusAttributes,
		config:           requestConfig,
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
