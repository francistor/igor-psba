package psbahandlers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/handlerfunctions"
	"github.com/francistor/igor/instrumentation"
	"github.com/francistor/igor/radiuscodec"
	"github.com/francistor/igor/router"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

// Handler variables. Populated on initialization
var radiusRouter *router.RadiusRouter

var databaseConfig DatabaseConfig
var dbHandle *sql.DB

// Configuration files
var globalConfig GlobalConfig
var radiusClients config.RadiusClients
var realmConfig handlerfunctions.RadiusUserFile
var serviceConfig handlerfunctions.RadiusUserFile
var radiusChecks handlerfunctions.RadiusPacketChecks
var radiusFilters handlerfunctions.AVPFilters

var pwRegex = regexp.MustCompile("^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):(([0-9]+)-)?([0-9]+)$")

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
		return fmt.Errorf("could not ping database %w", err)
	}

	////////////////////////////////////////////////////////////////////////
	// Populate the configuration files
	////////////////////////////////////////////////////////////////////////
	// Global configuration
	gJson, err := ci.CM.GetConfigObjectAsText("globalConfig.json", true)
	if err != nil {
		return fmt.Errorf("could not read globalConfig.json %w", err)
	}
	err = json.Unmarshal(gJson, &globalConfig)
	if err != nil {
		return fmt.Errorf("could not unmarshal globalConfig.json %w", err)
	}

	// Radius Clients
	radiusClients = ci.RadiusClientsConf()

	// Realm config
	realmConfig, err = handlerfunctions.NewRadiusUserFile("realmConfig.json", ci)
	if err != nil {
		return fmt.Errorf("could not get realm configuration %w", err)
	}

	// Service configuration
	serviceConfig, err = handlerfunctions.NewRadiusUserFile("serviceConfig.json", ci)
	if err != nil {
		return fmt.Errorf("could not get service configuration.json %w", err)
	}

	// Radius Checks
	radiusChecks, err = handlerfunctions.NewRadiusChecks("radiusChecks.json", ci)
	if err != nil {
		return fmt.Errorf("could not get radius checks %w", err)
	}

	// Radius Filters
	radiusFilters, err = handlerfunctions.NewAVPFilters("radiusFilters.json", ci)
	if err != nil {
		return fmt.Errorf("could not get radius filters %w", err)
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

	// Prepare logging infra
	logLines := make(instrumentation.LogLines, 0)

	defer func(lines []instrumentation.LogLine) {
		logLines.WriteWLog()
	}(logLines)

	if config.IsDebugEnabled() {
		logLines.WLogEntry(config.LEVEL_DEBUG, "")
		logLines.WLogEntry(config.LEVEL_DEBUG, "starting processing radius packet")
		logLines.WLogEntry(config.LEVEL_DEBUG, request.String())
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
	fmt.Println(radiusClientType)

	// Normalize request data
	var userName = strings.ToLower(request.GetStringAVP("User-Name"))
	var userNameComponents = strings.Split(userName, "@")
	var realm = "NONE"
	if len(userNameComponents) > 1 {
		realm = userNameComponents[1]
	}
	fmt.Println(realm)
	var macAddress = ""
	if addr := request.GetStringAVP("Huawei-User-MAC"); addr != "" {
		macAddress = addr
	} else if addr := request.GetStringAVP("Alc-Client-Hardware-Addr"); addr != "" {
		macAddress = addr
	} else if addr := request.GetStringAVP("Unishpere-PPPoE-Description"); addr != "" {
		macAddress = addr[6:]
	} else if addr := request.GetCiscoAVPair("macaddress"); addr != "" {
		// TODO: Correct this!
		macAddress = addr
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
		logLines.WLogEntry(config.LEVEL_DEBUG, "Decoded NAS-Port-Id %s:%s-%s", dslamIPAddr, svlan, cvlan)

		svlanInt, err := strconv.ParseInt(svlan, 10, 64)
		if err != nil {
			logLines.WLogEntry(config.LEVEL_ERROR, "Bad svlan: %s", svlan)
		}
		cvlanInt, err := strconv.ParseInt(cvlan, 10, 64)
		if err != nil {
			logLines.WLogEntry(config.LEVEL_ERROR, "Bad cvlan: %s", cvlan)
		}
		accessId = dslamIPAddr
		accessPort = svlanInt*4096 + cvlanInt
	}

	// If the above did not produce a result
	if accessId == "" {
		accessPort = request.GetIntAVP("NAS-Port")
		accessId = request.GetStringAVP("NAS-IP-Address")
	}

	/*

	   // Add synthetic attribute with real NAS-IP-Address
	   request >> "NAS-IP-Address" match {
	     case Some(nasIpAddressAVP) => request << ("PSA-BRAS-NAS-IP-Address", nasIpAddressAVP.stringValue)
	     case _ =>
	   }

	   // Priorities Client --> Realm --> Global
	   val jConfig = jGlobalConfig.merge(jRealmConfig.forKey(realm, "DEFAULT")).
	     merge(jRadiusClientConfig.forKey(nasIpAddress, "DEFAULT"))
	*/

	// Call the corresponding handler
	switch request.Code {
	case radiuscodec.ACCESS_REQUEST:
		return AccessRequestHandler(request, logLines)
	case radiuscodec.ACCOUNTING_REQUEST:
		return AccountingRequestHandler(request, logLines)
	}

	// If here, the packet was not recognized
	return nil, fmt.Errorf("unrecognized code %d for radius packet", request.Code)
}