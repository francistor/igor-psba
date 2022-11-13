package psbahandlers

import (
	"encoding/json"
	"fmt"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/radiuscodec"
	"github.com/francistor/igor/router"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

var databaseConfig DatabaseConfig
var dbHandle *sql.DB
var radiusRouter *router.RadiusRouter

// Populates database config
func InitHandler(ci *config.PolicyConfigurationManager, r *router.RadiusRouter) error {

	// Read database configuration
	if jc, err := ci.CM.GetConfigObjectAsText("clientsDatabase.json", true); err != nil {
		return err
	} else {
		if err = json.Unmarshal(jc, &databaseConfig); err != nil {
			return err
		}
	}

	// Set the router variable
	radiusRouter = r

	// Create the database object
	var err error
	dbHandle, err = sql.Open(databaseConfig.Driver, databaseConfig.Url)
	if err != nil {
		return err
	}
	err = dbHandle.Ping()
	if err != nil {
		return err
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

	// Call the corresponding handler
	switch request.Code {
	case radiuscodec.ACCESS_REQUEST:
		return AccessRequestHandler(request)
	case radiuscodec.ACCOUNTING_REQUEST:
		return AccountingRequestHandler(request)
	}

	// If here, the packet was not recognized
	return nil, fmt.Errorf("unrecognized code %d for radius packet", request.Code)
}
