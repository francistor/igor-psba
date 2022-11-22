package psbahandlers

import (
	"database/sql"
	"fmt"
	"time"
)

// Represents a PlanParameter
type PlanParameter struct {
	ParameterName  string
	ParameterValue string
}

// Gets periodically the info in the PlanParameters table
type PlanCache struct {
	Parameters *map[string][]PlanParameter
	ticker     *time.Ticker
	dbHandle   *sql.DB
}

// Creates a new PlanCache
func NewPlanCache(dbHandle *sql.DB, tickTime time.Duration) *PlanCache {
	var pc = PlanCache{
		ticker:   time.NewTicker(tickTime),
		dbHandle: dbHandle,
	}

	// Initialize
	pc.refreshParameters()

	return &pc
}

// Starts the caching process
func (pc *PlanCache) Start() {
	go func() {
		for range pc.ticker.C {
			err := pc.refreshParameters()
			if err != nil {
				fmt.Println("plan parameters cache refresh error: " + err.Error())
			}
		}
	}()
}

// Stops the ticker
func (pc *PlanCache) Close() {
	pc.ticker.Stop()
}

// Grabs the planparameters form the DB
func (pc *PlanCache) refreshParameters() error {
	var params = make(map[string][]PlanParameter)
	stmt, err := dbHandle.Prepare("select PlanName, ParameterName, ParameterValue from planParameters")
	if err != nil {
		return err
	}
	rows, err := stmt.Query()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var planName string
		var parameterName string
		var parameterValue string
		err := rows.Scan(
			&planName,
			&parameterName,
			&parameterValue,
		)
		if err != nil {
			return err
		}

		if _, found := params[planName]; found {
			params[planName] = append(params[planName], PlanParameter{parameterName, parameterValue})
		} else {
			params[planName] = []PlanParameter{{parameterName, parameterValue}}
		}
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	pc.Parameters = &params

	return nil
}
