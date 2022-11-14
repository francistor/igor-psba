package psbahandlers

import (
	"fmt"

	"github.com/francistor/igor/instrumentation"
	"github.com/francistor/igor/radiuscodec"
	"go.uber.org/zap/zapcore"
)

func AccessRequestHandler(request *radiuscodec.RadiusPacket, logLines instrumentation.LogLines) (*radiuscodec.RadiusPacket, error) {

	// Find the user
	client, err := findClient(logLines)
	if err != nil {
		// No answer
		return nil, err
	}

	if client.ClientId != 0 {
		fmt.Printf("client found %#v\n", client)
	} else {
		fmt.Printf("client not found\n")
	}

	resp := radiuscodec.NewRadiusResponse(request, true)

	// Echo all attributes
	for i := range request.AVPs {
		resp.AddAVP(&request.AVPs[i])
	}

	return resp, nil
}

// Helper function to get the client from the database
func findClient(logLines instrumentation.LogLines) (Client, error) {
	// Find the user
	client := Client{}
	rows, err := dbHandle.Query("select ClientId, ExternalClientId, PlanName from clients where ExternalClientId = ?", 3)
	if err != nil {
		logLines.WLogEntry(zapcore.ErrorLevel, err.Error())
		return client, err
	}
	for rows.Next() {
		err := rows.Scan(&client.ClientId, &client.ExternalClientId, &client.PlanName)
		if err != nil {
			logLines.WLogEntry(zapcore.ErrorLevel, err.Error())
			return client, err
		}
	}
	err = rows.Err()
	if err != nil {
		logLines.WLogEntry(zapcore.ErrorLevel, err.Error())
		return client, err
	}

	return client, nil
}
