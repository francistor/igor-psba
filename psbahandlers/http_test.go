package psbahandlers

import (
	"fmt"
	"strings"
	"testing"
)

func TestSimpleAccessRequest(t *testing.T) {

	// Build the request packet
	jRadiusRequest := `
	{
		"destination": "psba-server-group",
		"packet": {
			"Code": 1,
			"AVPs":[
				{"User-Name":"francisco@database.provision.nopermissive.doreject.block_addon.proxy"},
				{"User-Password": "${password}"},
				{"NAS-IP-Address": "127.0.0.1"},
				{"NAS-Port": 2},
				{"Igor-OctetsAttribute": "01"}	
			]
		},
		"perRequestTimeoutSpec": "1s",
		"tries": 1,
		"serverTries": 1
	}
	`
	jRadiusRequest = strings.ReplaceAll(jRadiusRequest, "${password}", fmt.Sprintf("%x", []byte("francisco")))

	checks := []TestCheck{
		{"avp is", "User-Name", "francisco@database.provision.nopermissive.doreject.block_addon.proxy"},
		{"avp is", "Igor-OctetsAttribute", "01"},
	}
	testInvoker.testCaseJSON(t, "simple access request", checks, jRadiusRequest)
}

func TestSimpleSessionAccountingRequest(t *testing.T) {

	// Build the request packet
	jRadiusRequest := `
	{
		"destination": "psba-server-group",
		"packet": {
			"Code": 4,
			"AVPs":[
				{"User-Name":"francisco@database.provision.nopermissive.doreject.block_addon.proxy"},
				{"NAS-IP-Address": "127.0.0.1"},
				{"NAS-Port": 1},
				{"Igor-OctetsAttribute": "01"},
				{"Acct-Status-Type": "Start"}	
			]
		},
		"perRequestTimeoutSpec": "1s",
		"tries": 1,
		"serverTries": 1
	}
	`
	checks := []TestCheck{
		{"code is", "", "5"},
	}
	testInvoker.testCaseJSON(t, "simple session accounting", checks, jRadiusRequest)
}

func TestSimpleServiceAccountingRequest(t *testing.T) {

	// Build the request packet
	jRadiusRequest := `
	{
		"destination": "psba-server-group",
		"packet": {
			"Code": 4,
			"AVPs":[
				{"User-Name":"francisco@database.provision.nopermissive.doreject.block_addon.proxy"},
				{"NAS-IP-Address": "127.0.0.1"},
				{"NAS-Port": 1},
				{"Igor-OctetsAttribute": "01"},
				{"Acct-Status-Type": "Start"},	
				{"HW-Service-Info":"Nmyservice"}
			]
		},
		"perRequestTimeoutSpec": "1s",
		"tries": 1,
		"serverTries": 1
	}
	`
	checks := []TestCheck{
		{"code is", "", "5"},
	}
	testInvoker.testCaseJSON(t, "simple test", checks, jRadiusRequest)
}
