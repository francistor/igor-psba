package psbatest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/francistor/igor/httprouter"
	"github.com/francistor/igor/radiuscodec"
	"github.com/francistor/igor/router"
)

type TestCheck struct {
	CheckType    string
	CheckOperand string
	CheckValue   string
}

type TestInvoker struct {
	Http2Client http.Client
	Url         string
}

// Validates a radius packet against a series of checks
func (i *TestInvoker) checkResponse(t *testing.T, testName string, checks []TestCheck, radiusResponse *radiuscodec.RadiusPacket) {
	var val string
	for _, check := range checks {
		switch check.CheckType {
		case "avp is":
			val = radiusResponse.GetStringAVP(check.CheckOperand)
			if val != check.CheckValue {
				t.Errorf("[FAIL] <%s> %s is %s", testName, check.CheckOperand, val)
			} else {
				t.Logf("[OK] <%s> %s is %s", testName, check.CheckOperand, check.CheckValue)
			}
		case "code is":
			val = fmt.Sprintf("%d", radiusResponse.Code)
			if val != check.CheckValue {
				t.Errorf("[FAIL] <%s> response code is %s", testName, val)
			} else {
				t.Logf("[OK] <%s> response code is %s", testName, check.CheckValue)
			}
		}
	}
}

// Sends a request and verifies the answer. Request is in JSON format
func (i *TestInvoker) testCaseJSON(t *testing.T, testName string, checks []TestCheck, request string) {

	// Send the request to the router
	jRadiusResponse, err := httprouter.RouteHttp(i.Http2Client, i.Url, []byte(request))

	if err != nil {
		t.Fatalf("<%s> could not route request due to %s", testName, err)
	}

	// Get the response
	var radiusResponse radiuscodec.RadiusPacket
	err = json.Unmarshal(jRadiusResponse, &radiusResponse)
	if err != nil {
		t.Fatalf("<%s> could not unmarshal response due to %s", testName, err)
	}

	// Verify
	i.checkResponse(t, testName, checks, &radiusResponse)
}

// Sends a request and verifies the answer. Request is a raw radius packet
func (i *TestInvoker) testCaseRaw(t *testing.T, testName string, checks []TestCheck, rrequest *router.RoutableRadiusRequest, router *router.RadiusRouter) {

	radiusResponse, err := router.RouteRadiusRequest(rrequest.Packet, rrequest.Destination, rrequest.PerRequestTimeout, rrequest.Tries, rrequest.ServerTries, rrequest.Secret)
	if err != nil {
		t.Fatalf("<%s> could not route request due to %s", testName, err)
	}

	// Verify
	i.checkResponse(t, testName, checks, radiusResponse)
}
