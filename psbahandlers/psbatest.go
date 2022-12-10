package psbahandlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/httprouter"
	"github.com/francistor/igor/router"
)

// Placeholder for the specification of something to validate in a radius packet
// CheckType may be "avp is", "code is"
type TestCheck struct {
	CheckType    string
	CheckOperand string
	CheckValue   string
}

// This object implements methods to implement a radius test, consisting of sending a radius
// packet and validating the response agains a set of rules specified as TestChecks
// May use http to send the requests, in which case the Http2Client and Url are in effect, or
// may use a radius router, in which case the field RRouter must be initialized
type TestInvoker struct {
	Http2Client http.Client
	Url         string
	RRouter     *router.RadiusRouter
}

// Sends a request and verifies the answer. Request is in JSON format
func (i *TestInvoker) testCaseJSON(t *testing.T, testName string, checks []TestCheck, request string) {

	// Send the request to the router
	jRadiusResponse, err := httprouter.RouteHttp(i.Http2Client, i.Url, []byte(request))

	if err != nil {
		t.Fatalf("<%s> could not route request due to %s", testName, err)
	}

	// Get the response
	var radiusResponse core.RadiusPacket
	err = json.Unmarshal(jRadiusResponse, &radiusResponse)
	if err != nil {
		t.Fatalf("<%s> could not unmarshal response due to %s", testName, err)
	}

	// Verify
	i.checkResponse(t, testName, checks, &radiusResponse)
}

// Sends a request and verifies the answer. Request is a raw radius packet
func (i *TestInvoker) testCaseRaw(t *testing.T, testName string, checks []TestCheck, rrequest *router.RoutableRadiusRequest) {

	radiusResponse, err := i.RRouter.RouteRadiusRequest(rrequest.Packet, rrequest.Destination, rrequest.PerRequestTimeout, rrequest.Tries, rrequest.ServerTries, rrequest.Secret)
	if err != nil {
		t.Fatalf("<%s> could not route request due to %s", testName, err)
	}

	// Verify
	i.checkResponse(t, testName, checks, radiusResponse)
}

// Validates a radius packet against a series of checks
func (i *TestInvoker) checkResponse(t *testing.T, testName string, checks []TestCheck, radiusResponse *core.RadiusPacket) {
	var val string
	for _, check := range checks {
		switch check.CheckType {

		case "avp contains":
			val = radiusResponse.GetStringAVP(check.CheckOperand)
			if !strings.Contains(val, check.CheckValue) {
				t.Errorf("[FAIL] <%s> %s does not contain %s", testName, check.CheckOperand, val)
			} else {
				t.Logf("[OK] <%s> %s contains %s", testName, check.CheckOperand, check.CheckValue)
			}

		case "avp is":
			val = radiusResponse.GetStringAVP(check.CheckOperand)
			if val != check.CheckValue {
				t.Errorf("[FAIL] <%s> %s is %s", testName, check.CheckOperand, val)
			} else {
				t.Logf("[OK] <%s> %s is %s", testName, check.CheckOperand, check.CheckValue)
			}

		case "cisco avpair is":
			val = radiusResponse.GetCiscoAVPair(check.CheckOperand)
			if val != check.CheckValue {
				t.Errorf("[FAIL] <%s> %s is %s", testName, check.CheckOperand, val)
			} else {
				t.Logf("[OK] <%s> %s is %s", testName, check.CheckOperand, check.CheckValue)
			}

		case "cisco avpair notpresent":
			val = radiusResponse.GetCiscoAVPair(check.CheckOperand)
			if val != "" {
				t.Errorf("[FAIL] <%s> %s is present", testName, check.CheckOperand)
			} else {
				t.Logf("[OK] <%s> %s is not present", testName, check.CheckOperand)
			}

		case "avp notpresent":
			val = radiusResponse.GetStringAVP(check.CheckOperand)
			if val != "" {
				t.Errorf("[FAIL] <%s> %s is present", testName, check.CheckOperand)
			} else {
				t.Logf("[OK] <%s> %s is not present", testName, check.CheckOperand)
			}

		case "avp present":
			val = radiusResponse.GetStringAVP(check.CheckOperand)
			if val == "" {
				t.Errorf("[FAIL] <%s> %s is not present", testName, check.CheckOperand)
			} else {
				t.Logf("[OK] <%s> %s is present", testName, check.CheckOperand)
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
