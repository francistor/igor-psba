package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/francistor/igor/httprouter"
	"github.com/francistor/igor/radiuscodec"
)

type TestCheck struct {
	checkType    string
	checkOperand string
	checkValue   string
}

type TestInvoker struct {
	http2Client http.Client
	url         string
}

func (i *TestInvoker) testCase(t *testing.T, testName string, request string, checks []TestCheck) {

	jRadiusResponse, err := httprouter.RouteHttp(i.http2Client, i.url, []byte(request))

	if err != nil {
		t.Fatalf("%s could not route request due to %s", testName, err)
	}

	var radiusResponse radiuscodec.RadiusPacket
	err = json.Unmarshal(jRadiusResponse, &radiusResponse)
	if err != nil {
		t.Fatalf("%s could not unmarshal response due to %s", testName, err)
	}

	for _, check := range checks {
		switch check.checkType {
		case "avp is":
			val := radiusResponse.GetStringAVP(check.checkOperand)
			if val != check.checkValue {
				t.Errorf("[FAIL] <%s> %s is %s", testName, check.checkOperand, check.checkValue)
			} else {
				t.Logf("[OK] <%s> %s is %s", testName, check.checkOperand, check.checkValue)
			}
		case "code is":
			if string(radiusResponse.Code) != check.checkValue {
				t.Errorf("[FAIL] <%s> code is %s", testName, check.checkValue)
			} else {
				t.Errorf("[OK] <%s> code is %s", testName, check.checkValue)
			}
		}
	}

}
