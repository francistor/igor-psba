package psbahandlers

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/router"
)

func TestSessionAcctCDRWrite(t *testing.T) {

	requestPacket := core.NewRadiusRequest(core.ACCOUNTING_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("NAS-Port", 1).
		Add("User-Name", "TestUsername").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	requestPacket1 := requestPacket.Copy(nil, nil)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "5"},
	}

	testInvoker.testCaseRaw(t, "Smoke test", checks, &rrr)

	// Find a CDR file
	sessionCDRFiles, err := os.ReadDir(sessionCDRDir)
	if err != nil {
		t.Fatalf("error reading session cdr directory: %s", err)
	}
	if len(sessionCDRFiles) < 1 {
		t.Fatalf("no session cdr found: %s", err)
	}
	// Check contents
	fileBytes, err := os.ReadFile(sessionCDRDir + "/" + sessionCDRFiles[0].Name())
	if err != nil {
		t.Fatalf("error reading session cdr file: %s", err)
	}
	if !strings.Contains(string(fileBytes), "TestUsername") {
		t.Fatalf("bad contents in cdr file")
	}

	// The service CDR file is empty
	serviceCDRFiles, err := os.ReadDir(serviceCDRDir)
	if err != nil {
		t.Fatalf("error reading service cdr directory: %s", err)
	}
	if len(serviceCDRFiles) != 0 {
		t.Fatal("some file found in service cdr directory")
	}
}

func TestServiceAcctCDRWrite(t *testing.T) {

	requestPacket := core.NewRadiusRequest(core.ACCOUNTING_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("NAS-Port", 1).
		Add("User-Name", "TestUsername").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("HW-Service-Info", "Abasic")

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "5"},
	}

	testInvoker.testCaseRaw(t, "Smoke test", checks, &rrr)

	// Find a CDR file
	serviceCDRFiles, err := os.ReadDir(serviceCDRDir)
	if err != nil {
		t.Fatalf("error reading service cdr directory: %s", err)
	}
	if len(serviceCDRFiles) < 1 {
		t.Fatalf("no service cdr found: %s", err)
	}
	// Check contents
	fileBytes, err := os.ReadFile(serviceCDRDir + "/" + serviceCDRFiles[0].Name())
	fmt.Println(string(fileBytes))
	if err != nil {
		t.Fatalf("error reading service cdr file: %s", err)
	}
	if !strings.Contains(string(fileBytes), "basic") {
		t.Fatalf("bad contents in cdr file")
	}
}
