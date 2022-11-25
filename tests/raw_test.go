package psbatest

import (
	"fmt"
	"testing"
	"time"

	"github.com/francistor/igor/radiuscodec"
	"github.com/francistor/igor/router"
)

func TestAuthorizationTypes(t *testing.T) {

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := radiuscodec.NewRadiusRequest(radiuscodec.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01").
		Add("User-Password", passwordBytes)

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: database
	// Authlocal: provision

	// No user or password in database.
	requestPacket1 := requestPacket.Copy(nil, nil)
	requestPacket1.Add("NAS-Port", 8)
	requestPacket1.Add("User-Name", "francisco@database.provision.nopermissive.reject_addon.pcautiv_addon.proxy")
	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@database.provision.nopermissive.reject_addon.pcautiv_addon.proxy"},
		{"avp is", "Igor-OctetsAttribute", "01"},
	}

	testInvoker.testCaseRaw(t, "simple access request", checks, &rrr, clientRouter)

	/*
		// Password in database. Good password
		requestPacket2 := requestPacket.Copy(nil, nil)
		requestPacket2.Add("User-Name", "francisco@database.provision.nopermissive.reject_addon.pcautiv_addon.proxy")
		requestPacket2.Add("NAS-Port", 2)
		rrr.Packet = requestPacket2
		checks = []TestCheck{
			{"code is", "", "2"},
			{"avp is", "User-Name", "francisco@database.provision.nopermissive.reject_addon.pcautiv_addon.proxy"},
			{"avp is", "Igor-OctetsAttribute", "01"},
		}

		testInvoker.testCaseRaw(t, "simple access request", checks, &rrr, clientRouter)
	*/
}
