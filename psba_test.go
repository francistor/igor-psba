package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/francistor/igor-psba/psbahandlers"
	"golang.org/x/net/http2"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/httprouter"
	"github.com/francistor/igor/router"
)

var clientRouter *router.RadiusRouter
var clientHttpRouter *httprouter.HttpRouter
var serverRouter *router.RadiusRouter
var superserverRouter *router.RadiusRouter

var http2Client http.Client

var testInvoker TestInvoker

func TestMain(m *testing.M) {

	// Initialize the Config Object as done in main.go
	bootstrapFile := "resources/searchRules.json"

	// Initialize policy
	config.InitPolicyConfigInstance(bootstrapFile, "clientpsba", true)
	serverCInstance := config.InitPolicyConfigInstance(bootstrapFile, "serverpsba", false)
	config.InitPolicyConfigInstance(bootstrapFile, "superserverpsba", false)

	clientRouter = router.NewRadiusRouter("clientpsba", psbahandlers.VoidHandler)
	serverRouter = router.NewRadiusRouter("serverpsba", psbahandlers.RequestHandler)
	superserverRouter = router.NewRadiusRouter("superserverpsba", psbahandlers.EchoHandler)

	clientHttpRouter = httprouter.NewHttpRouter("clientpsba", nil, clientRouter)

	// Initialize handler
	if err := psbahandlers.InitHandler(serverCInstance, serverRouter); err != nil {
		panic(err)
	}

	// Start routers
	clientRouter.Start()
	serverRouter.Start()
	superserverRouter.Start()

	// Http Client
	// Create an http client with timeout and http2 transport
	http2Client = http.Client{
		Timeout: 2 * time.Second,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ignore expired SSL certificates
		},
	}

	testInvoker = TestInvoker{
		url:         "https://localhost:20000/routeRadiusRequest",
		http2Client: http2Client,
	}

	// Execute the tests
	exitCode := m.Run()

	// Close
	superserverRouter.Close()
	serverRouter.Close()
	clientHttpRouter.Close()
	clientRouter.Close()

	psbahandlers.CloseHandler()

	os.Exit(exitCode)
}

func TestSimpleRequest(t *testing.T) {

	// Build the request packet
	jRadiusRequest := `
	{
		"destination": "psba-server-group",
		"packet": {
			"Code": 1,
			"AVPs":[
				{"User-Name":"myusername@database.provision.preject_addon.pcautiv_addon.proxy"},
				{"NAS-IP-Address": "150.0.0.1"},
				{"NAS-Port": 1},
				{"Igor-OctetsAttribute": "00"}	
			]
		},
		"perRequestTimeoutSpec": "1s",
		"tries": 1,
		"serverTries": 1
	}
	`
	checks := []TestCheck{
		{"avp is", "User-Name", "myusername@proxy"},
		{"avp is", "Igor-OctetsAttribute", "00"},
	}
	testInvoker.testCase(t, "simple test", jRadiusRequest, checks)
}
