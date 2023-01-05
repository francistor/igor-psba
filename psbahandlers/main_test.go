package psbahandlers

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/httprouter"
	"github.com/francistor/igor/router"
)

// Variables at the disposal of the tests specified in other files
var clientRouter *router.RadiusRouter
var clientHttpRouter *httprouter.HttpRouter
var serverRouter *router.RadiusRouter
var superserverRouter *router.RadiusRouter

var http2Client http.Client

var testInvoker TestInvoker

var sessionCDRDir = "cdr/session"
var serviceCDRDir = "cdr/service"

func TestMain(m *testing.M) {

	bootstrapFile := "resources/searchRules.json"

	// Spawn three instances of router: client, server and superserver

	// Initialize policy instances
	core.InitPolicyConfigInstance(bootstrapFile, "clientpsba", true)
	serverCInstance := core.InitPolicyConfigInstance(bootstrapFile, "serverpsba", false)
	core.InitPolicyConfigInstance(bootstrapFile, "superserverpsba", false)

	// Initialize the routers
	clientRouter = router.NewRadiusRouter("clientpsba", VoidHandler)
	serverRouter = router.NewRadiusRouter("serverpsba", RequestHandler)
	superserverRouter = router.NewRadiusRouter("superserverpsba", SuperserverHandler)

	// Initialize a router in the client
	clientHttpRouter = httprouter.NewHttpRouter("clientpsba", nil, clientRouter)

	// Clean cdr files
	os.RemoveAll(sessionCDRDir)
	os.RemoveAll(serviceCDRDir)

	// Initialize handler for the server. The superserver will use test Handlers that do not require initialization
	if err := InitHandler(serverCInstance, serverRouter); err != nil {
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

	// The client http router will be listening in port 20000 (resources/clientpsba/httpRouter.json)
	testInvoker = TestInvoker{
		Url:         "https://localhost:20000/routeRadiusRequest",
		Http2Client: http2Client,
		RRouter:     clientRouter,
	}

	// Execute the tests
	exitCode := m.Run()

	// Close
	superserverRouter.Close()
	serverRouter.Close()
	clientHttpRouter.Close()
	clientRouter.Close()

	CloseHandler()

	os.Exit(exitCode)
}
