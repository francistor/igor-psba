package psbatest

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

	// Clean cdr files
	os.RemoveAll(os.Getenv("IGOR_BASE") + "/cdr/session")
	os.RemoveAll(os.Getenv("IGOR_BASE") + "/cdr/service")

	bootstrapFile := "resources/searchRules.json"

	// Spawn three instances of router: client, server and superserver

	// Initialize policy instances
	config.InitPolicyConfigInstance(bootstrapFile, "clientpsba", true)
	serverCInstance := config.InitPolicyConfigInstance(bootstrapFile, "serverpsba", false)
	config.InitPolicyConfigInstance(bootstrapFile, "superserverpsba", false)

	// Initialize the routers
	clientRouter = router.NewRadiusRouter("clientpsba", psbahandlers.VoidHandler)
	serverRouter = router.NewRadiusRouter("serverpsba", psbahandlers.RequestHandler)
	superserverRouter = router.NewRadiusRouter("superserverpsba", psbahandlers.SuperserverHandler)

	// Initialize a router in the client
	clientHttpRouter = httprouter.NewHttpRouter("clientpsba", nil, clientRouter)

	// Initialize handler for the server. The superserver will use test Handlers that do not require initialization
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
		Url:         "https://localhost:20000/routeRadiusRequest",
		Http2Client: http2Client,
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
