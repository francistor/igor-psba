package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/router"

	"github.com/francistor/igor-psba/psbahandlers"
)

func main() {

	// Set the environment if not already set
	if os.Getenv("IGOR_BASE") == "" {
		ex, _ := os.Executable()
		os.Setenv("IGOR_BASE", filepath.Dir(ex)+"/")
		fmt.Printf("Base location: %s\n", os.Getenv("IGOR_BASE"))
	}

	// defer profile.Start(profile.BlockProfile).Stop()

	// After ^C, signalChan will receive a message
	doneChan := make(chan struct{}, 1)
	signalChan := make(chan os.Signal, 1)
	go func() {
		<-signalChan
		close(doneChan)
		fmt.Println("terminating server")
	}()
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Get the command line arguments
	bootPtr := flag.String("boot", "resources/searchRules.json", "File or http URL with Configuration Search Rules")
	instancePtr := flag.String("instance", "", "Name of instance")

	flag.Parse()

	// Initialize the Config Object
	ci := core.InitPolicyConfigInstance(*bootPtr, *instancePtr, true)

	// Get logger
	logger := core.GetLogger()

	// Start Radius
	r := router.NewRadiusRouter(*instancePtr, psbahandlers.RequestHandler)
	logger.Info("Radius router started")

	// Initialize handler. Reads configuration files
	if err := psbahandlers.InitHandler(ci, r); err != nil {
		panic("could not initialize handler " + err.Error())
	}
	defer psbahandlers.CloseHandler()

	// Start server
	r.Start()

	// Wait for termination signal
	<-doneChan

	// Close router gracefully
	r.Close()
}
