package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/handlerfunctions"
	"github.com/francistor/igor/router"

	"github.com/francistor/igor-psba/psbahandlers"
)

func main() {

	// defer profile.Start(profile.BlockProfile).Stop()

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
	ci := config.InitPolicyConfigInstance(*bootPtr, *instancePtr, true)

	// Get logger
	logger := config.GetLogger()

	// Start Radius
	r := router.NewRadiusRouter(*instancePtr, handlerfunctions.EmptyRadiusHandler)
	logger.Info("Radius router started")

	// Initialize handler. Reads configuration files
	if err := psbahandlers.InitHandler(ci, r); err != nil {
		panic("could not initialize handler " + err.Error())
	}
	defer psbahandlers.CloseHandler()

	// Start server
	r.Start()

	<-doneChan

	// Close router gracefully
	r.Close()
}
