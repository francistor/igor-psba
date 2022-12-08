package psbahandlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/francistor/igor/core"
)

// Void Handler
func VoidHandler(request *core.RadiusPacket) (*core.RadiusPacket, error) {
	return nil, nil
}

// Superserver Handler
// Echoes everything.
// If username is "reject", does reject
// If username is "drop", returns error
func SuperserverHandler(request *core.RadiusPacket) (*core.RadiusPacket, error) {
	hl := core.NewHandlerLogger()
	l := hl.L

	defer func(l *core.HandlerLogger) {
		l.WriteLog()
	}(hl)

	l.Debug("starting Echo Handler")

	userName := request.GetStringAVP("User-Name")

	var response *core.RadiusPacket
	if userName == "drop" {
		return nil, fmt.Errorf("username was <drop>")
	}

	// Access-Reject does not mirror or include attributes other than Reply-Message
	if strings.HasPrefix(userName, "reject") {
		response = core.NewRadiusResponse(request, false)
		response.Add("Reply-Message", "rejected by upstream server")
		return response, nil
	}

	response = core.NewRadiusResponse(request, true)

	// Echo all attributes
	for i := range request.AVPs {
		l.Infof("copying attribute %s", request.AVPs[i])
		response.AddAVP(&request.AVPs[i])
	}

	// Add attributes
	response.Add("Framed-IP-Address", "10.10.10.10")
	response.Add("Reply-Message", "message from upstream")

	l.Infof("finished Echo Handler")
	return response, nil
}

// Send all request to super-server
func ProxyHandler(request *core.RadiusPacket) (*core.RadiusPacket, error) {
	hl := core.NewHandlerLogger()
	l := hl.L

	defer func(l *core.HandlerLogger) {
		l.WriteLog()
	}(hl)

	l.Debug("starting Proxy Handler")
	proxyResponse, err := radiusRouter.RouteRadiusRequest(request.Copy(nil, nil), "psba-superserver-group", 1*time.Second, 1, 1, "")
	if err != nil {
		return nil, err
	}
	l.Infof(proxyResponse.String())
	l.Infof("finished Proxy Handler")

	// Tweak authenticator
	return proxyResponse.MakeResponseTo(request), nil
}
