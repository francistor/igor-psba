package psbahandlers

import (
	"fmt"
	"time"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/radiuscodec"
)

// Void Handler
func VoidHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	return nil, nil
}

// Superserver Handler
// Echoes everything.
// If username is "reject", does reject
// If username is "drop", returns error
func SuperserverHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	hl := config.NewHandlerLogger()
	l := hl.L

	defer func(l *config.HandlerLogger) {
		l.WriteLog()
	}(hl)

	l.Debug("starting Echo Handler")

	userName := request.GetStringAVP("User-Name")

	var response *radiuscodec.RadiusPacket
	if userName == "drop" {
		return nil, fmt.Errorf("username was <drop>")
	}
	if userName == "reject" {
		response = radiuscodec.NewRadiusResponse(request, false)
		response.Add("Reply-Message", "rejected by upstream server")
		return response, nil
	}

	response = radiuscodec.NewRadiusResponse(request, true)

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
func ProxyHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	hl := config.NewHandlerLogger()
	l := hl.L

	defer func(l *config.HandlerLogger) {
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
