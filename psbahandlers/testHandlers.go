package psbahandlers

import (
	"time"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/radiuscodec"
)

// Void Handler
func VoidHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	return nil, nil
}

// Superserver Handler
func EchoHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	hl := config.NewHandlerLogger()
	l := hl.L

	defer func(l *config.HandlerLogger) {
		l.WriteLog()
	}(hl)

	l.Debug("starting Echo Handler")

	resp := radiuscodec.NewRadiusResponse(request, true)

	// Echo all attributes
	for i := range request.AVPs {
		l.Infof("copying attribute %s", request.AVPs[i])
		resp.AddAVP(&request.AVPs[i])
	}

	l.Infof("finished Echo Handler")
	return resp, nil
}

// Send all request to super-server
func ProxyHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	hl := config.NewHandlerLogger()
	l := hl.L

	defer func(l *config.HandlerLogger) {
		l.WriteLog()
	}(hl)

	l.Debug("starting Proxy Handler")
	proxyResponse, err := radiusRouter.RouteRadiusRequest("psba-superserver-group", request.Copy(nil, nil), 1*time.Second, 1, 1, "")
	if err != nil {
		return nil, err
	}
	l.Infof(proxyResponse.String())
	l.Infof("finished Proxy Handler")

	// Tweak authenticator
	return proxyResponse.MakeResponseTo(request), nil
}
