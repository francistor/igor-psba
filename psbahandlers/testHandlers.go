package psbahandlers

import (
	"time"

	"github.com/francistor/igor/instrumentation"
	"github.com/francistor/igor/radiuscodec"
	"go.uber.org/zap/zapcore"
)

// Void Handler
func VoidHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	return nil, nil
}

// Superserver Handler
func EchoHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	logLines := make(instrumentation.LogLines, 0)

	defer func(lines []instrumentation.LogLine) {
		logLines.WriteWLog()
	}(logLines)

	logLines.WLogEntry(zapcore.InfoLevel, "starting Echo Handler")

	resp := radiuscodec.NewRadiusResponse(request, true)

	// Echo all attributes
	for i := range request.AVPs {
		logLines.WLogEntry(zapcore.InfoLevel, "copying attribute %s", request.AVPs[i])
		resp.AddAVP(&request.AVPs[i])
	}

	logLines.WLogEntry(zapcore.InfoLevel, "finished Echo Handler")
	return resp, nil
}

// Send all request to super-server
func ProxyHandler(request *radiuscodec.RadiusPacket) (*radiuscodec.RadiusPacket, error) {
	logLines := make(instrumentation.LogLines, 0)

	defer func(lines []instrumentation.LogLine) {
		logLines.WriteWLog()
	}(logLines)

	logLines.WLogEntry(zapcore.InfoLevel, "starting Proxy Handler")
	proxyResponse, err := radiusRouter.RouteRadiusRequest("psba-superserver-group", request.Copy(nil, nil), 1*time.Second, 1, 1, "")
	if err != nil {
		return nil, err
	}
	logLines.WLogEntry(zapcore.InfoLevel, proxyResponse.String())
	logLines.WLogEntry(zapcore.InfoLevel, "finished Proxy Handler")

	// Tweak authenticator
	return proxyResponse.MakeResponseTo(request), nil
}
