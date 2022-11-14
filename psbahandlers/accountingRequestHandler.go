package psbahandlers

import (
	"github.com/francistor/igor/instrumentation"
	"github.com/francistor/igor/radiuscodec"
)

func AccountingRequestHandler(request *radiuscodec.RadiusPacket, logLines instrumentation.LogLines) (*radiuscodec.RadiusPacket, error) {

	return request, nil
}
