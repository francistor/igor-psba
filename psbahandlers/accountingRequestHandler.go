package psbahandlers

import (
	"sync"
	"time"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/radiuscodec"
)

func AccountingRequestHandler(request *radiuscodec.RadiusPacket, ctx *RequestContext, hl *config.HandlerLogger, wg *sync.WaitGroup) (*radiuscodec.RadiusPacket, error) {

	l := hl.L

	l.Debug("start processing accounting request")
	l.Debug(request.String())

	// Check Session or Service accounting
	var serviceName string
	if ctx.radiusClientType == "SRC" {
		serviceName = request.GetStringAVP("Class")
	} else {
		if hsi := request.GetStringAVP("HW-Service-Info"); hsi != "" && len(hsi) > 1 {
			serviceName = hsi[1:]
		} else if alussa := request.GetStringAVP("Alc-Sub-Serv-Activate"); alussa != "" {
			serviceName = alussa
		} else if sn := request.GetCiscoAVPair("servicename"); sn != "" {
			serviceName = sn
		} else if sn := request.GetStringAVP("Redback-Service-Name"); sn != "" {
			serviceName = sn
		}
	}

	// Insert attribute if Service Accounting
	if serviceName != "" {
		l.Debugf("is service accounting: >%s>", serviceName)
		request.Add("PSA-ServiceName", serviceName)
	} else {
		l.Debugf("is session accounting")
	}

	// Write CDR
	for i, w := range cdrWriters {
		l.Debugf("checking with <%s>", cdrWriteCheckers[i])
		if c, found := radiusCheckers[cdrWriteCheckers[i]]; found {
			if c.CheckPacket(request) {
				w.WriteRadiusCDR(request)
				l.Debugf("cdr written")
			}
		} else {
			panic("checker not found: " + cdrWriteCheckers[i])
		}
	}

	// Copy to defined targets
	for _, ct := range ctx.config.CopyTargets {
		// Check if the packet should be treated by this target
		checker := radiusCheckers[ct.CheckerName]
		if checker.CheckPacket(request) {
			l.Debugf("copy to %s -> group: %s", ct.TargetName, ct.ProxyGroupName)
			// Generate the copy to be sent to the proxy
			// Ignore the error because the check was done at initialization time
			reqCopy, _ := radiusFilters.FilterPacket(ct.FilterName, request)
			l.Debugf("sending radius packet to %s %s", ct.ProxyGroupName, reqCopy)

			// Do proxy asycnronously
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := radiusRouter.RouteRadiusRequest(ct.ProxyGroupName, reqCopy, time.Duration(ct.ProxyTimeoutMillis)*time.Millisecond, 1+ct.ProxyRetries, 1+ct.ProxyServerRetries, ""); err != nil {
					config.GetLogger().Warnf("error sending copy to %s: %s", ct.ProxyGroupName, err)
				} else {
					l.Debugf("proxy done")
				}
			}()

		} else {
			l.Debugf("skipping target %s", ct.TargetName)
		}
	}

	// Inline proxy
	if ctx.config.ProxyGroupName != "" && ((serviceName != "" && ctx.config.ProxyServiceAccounting) || (serviceName == "" && ctx.config.ProxySessionAccounting)) {
		l.Debugf("proxy to %s", ctx.config.ProxyGroupName)
		reqCopy, _ := radiusFilters.FilterPacket(ctx.config.AcctProxyFilterOut, request)
		_, err := radiusRouter.RouteRadiusRequest(ctx.config.ProxyGroupName, reqCopy, time.Duration(ctx.config.ProxyTimeoutMillis)*time.Millisecond, 1+ctx.config.ProxyRetries, 1+ctx.config.ProxyServerRetries, "")
		if err != nil {
			l.Warn("error proxying to %s: %s", ctx.config.ProxyGroupName, err)
		}
	}

	response := radiuscodec.NewRadiusResponse(request, true)

	return response, nil
}
