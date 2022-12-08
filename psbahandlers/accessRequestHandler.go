package psbahandlers

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/handler"
)

func AccessRequestHandler(request *core.RadiusPacket, ctx *RequestContext, hl *core.HandlerLogger) (*core.RadiusPacket, error) {

	now := time.Now()

	// For logging
	l := hl.L

	// We signal that the client is to be rejected by providing a value to this variable, that is used also in the Reply-Message
	var rejectReason string
	// Profiles to assign. The model specifies a mandatory basic profile and an optional addon profile
	var basicProfile string
	var addonProfile string
	// Attributes from upstream server
	var proxyRadiusAttrs = make([]core.RadiusAVP, 0)

	// Find the user
	clientpou, err := findClient(ctx.userName, ctx.accessPort, ctx.accessId, hl)
	if err != nil {
		// No answer
		return nil, err
	}

	// Actions if user not found
	if clientpou.ClientId != 0 {
		l.Debugf("client found %#v\n", clientpou)
		basicProfile = standardBasicProfileName
	} else {
		l.Debug("client not found\n")
		// If permissiveProfile is defined, we assign that one. Otherwise, signal rejection
		if ctx.config.PermissiveProfile != "" {
			l.Debugf("assigning permissive profile <%s>", ctx.config.PermissiveProfile)
			clientpou.AccessId = ctx.accessId
			clientpou.AccessPort = ctx.accessPort
			clientpou.UserName = ctx.userName
			basicProfile = ctx.config.PermissiveProfile
		} else {
			rejectReason = "client not found"
		}
	}

	// Authenticate user
	switch ctx.config.AuthLocal {
	case "provision":
		// Check only if provisioned password
		if clientpou.Password != "" {
			if request.GetPasswordStringAVP("User-Password") != clientpou.Password {
				l.Debugf("incorrect password")
				rejectReason = "authorization rejected (provision) for " + clientpou.UserName
			}
		} else {
			l.Debugf("not verifying unprovisioned password")
		}

		// Check login if provisioned
		if clientpou.UserName != "" {
			if ctx.userName != strings.ToLower(clientpou.UserName) {
				l.Debugf("incorrect login")
				rejectReason = "login unmatch (provision) for " + clientpou.UserName
			}
		} else {
			l.Debugf("not verifying unprovisioned login")
		}
	case "file":
		if userEntry, found := specialUsers.Get()[clientpou.UserName]; found {
			if request.GetPasswordStringAVP("User-Password") != userEntry.CheckItems["password"] {
				l.Debugf("incorrect password")
				rejectReason = "Authorization rejected (file) for " + clientpou.UserName
			}
		} else {
			l.Debugf("%s not found in special users file", clientpou.UserName)
			rejectReason = clientpou.UserName + "not found"
		}
	default:
	}

	if rejectReason == "" {
		// Priorities are (from low to high)
		// Notification --> clientOverrides --> blocked --> realmOverride (--> rejectOverrides)

		// Apply overrides and calculate basic service and addon

		// Notification overrides
		if clientpou.NotificationExpDate.After(now) {
			if ctx.config.NotificationIsAddon {
				addonProfile = "notification"
				l.Debugf("applying notification addon <%s>", addonProfile)
			} else {
				basicProfile = "notification"
				l.Debugf("applying notification basic profile <%s>", basicProfile)
			}
		}
		// Client overrides
		if clientpou.AddonProfileOverrideExpDate.After(now) {
			addonProfile = clientpou.AddonProfileOverride
			l.Debugf("applying client addon <%s>", addonProfile)
		}
		// Blocking overrides
		// TODO: Apply blocking timeout
		if clientpou.BlockingStatus == 2 {
			if ctx.config.BlockingIsAddon {
				addonProfile = ctx.config.BlockingProfile
				l.Debugf("applying blocking addon <%s>", addonProfile)
			} else {
				basicProfile = ctx.config.BlockingProfile
				l.Debugf("applying blocking basic profile <%s>", basicProfile)
			}
		}
		// Realm override
		if ctx.config.RealmProfile != "" {
			basicProfile = ctx.config.RealmProfile
			addonProfile = ""
			l.Debugf("applying realm basic profile <%s>", basicProfile)
		}

		// Proxy
		if ctx.config.ProxyGroupName != "" && ctx.config.ProxyGroupName != "none" {

			// Filter
			proxyRequest, err := radiusFilters.FilteredPacket(request, ctx.config.AuthProxyFilterOut)
			if err != nil {
				return nil, fmt.Errorf("could not apply filter %s: %w", ctx.config.AuthProxyFilterOut, err)
			}

			// Do proxy
			l.Debugf("proxying to %s with attributes %v", ctx.config.ProxyGroupName, proxyRequest.AVPs)
			proxyReply, err := radiusRouter.RouteRadiusRequest(
				proxyRequest,
				ctx.config.ProxyGroupName,
				time.Duration(ctx.config.ProxyTimeoutMillis)*time.Millisecond,
				1+ctx.config.ProxyRetries,
				1+ctx.config.ProxyServerRetries,
				"")

			// Treat error (exit or ignore)
			if err != nil {
				l.Debugf("proxy error %s", err)
				if !ctx.config.AcceptOnProxyError {
					return nil, fmt.Errorf("proxy error: %w", err)
				} else {
					// Fake, accept, empty radius response
					proxyReply = core.NewRadiusResponse(request, true)
					l.Debugf("ingoring proxy error %w", err)
				}
			} else {
				l.Debugf("proxy reply: %s", proxyReply)
			}

			// Treat reject
			if proxyReply.Code == core.ACCESS_REJECT {
				l.Debug("access reject")
				rejectReason = "rejected by upstream radius: " + proxyReply.GetStringAVP("Reply-Message")
			} else {
				// Access Accept
				l.Debug("access accept")
				filteredProxyReply, err := radiusFilters.FilteredPacket(proxyReply, ctx.config.AuthProxyFilterIn)
				if err != nil {
					return nil, fmt.Errorf("could not apply filter %s: %w", ctx.config.AuthProxyFilterIn, err)
				}
				proxyRadiusAttrs = filteredProxyReply.AVPs
				l.Debugf("filtered proxy reply attributes: %s", proxyRadiusAttrs)
			}
		}
	}

	// Reject overrides or reject reply
	if rejectReason != "" {
		// Just a normal reject
		if ctx.config.RejectProfile == "" {
			l.Debugf("sending reject with reason %s", rejectReason)
			response := core.NewRadiusResponse(request, false)
			response.Add("Reply-Message", rejectReason)
			return response, nil
		}

		l.Debugf("applying reject basic profile <%s>", basicProfile)
		basicProfile = ctx.config.RejectProfile
		addonProfile = ""
	}

	// Compose final response

	// Get the basic profile radius attributes
	l.Debugf("composing final response with basicProfile <%s> and addonProfile <%s>", basicProfile, addonProfile)

	var basicProfileRadiusAttrs handler.AVPItems
	var basicProfileNoRadiusAttrs handler.AVPItems
	if basicProfile == standardBasicProfileName {
		// If the basic profile is that of the Internet service, take the parametrization from the basicProfiles
		basicProfileForPlan, err := basicProfiles.GetKey(clientpou.PlanName)
		if err != nil {
			l.Errorf("plan %s not found", clientpou.PlanName)
			return nil, fmt.Errorf("plan %s not found", clientpou.PlanName)
		}
		basicProfileRadiusAttrs = basicProfileForPlan[standardBasicProfileName].ReplyItems
		basicProfileNoRadiusAttrs = basicProfileForPlan[standardBasicProfileName].NonOverridableReplyItems
	} else {
		l.Info(profiles.Get())
		basicProfileRadiusAttrs = profiles.Get()[basicProfile].ReplyItems
		basicProfileNoRadiusAttrs = profiles.Get()[basicProfile].NonOverridableReplyItems
	}

	// Get the addon profile radius attributes
	var addonProfileRadiusAttrs handler.AVPItems
	var addonProfileNoRadiusAttrs handler.AVPItems
	if addonProfile != "" {
		if addon, found := profiles.Get()[addonProfile]; !found {
			return nil, fmt.Errorf("addon profile not found %s", addonProfile)
		} else {
			addonProfileRadiusAttrs = addon.ReplyItems
			addonProfileNoRadiusAttrs = addon.ReplyItems
		}
	}

	// Log
	if core.IsDebugEnabled() {
		l.Debugf("basic profile attributes: %s", basicProfileRadiusAttrs)
		l.Debugf("basic profile no attributes: %s", basicProfileNoRadiusAttrs)
		l.Debugf("addon profile attributes: %s", addonProfileRadiusAttrs)
		l.Debugf("addon profile no attributes: %s", addonProfileNoRadiusAttrs)
	}

	// Merge
	radiusAttributes := ctx.radiusAttributes.OverrideWith(basicProfileRadiusAttrs).OverrideWith(addonProfileRadiusAttrs).OverrideWith(proxyRadiusAttrs)
	noRadiusAttributes := ctx.noRadiusAttributes.Add(basicProfileNoRadiusAttrs).Add(addonProfileNoRadiusAttrs)

	// Compose and add class attribute
	classAttrs := []string{fmt.Sprintf("P:%s", clientpou.PlanName), fmt.Sprintf("C:%s", clientpou.ExternalClientId)}
	if addonProfile != "" {
		classAttrs = append(classAttrs, fmt.Sprintf("A:%s", addonProfile))
	}
	classRadiusAVP, _ := core.NewRadiusAVP("Class", strings.Join(classAttrs, "#"))

	// Build the response
	response := core.NewRadiusResponse(request, true).
		AddAVPs(radiusAttributes).
		AddAVPs(noRadiusAttributes).
		AddAVP(classRadiusAVP)

	// Add the Fixed IP addresses if necessary
	if clientpou.IPv4Address != "" {
		response.Add("Framed-IP-Address", clientpou.IPv4Address)
	}
	if clientpou.IPv6DelegatedPrefix != "" {
		response.Add("Delegated-IPv6-Prefix", clientpou.IPv6DelegatedPrefix)
	}

	l.Debugf(response.String())

	return response, nil
}

type NullableClientPoU struct {
	ClientId                    int
	ExternalClientId            string
	ISP                         sql.NullString
	PlanName                    string
	BlockingStatus              int
	PlanOverride                sql.NullString
	PlanOverrideExpDate         sql.NullTime
	AddonProfileOverride        sql.NullString
	AddonProfileOverrideExpDate sql.NullTime
	NotificationExpDate         sql.NullTime
	Parameters                  sql.NullString
	AccessPort                  sql.NullInt64
	AccessId                    sql.NullString
	UserName                    sql.NullString
	Password                    sql.NullString
	IPv4Address                 sql.NullString
	IPv6DelegatedPrefix         sql.NullString
	IPv6WANPrefix               sql.NullString
	AccessType                  sql.NullInt32
	CheckType                   sql.NullInt32
}

func (p *NullableClientPoU) toPoU() ClientPoU {
	clientPoU := ClientPoU{
		ClientId:                    p.ClientId,
		ExternalClientId:            p.ExternalClientId,
		ISP:                         p.ISP.String,
		PlanName:                    p.PlanName,
		BlockingStatus:              p.BlockingStatus,
		PlanOverride:                p.PlanOverride.String,
		PlanOverrideExpDate:         p.PlanOverrideExpDate.Time,
		AddonProfileOverride:        p.AddonProfileOverride.String,
		AddonProfileOverrideExpDate: p.AddonProfileOverrideExpDate.Time,
		NotificationExpDate:         p.NotificationExpDate.Time,
		Parameters:                  p.Parameters.String,
		AccessPort:                  p.AccessPort.Int64,
		AccessId:                    p.AccessId.String,
		UserName:                    p.UserName.String,
		Password:                    p.Password.String,
		IPv4Address:                 p.IPv4Address.String,
		IPv6DelegatedPrefix:         p.IPv6DelegatedPrefix.String,
		IPv6WANPrefix:               p.IPv6WANPrefix.String,
		AccessType:                  int(p.AccessType.Int32),
		CheckType:                   int(p.CheckType.Int32),
	}

	return clientPoU
}

// Helper function to get the client from the database
func findClient(userName string, accessPort int64, accessId string, hl *core.HandlerLogger) (ClientPoU, error) {

	l := hl.L

	// Find the user
	clientpou := NullableClientPoU{}
	stmt, err := dbHandle.Prepare(`select 
	clients.ClientId, 
	ExternalClientId, 
	ISP, 
	PlanName, 
	BlockingStatus, 
	PlanOverride, 
	PlanOverrideExpDate, 
	AddonProfileOverride, 
	AddonProfileOverrideExpDate, 
	NotificationExpDate,
	Parameters,
	AccessPort,
	AccessId,
	UserName,
	Password,
	IPv4Address,
	IPv6DelegatedPrefix,
	IPv6WANPrefix,
	AccessType,
	CheckType
	from clients, pou where clients.ClientId = pou.ClientId and accessId = ? and accessPort = ?`)
	if err != nil {
		l.Error(err.Error())
		return ClientPoU{}, err
	}
	rows, err := stmt.Query(accessId, accessPort)
	if err != nil {
		return ClientPoU{}, err
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(
			&clientpou.ClientId,
			&clientpou.ExternalClientId,
			&clientpou.ISP,
			&clientpou.PlanName,
			&clientpou.BlockingStatus,
			&clientpou.PlanOverride,
			&clientpou.PlanOverrideExpDate,
			&clientpou.AddonProfileOverride,
			&clientpou.AddonProfileOverrideExpDate,
			&clientpou.NotificationExpDate,
			&clientpou.Parameters,
			&clientpou.AccessPort,
			&clientpou.AccessId,
			&clientpou.UserName,
			&clientpou.Password,
			&clientpou.IPv4Address,
			&clientpou.IPv6DelegatedPrefix,
			&clientpou.IPv6WANPrefix,
			&clientpou.AccessType,
			&clientpou.CheckType,
		)
		if err != nil {
			l.Error(err.Error())
			return ClientPoU{}, err
		}
	}
	err = rows.Err()
	if err != nil {
		l.Error(err.Error())
		return ClientPoU{}, err
	}

	return clientpou.toPoU(), nil
}
