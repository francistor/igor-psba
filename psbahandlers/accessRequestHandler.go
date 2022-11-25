package psbahandlers

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/radiuscodec"
)

func AccessRequestHandler(request *radiuscodec.RadiusPacket, ctx *RequestContext, hl *config.HandlerLogger) (*radiuscodec.RadiusPacket, error) {

	now := time.Now()

	// For logging
	l := hl.L

	// We signal that the client is to be rejected by providing a value to this variable, that is used also in the Reply-Message
	var rejectReason string
	// Profiles to assign. The model specifies a mandatory basic profile and an optional addon profile
	var basicProfile string
	var addonProfile string
	// Attributes from upstream server
	var proxyAVPs = make([]radiuscodec.RadiusAVP, 0)

	// Find the user
	clientpou, err := findClient(ctx.userName, ctx.accessPort, ctx.accessId, hl)
	if err != nil {
		// No answer
		return nil, err
	}

	// Actions if user not found
	if clientpou.ClientId != 0 {
		l.Debugf("client found %#v\n", clientpou)
		//l.Debug(clientpou.NotificationExpDate.Format("2006-01-02T15:04:05 MST"))
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
		if userEntry, found := specialUsers[clientpou.UserName]; found {
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
		basicProfile = "basic"
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
			proxyRequest, err := radiusFilters.FilteredPacket(ctx.config.AuthProxyFilterOut, request)
			if err != nil {
				return nil, fmt.Errorf("could not apply filter %s: %w", ctx.config.AuthProxyFilterOut, err)
			}

			// Do proxy
			proxyReply, err := radiusRouter.RouteRadiusRequest(
				proxyRequest,
				ctx.config.ProxyGroupName,
				time.Duration(ctx.config.ProxyTimeoutMillis)*time.Millisecond,
				1+ctx.config.ProxyRetries,
				1+ctx.config.ProxyServerRetries,
				"")

			// Treat error (exit or ignore)
			if err != nil {
				if !ctx.config.AcceptOnProxyError {
					return nil, fmt.Errorf("proxy error: %w", err)
				} else {
					// Fake, accept, empty radius response
					proxyReply = radiuscodec.NewRadiusResponse(request, true)
					l.Debugf("ingoring proxy error %w", err)
				}
			} else {
				l.Debugf("proxy reply: %s", proxyReply)
			}

			// Treat reject
			if proxyReply.Code == radiuscodec.ACCESS_REJECT {
				rejectReason = "rejected by upstream radius: " + proxyReply.GetStringAVP("Reply-Message")
			} else {
				// Access Accept
				filteredProxyReply, err := radiusFilters.FilteredPacket(ctx.config.AuthProxyFilterIn, proxyReply)
				if err != nil {
					return nil, fmt.Errorf("could not apply filter %s: %w", ctx.config.AuthProxyFilterIn, err)
				}
				proxyAVPs = filteredProxyReply.AVPs
				l.Debugf("filtered proxy reply attributes: %s", proxyAVPs)
			}
		}
	}

	// Reject overrides or reject reply
	if rejectReason != "" {
		// Just a normal reject
		if ctx.config.RejectProfile == "" {

			response := radiuscodec.NewRadiusResponse(request, false)
			response.Add("Reply-Message", rejectReason)
			return response, nil
		}

		if ctx.config.RejectIsAddon {
			addonProfile = ctx.config.RejectProfile
			l.Debugf("applying reject addon <%s>", addonProfile)
		} else {
			basicProfile = ctx.config.RejectProfile
			addonProfile = ""
			l.Debugf("applying reject basic profile <%s>", basicProfile)
		}
	}

	// Compose final response

	/*
			// Get basic service attributes
		                  val serviceAVPList = getRadiusAttrs(jServiceConfig, fServiceNameOption, "radiusAttrs")
		                  val noServiceAVPList = getRadiusAttrs(jServiceConfig, fServiceNameOption, "nonOverridableRadiusAttrs")

		                  val addonAVPList = if(fAddonServiceNameOption.isDefined) getRadiusAttrs(jServiceConfig, fAddonServiceNameOption, "radiusAttrs") else List()
		                  val noAddonAVPList = if(fAddonServiceNameOption.isDefined) getRadiusAttrs(jServiceConfig, fAddonServiceNameOption, "nonOverridableRadiusAttrs") else List()

		                  // Get domain attributes
		                  val realmAVPList = getRadiusAttrs(jRealmConfig, Some(realm), "radiusAttrs")
		                  val noRealmAVPList = getRadiusAttrs(jRealmConfig, Some(realm), "nonOverridableRadiusAttrs")

		                  // Get global attributes
		                  val globalAVPList = getRadiusAttrs(jGlobalConfig, None, "radiusAttrs")
		                  val noGlobalAVPList = getRadiusAttrs(jGlobalConfig, None, "nonOverridableRadiusAttrs")

		                  if(log.isDebugEnabled){
		                    log.debug("Adding Proxied Attributes: {}", proxyAVPList.map(_.pretty).mkString)
		                    log.debug("Adding non overridable Addon attributes: {} -> {}", fAddonServiceNameOption, noAddonAVPList.map(_.pretty).mkString)
		                    log.debug("Adding non overridable Service attributes: {} -> {}", fServiceNameOption, noServiceAVPList.map(_.pretty).mkString)
		                    log.debug("Adding non overridable realm attributes: {} -> {}", realm, noRealmAVPList.map(_.pretty).mkString)
		                    log.debug("Adding non overridable global attributes: {}", noGlobalAVPList.map(_.pretty).mkString)
		                    log.debug("Adding Addon attributes: {} -> {} ", fAddonServiceNameOption, addonAVPList.map(_.pretty).mkString)
		                    log.debug("Adding Service attributes: {} -> {} ", fServiceNameOption, serviceAVPList.map(_.pretty).mkString)
		                    log.debug("Adding realm attributes: {} -> {}", realm, realmAVPList.map(_.pretty).mkString)
		                    log.debug("Adding global attributes: {}", globalAVPList.map(_.pretty).mkString)
		                  }

		                  // Compose the response packet
		                  response <<
		                    proxyAVPList <<
		                    noAddonAVPList <<
		                    noServiceAVPList <<
		                    noRealmAVPList <<
		                    noGlobalAVPList <<?
		                    addonAVPList <<?
		                    serviceAVPList <<?
		                    realmAVPList <<?
		                    globalAVPList <<
		                    ("Class" -> s"S:${fServiceNameOption.getOrElse("none")}") <<
		                    ("Class" -> s"C:${legacyClientIdOption.getOrElse("not-found")}")

		                  if(fAddonServiceNameOption.isDefined) response << ("Class" -> s"A:${fAddonServiceNameOption.getOrElse("none")}")
		                  if(ipAddressOption.isDefined) response <:< ("Framed-IP-Address" -> ipAddressOption.get)                           // With Override
		                  if(delegatedIpv6PrefixOption.isDefined) response <:< ("Delegated-IPv6-Prefix" -> delegatedIpv6PrefixOption.get)   // With Override
	*/

	l.Debugf("rejectReason: %s, basicProfile: %s, addonProfile: %s", rejectReason, basicProfile, addonProfile)

	response := radiuscodec.NewRadiusResponse(request, true)

	// Echo all attributes
	for i := range request.AVPs {
		response.AddAVP(&request.AVPs[i])
	}

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
func findClient(userName string, accessPort int64, accessId string, hl *config.HandlerLogger) (ClientPoU, error) {

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
