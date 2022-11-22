package psbahandlers

import (
	"database/sql"

	"github.com/francistor/igor/config"
	"github.com/francistor/igor/radiuscodec"
)

func AccessRequestHandler(request *radiuscodec.RadiusPacket, ctx *RequestContext, hl *config.HandlerLogger) (*radiuscodec.RadiusPacket, error) {

	// For logging
	l := hl.L

	// We signal that the client is to be rejected by providing a value to this variable, that is used also in the Reply-Message
	var rejectReason string

	// Find the user
	clientpou, err := findClient(ctx.userName, ctx.accessPort, ctx.accessId, hl)
	if err != nil {
		// No answer
		return nil, err
	}

	if clientpou.ClientId != 0 {
		l.Debugf("client found %#v\n", clientpou)
		l.Debug(clientpou.NotificationExpDate.Format("2006-01-02T15:04:05 MST"))
	} else {
		l.Debug("client not found\n")
		// If permissiveProfile is defined, we assign that one. Otherwise, signal rejection
		if ctx.config.PermissiveProfile != "" {
			l.Debugf("assigning permissive profile <%s>", ctx.config.PermissiveProfile)
			clientpou.AccessId = ctx.accessId
			clientpou.AccessPort = ctx.accessPort
			clientpou.UserName = ctx.userName
			clientpou.PlanName = ctx.config.PermissiveProfile
		} else {
			rejectReason = "not found"
		}
	}

	println(rejectReason)

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
