package psbahandlers

import "time"

type Client struct {
	ClientId                    int
	ExternalClientId            string
	ContractId                  string
	PersonalId                  string
	SecondaryId                 string
	ISP                         string
	BillingCycle                int
	PlanName                    string
	BlockingStatus              int
	PlanOverride                string
	PlanOverrideExpDate         time.Time
	AddonProfileOverride        string
	AddonProfileOverrideExpDate time.Time
	NotificationExpDate         time.Time
	Parameters                  string
}

type PoU struct {
	PoUId               int
	ClientIdRef         int
	AccessPort          int64
	AccessId            string
	UserName            string
	Password            string
	IPv4Address         string
	IPv6DelegatedPrefix string
	IPv6WANPrefix       string
	AccessType          int
	CheckType           int
}

type ClientPoU struct {
	ClientId                    int
	ExternalClientId            string
	ISP                         string
	PlanName                    string
	BlockingStatus              int
	PlanOverride                string
	PlanOverrideExpDate         time.Time
	AddonProfileOverride        string
	AddonProfileOverrideExpDate time.Time
	NotificationExpDate         time.Time
	Parameters                  string
	AccessPort                  int64
	AccessId                    string
	UserName                    string
	Password                    string
	IPv4Address                 string
	IPv6DelegatedPrefix         string
	IPv6WANPrefix               string
	AccessType                  int
	CheckType                   int
}
