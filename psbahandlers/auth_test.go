package psbahandlers

import (
	"fmt"
	"testing"
	"time"

	"github.com/francistor/igor/core"
	"github.com/francistor/igor/router"
)

func TestSinglePacket(t *testing.T) {

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 1).
		Add("User-Name", "francisco@database.provision.nopermissive.doreject.block_addon.proxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@database.provision.nopermissive.doreject.block_addon.proxy"},
		{"avp is", "Igor-OctetsAttribute", "01"},
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"},
	}

	testInvoker.testCaseRaw(t, "Smoke test", checks, &rrr)
}

func TestAuthorizationTypes(t *testing.T) {

	domain := "database.provision.nopermissive.doreject.block_addon.proxy"
	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: database
	// Authlocal: provision

	// No user or password in database.
	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 1).
		Add("User-Name", "francisco@"+domain)

	rrr.Packet = requestPacket1

	// Unisphere-Virtual-Router --> From realm configuration
	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},                    // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                          // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                           // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                               // Service-Type is Login --> Forced when sent to proxy
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},        // HW-Output-Commited-Information-Rate --> Client found, plan found, template with basic profile executed
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"}, // Cisco AVPair subscriber:sa --> Nonoverridable attributes in basic profile
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},               // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                             // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-1"},               // Virtual Router from realm configuration
		{"cisco avpair is", "realm", domain},                              // AVPair from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                    // Attribute sent by proxy
	}

	testInvoker.testCaseRaw(t, "01 simple access request, no password", checks, &rrr)

	// Password in database. Good password
	requestPacket2 := requestPacket.Copy(nil, nil).
		Add("User-Name", "francisco@"+domain).
		Add("NAS-Port", 2).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket2
	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},
		{"avp is", "Igor-OctetsAttribute", "01"},
	}

	testInvoker.testCaseRaw(t, "02 simple access request, good password", checks, &rrr)

	// Password in database. Wrong password
	requestPacket3 := requestPacket.Copy(nil, nil).
		Add("User-Name", "francisco@"+domain).
		Add("NAS-Port", 2).
		Add("User-Password", []byte("bad"))

	rrr.Packet = requestPacket3
	checks = []TestCheck{
		{"code is", "", "3"},
		{"avp contains", "Reply-Message", "rejected"},
	}

	testInvoker.testCaseRaw(t, "03 simple access request, wrong password", checks, &rrr)

	// Both username and password in database. Both are OK
	requestPacket4 := requestPacket.Copy(nil, nil).
		Add("User-Name", "francisco@"+domain).
		Add("NAS-Port", 4).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket4
	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},
		{"avp is", "Igor-OctetsAttribute", "01"},
	}

	testInvoker.testCaseRaw(t, "04 simple access request, good username and password", checks, &rrr)

	// Both username and password in database. Username not matching
	requestPacket5 := requestPacket.Copy(nil, nil).
		Add("User-Name", "bad@"+domain).
		Add("NAS-Port", 4).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket5
	checks = []TestCheck{
		{"code is", "", "3"},
		{"avp contains", "Reply-Message", "unmatch"},
	}

	testInvoker.testCaseRaw(t, "05 simple access request, bad username", checks, &rrr)
}

func TestBlockedUser(t *testing.T) {

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: database
	// Authlocal: provision

	// Blocked with addon
	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 5).
		Add("User-Name", "francisco@database.provision.nopermissive.doreject.block_addon.proxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@database.provision.nopermissive.doreject.block_addon.proxy"}, // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                                                        // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                                                         // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                                                             // Service-Type is Login --> Forced when sent to proxy
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},                                      // HW-Output-Commited-Information-Rate --> Client found, plan found, template with basic profile executed
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"},                               // Cisco AVPair subscriber:sa --> Nonoverridable attributes in basic profile
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},                                             // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                                                           // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-1"},                                             // Virtual Router from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                                                  // Attribute sent by proxy

		{"avp-is", "Unisphere-Service-Bundle", "Apcautiv"}, // Addon pcautiv service
	}

	testInvoker.testCaseRaw(t, "01 blocked with addon", checks, &rrr)

	// Blocked as basic service
	requestPacket2 := requestPacket.Copy(nil, nil).
		Replace("User-Name", "francisco@database.provision.nopermissive.noreject.block_basic.proxy").
		Add("NAS-Port", 5)

	rrr.Packet = requestPacket2
	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@database.provision.nopermissive.noreject.block_basic.proxy"}, // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                                                        // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                                                         // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                                                             // Service-Type is Login --> Forced when sent to proxy
		{"avp notpresent", "HW-Output-Committed-Information-Rate", ""},                                  // HW-Output-Commited-Information-Rate --> Not present because basic service has been replaced
		{"cisco avpair notpresent", "subscriber:sa", ""},                                                // Cisco AVPair subscriber:sa --> Not present because basic service has been replaced
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},                                             // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                                                           // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-2"},                                             // Virtual Router from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                                                  // Attribute sent by proxy
		{"avp is", "Unisphere-Service-Bundle", "Apcautiv"},                                              // Basic pcautiv service
	}

	testInvoker.testCaseRaw(t, "02 blocked as basic", checks, &rrr)
}

func TestRejectedUser(t *testing.T) {

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: database
	// Authlocal: provision

	// Rejected with Access-Reject
	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 5).
		Add("User-Name", "rejected@database.provision.nopermissive.doreject.block_addon.proxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "3"},
		{"avp contains", "Reply-Message", "upstream"},
	}

	testInvoker.testCaseRaw(t, "01 rejected with access-reject", checks, &rrr)

	// Rejected with basic service
	requestPacket2 := requestPacket.Copy(nil, nil).
		Replace("User-Name", "reject@database.provision.nopermissive.noreject.block_basic.proxy")

	rrr.Packet = requestPacket2
	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp notpresent", "User-Name", ""},
		{"avp notpresent", "Igor-OctetsAttribute", ""},
		{"avp notpresent", "User-Password", ""},
		{"avp notpresent", "Service-Type", "Login"},
		{"avp notpresent", "HW-Output-Committed-Information-Rate", ""}, // HW-Output-Commited-Information-Rate --> Not present because basic service has been replaced
		{"cisco avpair notpresent", "subscriber:sa", ""},               // Cisco AVPair subscriber:sa --> Not present because basic service has been replaced
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},            // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                          // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-2"},            // Virtual Router from realm configuration
		{"avp notpresent", "Framed-IP-Address", ""},                    // Framed IP Address not generated by proxy
		{"avp-is", "Unisphere-Service-Bundle", "Areject"},              // Basic pcautiv service
	}

	testInvoker.testCaseRaw(t, "02 rejected with basic replacement", checks, &rrr)
}

func TestUserNotFound(t *testing.T) {

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: database
	// Authlocal: provision

	// Rejected with Access-Reject

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 9999).
		Add("User-Name", "francisco@database.provision.nopermissive.doreject.block_addon.proxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "3"},
		{"avp contains", "Reply-Message", "not found"},
	}

	testInvoker.testCaseRaw(t, "01 user not found is rejected", checks, &rrr)

	// Not found assigns permissive service
	requestPacket2 := requestPacket.Copy(nil, nil).
		Replace("User-Name", "francisco@database.provision.permissive.noreject.block_basic.proxy")

	rrr.Packet = requestPacket2
	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@database.provision.permissive.noreject.block_basic.proxy"}, // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                                                      // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                                                       // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                                                           // Service-Type is Login --> Forced when sent to proxy
		{"avp notpresent", "HW-Output-Committed-Information-Rate", ""},                                // Client not found, permissive service does not include this attribute
		{"cisco avpair notpresent", "subscriber:sa", ""},                                              // Client not found, permissive service does not include this attribute
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},                                           // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                                                         // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-3"},                                           // Virtual Router from realm configuration
		{"cisco avpair is", "realm", "database.provision.permissive.noreject.block_basic.proxy"},      // AVPair from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                                                // Attribute sent by proxy
		{"avp is", "HW-Account-Info", "Apermissive"},                                                  // permissive service attribute
	}

	testInvoker.testCaseRaw(t, "02 not found with permissive service", checks, &rrr)
}

func TestProvisionSpecialUser(t *testing.T) {

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: file
	// Authlocal: provision

	// User without plan

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 9999).
		Add("User-Name", "user1@file.provision.permissive.noreject.block_basic.noproxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp notpresent", "User-Name", ""},                                                    // Not proxied
		{"avp notpresent", "Igor-OctetsAttribute", ""},                                         // Not proxied
		{"avp notpresent", "User-Password", ""},                                                // Not proxied
		{"avp notpresent", "Service-Type", "Login"},                                            // Not proxied
		{"avp notpresent", "HW-Output-Committed-Information-Rate", ""},                         // No plan
		{"cisco avpair notpresent", "subscriber:sa", ""},                                       // No plan
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},                                    // Radius attributes in global config
		{"cisco avpair is", "global", "true"},                                                  // Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-4"},                                    // Virtual Router from realm configuration
		{"cisco avpair is", "realm", "file.provision.permissive.noreject.block_basic.noproxy"}, // AVPair from realm configuration
		{"avp notpresent", "Framed-IP-Address", ""},                                            // Not proxied
		{"avp is", "Filter-Id", "user1@file"},                                                  // permissive service attribute
		{"avp is", "Idle-Timeout", "3600"},                                                     // permissive service attribute
	}

	testInvoker.testCaseRaw(t, "01 provision in file without plan", checks, &rrr)

	// User with plan
	requestPacket2 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 9999).
		Add("User-Name", "user2@file.provision.permissive.noreject.block_basic.noproxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket2

	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp notpresent", "User-Name", ""},                                                    // Not proxied
		{"avp notpresent", "Igor-OctetsAttribute", ""},                                         // Not proxied
		{"avp notpresent", "User-Password", ""},                                                // Not proxied
		{"avp notpresent", "Service-Type", "Login"},                                            // Not proxied
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},                             // From plan
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"},                      // From plan
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},                                    // Radius attributes in global config
		{"cisco avpair is", "global", "true"},                                                  // Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-4"},                                    // Virtual Router from realm configuration
		{"cisco avpair is", "realm", "file.provision.permissive.noreject.block_basic.noproxy"}, // AVPair from realm configuration
		{"avp notpresent", "Framed-IP-Address", ""},                                            // Not proxied
		{"avp is", "Filter-Id", "user2@file"},                                                  // From user file
		{"avp is", "Idle-Timeout", "3600"},                                                     // From realm
	}

	testInvoker.testCaseRaw(t, "02 provision in file with plan", checks, &rrr)

	// User not found. Assigned permissive service
	requestPacket3 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 9999).
		Add("User-Name", "bad@file.provision.permissive.noreject.block_basic.noproxy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket3

	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp notpresent", "User-Name", ""},                                                    // Not proxied
		{"avp notpresent", "Igor-OctetsAttribute", ""},                                         // Not proxied
		{"avp notpresent", "User-Password", ""},                                                // Not proxied
		{"avp notpresent", "Service-Type", "Login"},                                            // Not proxied
		{"avp notpresent", "HW-Output-Committed-Information-Rate", ""},                         // User not found
		{"cisco avpair notpresent", "subscriber:sa", ""},                                       // User not found
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},                                    // Radius attributes in global config
		{"cisco avpair is", "global", "true"},                                                  // Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-4"},                                    // Virtual Router from realm configuration
		{"cisco avpair is", "realm", "file.provision.permissive.noreject.block_basic.noproxy"}, // AVPair from realm configuration
		{"avp notpresent", "Framed-IP-Address", ""},                                            // Not proxied
		{"avp is", "Unisphere-Service-Bundle", "Apermissive"},                                  // Permissive service
	}

	testInvoker.testCaseRaw(t, "03 provision in file not found with permissive", checks, &rrr)
}

func TestAuthLocalFileBetatester(t *testing.T) {
	var passwordBytes = fmt.Sprintf("%x", []byte("secret"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: databae
	// Authlocal: file

	// User without plan

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 4). // Line has both login and password, but not taken into account becasuse authLocal is "file"
		Add("User-Name", "betatester@database.file.nopermissive.reject.block_reject.noproxy.betatester").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},                                                                              // Password validated from file
		{"avp notpresent", "User-Name", ""},                                                               // Not proxied
		{"avp notpresent", "Igor-OctetsAttribute", ""},                                                    // Not proxied
		{"avp notpresent", "User-Password", ""},                                                           // Not proxied
		{"avp notpresent", "Service-Type", "Login"},                                                       // Not proxied
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},                                        // From user plan
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"},                                 // From user plan
		{"cisco avpair is", "global", "true"},                                                             // Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-5"},                                               // Virtual Router from realm configuration
		{"cisco avpair is", "realm", "database.file.nopermissive.reject.block_reject.noproxy.betatester"}, // AVPair from realm configuration
		{"avp notpresent", "Framed-IP-Address", ""},                                                       // Not proxied
	}

	testInvoker.testCaseRaw(t, "01 betatester with correct password", checks, &rrr)

}

func TestAuthLocalFileWithOverrideSpeedy(t *testing.T) {
	var passwordBytes = fmt.Sprintf("%x", []byte("secret"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: databae
	// Authlocal: file

	// User without plan

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 4). // Line has both login and password, but not taken into account becasuse authLocal is "file"
		Add("User-Name", "speedy@database.file.nopermissive.reject.block_reject.noproxy.speedy").
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},                                                                          // Password validated from file
		{"avp notpresent", "User-Name", ""},                                                           // Not proxied
		{"avp notpresent", "Igor-OctetsAttribute", ""},                                                // Not proxied
		{"avp notpresent", "User-Password", ""},                                                       // Not proxied
		{"avp notpresent", "Service-Type", "Login"},                                                   // Not proxied
		{"avp notpresent", "HW-Output-Committed-Information-Rate", ""},                                // Plan profile overriden
		{"cisco avpair notpresent", "subscriber:sa", ""},                                              // Plan profile overriden
		{"cisco avpair is", "global", "true"},                                                         // Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-5"},                                           // Virtual Router from realm configuration
		{"cisco avpair is", "realm", "database.file.nopermissive.reject.block_reject.noproxy.speedy"}, // AVPair from realm configuration
		{"avp notpresent", "Framed-IP-Address", ""},                                                   // Not proxied
		{"avp is", "Unisphere-Service-Bundle", "Aspeedy"},                                             // From realm profile
	}

	testInvoker.testCaseRaw(t, "01 betatester with correct password", checks, &rrr)
}

func TestNotification(t *testing.T) {

	domain := "database.provision.nopermissive.doreject.block_addon.proxy"

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: databae
	// Authlocal: file

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 6). // Line with notification
		Add("User-Name", "francisco@"+domain).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},                    // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                          // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                           // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                               // Service-Type is Login --> Forced when sent to proxy
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},        // HW-Output-Commited-Information-Rate --> Client found, plan found, template with basic profile executed
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"}, // Cisco AVPair subscriber:sa --> Nonoverridable attributes in basic profile
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},               // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                             // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-1"},               // Virtual Router from realm configuration
		{"cisco avpair is", "realm", domain},                              // AVPair from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                    // Attribute sent by proxy
		{"avp is", "Unisphere-Service-Bundle", "Apubli"},                  // Notification addon
	}

	testInvoker.testCaseRaw(t, "01 notification addon", checks, &rrr)

	// If user is blocked, notification addon does not apply
	requestPacket2 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 5). // Line with notification
		Add("User-Name", "francisco@"+domain).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket2

	checks = []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},                    // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                          // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                           // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                               // Service-Type is Login --> Forced when sent to proxy
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},        // HW-Output-Commited-Information-Rate --> Client found, plan found, template with basic profile executed
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"}, // Cisco AVPair subscriber:sa --> Nonoverridable attributes in basic profile
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},               // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                             // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-1"},               // Virtual Router from realm configuration
		{"cisco avpair is", "realm", domain},                              // AVPair from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                    // Attribute sent by proxy
		{"avp is", "Unisphere-Service-Bundle", "Apcautiv"},                // Blocking addon
	}

	testInvoker.testCaseRaw(t, "02 notification addon in blocked with addon", checks, &rrr)

}

func TestPlanOverride(t *testing.T) {

	domain := "database.provision.nopermissive.doreject.block_addon.proxy"

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: databae
	// Authlocal: file

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 7). // Line with plan override
		Add("User-Name", "francisco@"+domain).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},                    // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                          // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                           // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                               // Service-Type is Login --> Forced when sent to proxy
		{"avp is", "HW-Output-Committed-Information-Rate", "2000"},        // Overriden plan
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=2000)"}, // Overriden plan
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},               // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                             // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-1"},               // Virtual Router from realm configuration
		{"cisco avpair is", "realm", domain},                              // AVPair from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                    // Attribute sent by proxy
	}

	testInvoker.testCaseRaw(t, "01 Plan override", checks, &rrr)
}

func TestAddonOverride(t *testing.T) {

	domain := "database.provision.nopermissive.doreject.block_addon.proxy"

	var passwordBytes = fmt.Sprintf("%x", []byte("francisco"))

	requestPacket := core.NewRadiusRequest(core.ACCESS_REQUEST).
		Add("NAS-IP-Address", "127.0.0.1").
		Add("Igor-OctetsAttribute", "01")

	rrr := router.RoutableRadiusRequest{
		Destination:       "psba-server-group",
		PerRequestTimeout: 1 * time.Second,
		Tries:             1,
		ServerTries:       1,
		Packet:            requestPacket,
	}

	// Provision: databae
	// Authlocal: file

	requestPacket1 := requestPacket.Copy(nil, nil).
		Add("NAS-Port", 8). // Line with addon override
		Add("User-Name", "francisco@"+domain).
		Add("User-Password", passwordBytes)

	rrr.Packet = requestPacket1

	checks := []TestCheck{
		{"code is", "", "2"},
		{"avp is", "User-Name", "francisco@" + domain},                    // Username echoed --> Has been sent to proxy
		{"avp is", "Igor-OctetsAttribute", "01"},                          // IgorOctets echoed --> Has been sent to proxy
		{"avp notpresent", "User-Password", ""},                           // User-Password not present --> Filtered in response from proxy
		{"avp is", "Service-Type", "Login"},                               // Service-Type is Login --> Forced when sent to proxy
		{"avp is", "HW-Output-Committed-Information-Rate", "1000"},        // Overriden plan
		{"cisco avpair is", "subscriber:sa", "internet(shape-rate=1000)"}, // Overriden plan
		{"avp is", "Redback-Client-DNS-Primary", "8.8.8.8"},               // DNS-Primary --> Radius attributes in global config
		{"cisco avpair is", "global", "true"},                             // Cisco AVPair global --> Nonoverridable attributes in global config
		{"avp is", "Unisphere-Virtual-Router", "vrouter-1"},               // Virtual Router from realm configuration
		{"cisco avpair is", "realm", domain},                              // AVPair from realm configuration
		{"avp is", "Framed-IP-Address", "10.10.10.10"},                    // Attribute sent by proxy
		{"avp is", "Unisphere-Service-Bundle", "Avala"},                   // Addon
	}

	testInvoker.testCaseRaw(t, "01 Addon override", checks, &rrr)
}
