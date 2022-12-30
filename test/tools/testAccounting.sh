# --------------------------------------------------------------
# Simple Access-Accept test for Radius
# --------------------------------------------------------------

export _THIS_FILE_DIRNAME=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $_THIS_FILE_DIRNAME/env.rc

# Test parameters
REQUESTFILE=$_THIS_FILE_DIRNAME/AccountingRequest.txt

COUNT=1
LOGLEVEL=info

# Delete Garbage
rm $_THIS_FILE_DIRNAME/out/*

# Diameter CCR -------------------------------------------------------------
echo 
echo AccountingRequest
echo

echo Class = \"myClass\" > $REQUESTFILE
echo NAS-Port = 1 >> $REQUESTFILE
echo NAS-IP-Address = \"127.0.0.1\" >> $REQUESTFILE
echo Acct-Session-Id = \"accounting-session-id-1\" >> $REQUESTFILE
echo Acct-Status-Type= \"Start\" >> $REQUESTFILE
echo User-Name= \"TestUser\" >> $REQUESTFILE
# Comment out this for session accounting
#echo Huawei-Service-Info = \"Abasic\" >> $REQUESTFILE

# Send the packet
# -overlap <number of simultaneous requests>
$RADIUS -debug $LOGLEVEL -retryCount 1 -count $COUNT -remoteAddress 127.0.0.1:1812 -code Accounting-Request -request "@$REQUESTFILE" $*