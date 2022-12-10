# --------------------------------------------------------------
# Simple Access-Accept test for Radius
# --------------------------------------------------------------

export _THIS_FILE_DIRNAME=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source $_THIS_FILE_DIRNAME/env.rc

# Test parameters
REQUESTFILE=$_THIS_FILE_DIRNAME/AccessRequest.txt

COUNT=1
LOGLEVEL=info

# Delete Garbage
rm $_THIS_FILE_DIRNAME/out/*

# Diameter CCR -------------------------------------------------------------
echo 
echo Access-Request
echo

echo User-Name = \"francisco@database.provision.nopermissive.doreject.block_addon.noproxy\" > $REQUESTFILE
echo User-Password = \"francisco\" >> $REQUESTFILE
echo NAS-Port = 1 >> $REQUESTFILE
echo NAS-IP-Address = \"127.0.0.1\" >> $REQUESTFILE

# Send the packet
# -overlap <number of simultaneous requests>
$RADIUS -debug $LOGLEVEL -retryCount 1 -count $COUNT -remoteAddress 127.0.0.1:1812 -code Access-Request -request "@$REQUESTFILE" $*