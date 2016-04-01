#!/usr/bin/env bash

# **gbp.sh**

# Sanity check that gbp started if enabled

echo "*********************************************************************"
echo "Begin DevStack Exercise: $0"
echo "*********************************************************************"

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following allowing as the install occurs.
set -o xtrace


# Settings
# ========

# Keep track of the current directory
EXERCISE_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $EXERCISE_DIR/..; pwd)

# Import common functions
source $TOP_DIR/functions

# Import configuration
source $TOP_DIR/openrc

# Import exercise configuration
source $TOP_DIR/exerciserc

source $TOP_DIR/openrc demo demo

function confirm_server_active {
    local VM_UUID=$1
    if ! timeout $ACTIVE_TIMEOUT sh -c "while ! nova show $VM_UUID | grep status | grep -q ACTIVE; do sleep 1; done"; then
        echo "server '$VM_UUID' did not become active!"
        false
    fi
}

# Create allow action that can used in several rules
gbp policy-action-create allow --action-type allow

# Create ICMP rule
gbp policy-classifier-create icmp-traffic --protocol icmp --direction bi
gbp policy-rule-create ping-policy-rule --classifier icmp-traffic --actions allow

# Create SSH Rule (Optional)
# gbp policy-classifier-create ssh-traffic --protocol tcp --port-range 22 --direction bi
# gbp policy-rule-create ssh-policy-rule --classifier ssh-traffic --actions allow

# Create HTTP Rule
gbp policy-classifier-create web-traffic --protocol tcp --port-range 80 --direction in
gbp policy-rule-create web-policy-rule --classifier web-traffic --actions allow

# Create HTTPs Rule
gbp policy-classifier-create secure-web-traffic --protocol tcp --port-range 443 --direction in
gbp policy-rule-create secure-web-policy-rule --classifier secure-web-traffic --actions allow

# ICMP policy-rule-set
gbp policy-rule-set-create icmp-policy-rule-set --policy-rules ping-policy-rule

# WEB policy-rule-set
gbp policy-rule-set-create web-policy-rule-set --policy-rules web-policy-rule

# ====== PROJECT OPERATION ======
# PTGs creation
gbp group-create  web
gbp group-create  client-1
gbp group-create  client-2

# PT creation
WEB_PORT=$(gbp policy-target-create web-pt-1 --policy-target-group web | awk "/port_id/ {print \$4}")
CLIENT1_PORT=$(gbp policy-target-create client-pt-1 --policy-target-group client-1 | awk "/port_id/ {print \$4}")
CLIENT2_PORT=$(gbp policy-target-create client-pt-2 --policy-target-group client-2 | awk "/port_id/ {print \$4}")

WEB_VM_1_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$WEB_PORT web-vm-1 | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO WEB_VM_1_UUID "Failure launching web-vm-1"
confirm_server_active $WEB_VM_1_UUID

CLIENT_VM_1_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$CLIENT1_PORT client-vm-1 | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO CLIENT_VM_1_UUID "Failure launching client-vm-1"
confirm_server_active $CLIENT_VM_1_UUID

CLIENT_VM_2_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$CLIENT2_PORT client-vm-2 | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO CLIENT_VM_2_UUID "Failure launching client-vm-2"
confirm_server_active $CLIENT_VM_2_UUID

####CHECKPOINT: No traffic flows

# policy-rule-set Association
gbp group-update client-1 --consumed-policy-rule-sets "icmp-policy-rule-set=scope,web-policy-rule-set=scope"
gbp group-update client-2 --consumed-policy-rule-sets "icmp-policy-rule-set=scope,web-policy-rule-set=scope"
gbp group-update web --provided-policy-rule-sets "icmp-policy-rule-set=scope,web-policy-rule-set=scope"

####CHECKPOINT: ICMP and HTTP work from app to web and vice versa

gbp policy-rule-set-update web-policy-rule-set --policy-rules "secure-web-policy-rule"

####CHECKPOINT: HTTP stops working for both the client PTGs, HTTPs is now enabled

nova delete web-vm-1
nova delete client-vm-1
nova delete client-vm-2

if ! timeout $TERMINATE_TIMEOUT sh -c "while nova list | grep -q ACTIVE; do sleep 1; done"; then
    die $LINENO "Some VMs failed to shutdown"
fi

gbp policy-target-delete web-pt-1
gbp policy-target-delete client-pt-1
gbp policy-target-delete client-pt-2

gbp group-delete  web
gbp group-delete  client-1
gbp group-delete  client-2

gbp policy-rule-set-delete icmp-policy-rule-set
gbp policy-rule-set-delete web-policy-rule-set

gbp policy-rule-delete secure-web-policy-rule
gbp policy-rule-delete web-policy-rule
gbp policy-rule-delete ping-policy-rule

gbp policy-classifier-delete secure-web-traffic
gbp policy-classifier-delete web-traffic
gbp policy-classifier-delete icmp-traffic

gbp policy-action-delete allow

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End DevStack Exercise: $0"
echo "*********************************************************************"
