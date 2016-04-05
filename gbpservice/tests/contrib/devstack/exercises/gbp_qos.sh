#!/usr/bin/env bash

# **gbp.sh**

# Sanity check that gbp started if enabled

echo "*********************************************************************"
echo "Begin DevStack Exercise: $0"
echo "*********************************************************************"

# Settings
# ========

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

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

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following allowing as the install occurs.
set -o xtrace

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

# ICMP policy-rule-set
gbp policy-rule-set-create icmp-policy-rule-set --policy-rules ping-policy-rule

# ====== PROJECT OPERATION ======
# PTGs creation
gbp group-create limited
gbp group-create unlimited

# PT creation
PORT1=$(gbp policy-target-create port1-pt --policy-target-group limited | awk "/port_id/ {print \$4}")
PORT2=$(gbp policy-target-create port2-pt --policy-target-group limited | awk "/port_id/ {print \$4}")
PORT3=$(gbp policy-target-create port3-pt --policy-target-group unlimited | awk "/port_id/ {print \$4}")
PORT4=$(gbp policy-target-create port4-pt --policy-target-group unlimited | awk "/port_id/ {print \$4}")

PORT1_VM_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$PORT1 port1-vm | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO PORT1_VM_UUID "Failure launching port1-vm"
confirm_server_active $PORT1_VM_UUID

PORT2_VM_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$PORT2 port2-vm | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO PORT2_VM_UUID "Failure launching port2-vm"
confirm_server_active $PORT2_VM_UUID

PORT3_VM_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$PORT3 port3-vm | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO PORT3_VM_UUID "Failure launching port3-vm"
confirm_server_active $PORT3_VM_UUID

PORT4_VM_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$PORT4 port4-vm | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO PORT4_VM_UUID "Failure launching port4-vm"
confirm_server_active $PORT4_VM_UUID

####CHECKPOINT: No traffic flows between groups and no QoS applied

# policy-rule-set Association
gbp group-update limited --consumed-policy-rule-sets "icmp-policy-rule-set"
gbp group-update unlimited --provided-policy-rule-sets "icmp-policy-rule-set"

####CHECKPOINT: ICMP now flows between each group, but still no QoS applied

# Create Network Service Policy that includes QoS parameters
gbp network-service-policy-create --network-service-params type=qos_burstrate,name=qos_burstrate,value=500 --network-service-params type=qos_maxrate,name=qos_maxrate,value=8000 "qos"

# Limit every PT in the limited PTG by associating the "qos" NSP created right before
gbp group-update limited --network-service-policy "qos"

####CHECKPOINT: Both port1-pt and port2-pt will not be able to exceed 8 Mbps with a burst rate of 500 Kb

nova delete port4-vm
nova delete port3-vm
nova delete port2-vm
nova delete port1-vm

if ! timeout $TERMINATE_TIMEOUT sh -c "while nova list | grep -q ACTIVE; do sleep 1; done"; then
    die $LINENO "Some VMs failed to shutdown"
fi

gbp policy-target-delete port4-pt
gbp policy-target-delete port3-pt
gbp policy-target-delete port2-pt
gbp policy-target-delete port1-pt

gbp group-delete unlimited
gbp group-delete limited

gbp policy-rule-set-delete icmp-policy-rule-set

gbp policy-rule-delete ping-policy-rule

gbp policy-classifier-delete icmp-traffic

gbp policy-action-delete allow

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End DevStack Exercise: $0"
echo "*********************************************************************"
