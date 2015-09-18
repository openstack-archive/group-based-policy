#!/usr/bin/env bash

# **gbp_fip.sh**

# Sanity check that gbp fip support works if enabled

echo "*********************************************************************"
echo "Begin DevStack Exercise: $0"
echo "*********************************************************************"

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

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

source $TOP_DIR/openrc admin admin

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


EXT_NET_ID=$(neutron net-list --router:external -c id | grep -v id | awk '{print $2}' )
EXT_NET_TO_BE_CLEANED_UP=false

if [ -z "$EXT_NET_ID" ] ; then
    EXT_NET_ID=$(neutron net-create "$PUBLIC_NETWORK_NAME" -- --router:external=True | grep ' id ' | get_field 2)
    EXT_SUBNET_ID=$(neutron subnet-create --ip_version 4 --gateway 172.16.73.1 --name public-subnet $EXT_NET_ID 172.16.73.0/24 | grep ' id ' | get_field 2)
    EXT_NET_TO_BE_CLEANED_UP=true
else
    EXT_NET_ID=$(neutron net-list --router:external -c id | grep -v id | awk '{print $2}' )
    EXT_SUBNET_ID=$(neutron net-show $EXT_NET_ID | grep subnets | awk '{print $4}' )
fi

die_if_not_set $LINENO EXT_SUBNET_ID "Failure creating external network"

EXT_SUBNET_CIDR=$(neutron subnet-show $EXT_SUBNET_ID | grep cidr | awk '{print $4}' )

EXT_SUBNET_GW=$(neutron subnet-show $EXT_SUBNET_ID | grep gateway_ip | awk '{print $4}' )

EXT_SEGMENT_ID=$(gbp external-segment-create --ip-version 4 --external-route destination=0.0.0.0/0,nexthop=$EXT_SUBNET_GW --shared True --subnet_id=$EXT_SUBNET_ID  --cidr $EXT_SUBNET_CIDR default | grep ' id ' | awk '{print $4}' )

die_if_not_set $LINENO EXT_SEGMENT_ID "Failure creating external segment"

NAT_POOL_ID=$(gbp nat-pool-create --ip-version 4 --ip-pool $EXT_SUBNET_CIDR --external-segment $EXT_SEGMENT_ID ext_nat_pool | grep ' id ' | awk '{print $4}' )

die_if_not_set $LINENO NAT_POOL_ID "Failure creating nat pool"

NSP_ID=$(gbp network-service-policy-create --network-service-params type=ip_pool,name=nat_fip,value=nat_pool nat_pool_nsp | grep ' id ' | awk '{print $4}' )

PTG_ID=$(gbp group-create --network-service-policy nat_pool_nsp provider_ptg | grep ' id ' | awk '{print $4}' )

die_if_not_set $LINENO PTG_ID "Failure creating ptg"

PT1_ID=$(gbp policy-target-create --policy-target-group provider_ptg provider_pt1 | grep ' id ' | awk '{print $4}' )

die_if_not_set $LINENO PT1_ID "Failure creating policy target"

PT2_ID=$(gbp policy-target-create --policy-target-group provider_ptg provider_pt2 | grep ' id ' | awk '{print $4}' )

die_if_not_set $LINENO PT2_ID "Failure creating policy target"

PT2_PORT_ID=$(gbp policy-target-show $PT2_ID | grep ' port_id ' | awk '{print $4}' )

PT2_PORT_IP=$(neutron port-show $PT2_PORT_ID | grep ' fixed_ips ' | awk '{print $7}' | awk -F '"' '{print $2}' )

PT2_FIXED_IP=$(neutron floatingip-list | grep $PT2_PORT_IP | awk '{print $4}' )

die_if_not_set $LINENO PT2_FIXED_IP "Floating IP not assigned to policy target"

PT1_PORT_ID=$(gbp policy-target-show $PT1_ID | grep ' port_id ' | awk '{print $4}' )

PT1_PORT_IP=$(neutron port-show $PT1_PORT_ID | grep ' fixed_ips ' | awk '{print $7}' | awk -F '"' '{print $2}' )

PT1_FIXED_IP=$(neutron floatingip-list | grep $PT1_PORT_IP | awk '{print $4}' )

die_if_not_set $LINENO PT1_FIXED_IP "Floating IP not assigned to policy target"



#############Cleanup###############


gbp policy-target-delete $PT2_ID
gbp policy-target-delete $PT1_ID
gbp group-delete $PTG_ID
gbp network-service-policy-delete $NSP_ID
gbp nat-pool-delete $NAT_POOL_ID
gbp external-segment-delete $EXT_SEGMENT_ID

if [ "$EXT_NET_TO_BE_CLEANED_UP" = true ] ; then
    neutron net-delete $EXT_NET_ID
fi

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End DevStack Exercise: $0"
echo "*********************************************************************"
