#!/usr/bin/env bash

# **gbp_purge.sh**

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

# Create allow action that can used in several rules
gbp policy-action-create allow --action-type allow

# Create ICMP rule
gbp policy-classifier-create icmp-traffic --protocol icmp --direction bi
gbp policy-rule-create ping-policy-rule --classifier icmp-traffic --actions allow

# ICMP policy-rule-set
gbp policy-rule-set-create icmp-policy-rule-set --policy-rules ping-policy-rule

# ====== PROJECT OPERATION ======
# PTGs creation
gbp group-create --provided-policy-rule-sets "icmp-policy-rule-set" --consumed-policy-rule-sets "icmp-policy-rule-set" web

# PT creation
gbp policy-target-create web-pt-1 --policy-target-group web

# ES creation
EXT_NET_ID=$(neutron net-create mgmt_out --router:external=True | grep ' id ' | awk '{print $4}')
EXT_SUBNET_ID=$(neutron subnet-create --ip_version 4 --gateway 172.16.73.1 --name public-subnet $EXT_NET_ID 172.16.73.0/24 | grep ' id ' | awk '{print $4}')
gbp external-segment-create --ip-version 4 --external-route destination=0.0.0.0/0,nexthop=172.16.73.1 --shared True --subnet_id=$EXT_SUBNET_ID  --cidr 50.50.50.0/24 mgmt_out

gbp l3policy-update --external-segment mgmt_out default

# Nat pool creation
gbp nat-pool-create --ip-version 4 --ip-pool 60.60.60.0/24 --external-segment mgmt_out ext_nat_pool

# External policy creation
gbp external-policy-create --external-segment mgmt_out --provided-policy-rule-sets "icmp-policy-rule-set" --consumed-policy-rule-sets "icmp-policy-rule-set" ext_pol

# NSP creation
gbp network-service-policy-create --network-service-params type=ip_pool,name=nat_fip,value=nat_pool nat_pool_nsp

# purge all the resources
DEMO_PROJECT_ID=$(keystone tenant-list | grep demo | awk '{print $2}')
gbp purge $DEMO_PROJECT_ID

# delete the neutron resources too
neutron subnet-delete public-subnet
neutron net-delete mgmt_out

PURGE_OUTPUT=$(gbp purge $DEMO_PROJECT_ID | grep 'Tenant has no supported resources')
die_if_not_set $LINENO PURGE_OUTPUT "Failure purging GBP resources"

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End DevStack Exercise: $0"
echo "*********************************************************************"
