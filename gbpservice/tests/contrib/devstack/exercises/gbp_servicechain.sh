#!/usr/bin/env bash

# **gbp_servicechain.sh**

# Sanity check that gbp servicechain plugin started if enabled

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

source $TOP_DIR/openrc demo demo

# Print the commands being run so that we can see the command that triggers
# an error.  It is also useful for following redirecting as the install occurs.
set -o xtrace

function confirm_server_active {
    local VM_UUID=$1
    if ! timeout $ACTIVE_TIMEOUT sh -c "while ! nova show $VM_UUID | grep status | grep -q ACTIVE; do sleep 1; done"; then
        echo "server '$VM_UUID' did not become active!"
        false
    fi
}


gbp service-profile-create --vendor heat_based_node_driver --insertion-mode l3 --servicetype FIREWALL fw-profile
gbp service-profile-create --vendor heat_based_node_driver --insertion-mode l3 --servicetype LOADBALANCER lb-profile

gbp  servicechain-node-create loadbalancer-node --template-file $TOP_DIR/gbp-templates/firewall-lb-servicechain/lb.template --service-profile lb-profile
gbp  servicechain-node-create firewall-node --template-file $TOP_DIR/gbp-templates/firewall-lb-servicechain/fw.template  --service-profile fw-profile

gbp servicechain-spec-create firewall-loadbalancer-spec --description spec --nodes "firewall-node loadbalancer-node"

gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet vip_ip_policy

# Create allow action that can used in several rules
gbp policy-action-create allow --action-type allow

# Create redirect action that can used in several rules
gbp policy-action-create redirect --action-type redirect --action-value firewall-loadbalancer-spec

# Create ICMP rule
gbp policy-classifier-create icmp-traffic --protocol icmp --direction bi
gbp policy-rule-create ping-policy-rule --classifier icmp-traffic --actions allow

# Create SSH Rule (Optional)
# gbp policy-classifier-create ssh-traffic --protocol tcp --port-range 22 --direction bi
# gbp policy-rule-create ssh-policy-rule --classifier ssh-traffic --actions allow

# Create HTTP Rule
gbp policy-classifier-create web-traffic --protocol tcp --port-range 80 --direction in
gbp policy-rule-create web-policy-rule --classifier web-traffic --actions redirect

# Create HTTPs Rule
gbp policy-classifier-create secure-web-traffic --protocol tcp --port-range 443 --direction in
gbp policy-rule-create secure-web-policy-rule --classifier secure-web-traffic --actions redirect

# ICMP policy-rule-set
gbp policy-rule-set-create icmp-policy-rule-set --policy-rules ping-policy-rule

# WEB policy-rule-set
gbp policy-rule-set-create web-policy-rule-set --policy-rules web-policy-rule

# ====== PROJECT OPERATION ======
# PTGs creation
gbp group-create  web
gbp group-create  client-1

# PT creation
WEB_PORT=$(gbp policy-target-create web-pt-1 --policy-target-group web | awk "/port_id/ {print \$4}")
CLIENT1_PORT=$(gbp policy-target-create client-pt-1 --policy-target-group client-1 | awk "/port_id/ {print \$4}")

##TODO(Magesh): Add traffic testing and use namespace ports instead of launching VMs
WEB_VM_1_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$WEB_PORT web-vm-1 | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO WEB_VM_1_UUID "Failure launching web-vm-1"
confirm_server_active $WEB_VM_1_UUID

CLIENT_VM_1_UUID=`nova boot --flavor m1.tiny --image $DEFAULT_IMAGE_NAME --nic port-id=$CLIENT1_PORT client-vm-1 | grep ' id ' | cut -d"|" -f3 | sed 's/ //g'`
die_if_not_set $LINENO CLIENT_VM_1_UUID "Failure launching client-vm-1"
confirm_server_active $CLIENT_VM_1_UUID


####CHECKPOINT: No traffic flows and no Service Chain Instances or Services are created

# policy-rule-set Association
gbp group-update client-1 --consumed-policy-rule-sets "icmp-policy-rule-set,web-policy-rule-set"
gbp group-update web --provided-policy-rule-sets "icmp-policy-rule-set,web-policy-rule-set" --network-service-policy vip_ip_policy

# Wait for the heat stacks to be setup completely
sleep 15

####CHECKPOINT: ICMP and HTTP work from app to web and vice versa and a Firewall and LoadBalancer services are created.


nova delete web-vm-1
nova delete client-vm-1

if ! timeout $TERMINATE_TIMEOUT sh -c "while nova list | grep -q ACTIVE; do sleep 1; done"; then
    die $LINENO "Some VMs failed to shutdown"
fi

gbp policy-target-delete web-pt-1
gbp policy-target-delete client-pt-1

gbp group-delete  web
gbp group-delete  client-1

gbp policy-rule-set-delete icmp-policy-rule-set
gbp policy-rule-set-delete web-policy-rule-set

gbp policy-rule-delete secure-web-policy-rule
gbp policy-rule-delete web-policy-rule
gbp policy-rule-delete ping-policy-rule

gbp policy-classifier-delete secure-web-traffic
gbp policy-classifier-delete web-traffic
gbp policy-classifier-delete icmp-traffic

gbp policy-action-delete allow
gbp policy-action-delete redirect

gbp network-service-policy-delete vip_ip_policy

gbp servicechain-spec-delete firewall-loadbalancer-spec

gbp  servicechain-node-delete loadbalancer-node
gbp  servicechain-node-delete firewall-node

gbp service-profile-delete lb-profile
gbp service-profile-delete fw-profile

set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End DevStack Exercise: $0"
echo "*********************************************************************"
