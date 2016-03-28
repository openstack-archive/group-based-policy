#!/bin/bash

#source /root/keystonerc_cloud_admin
source /home/stack/devstack/openrc neutron service
echo "Make sure that policy-targets associated to PTGs are deleted!!"

# Delete PTG
gbp group-delete fw_lb-consumer
gbp group-delete fw_lb-provider

# Delete network service policy
gbp network-service-policy-delete fw_lb_nsp

# Delete rule-set
gbp policy-rule-set-delete fw_lb-webredirect-ruleset

# Delete rules
gbp policy-rule-delete fw_lb-web-redirect-rule

# Delete classifier
gbp policy-classifier-delete fw_lb-webredirect

# Delete actions
gbp policy-action-delete redirect-to-fw_lb

# Delete service chain node and specs
gbp servicechain-spec-delete fw_lb_chainspec
gbp servicechain-node-delete FW_LB-LBNODE
gbp servicechain-node-delete FW_LB-FWNODE
