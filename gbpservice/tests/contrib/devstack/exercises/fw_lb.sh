#!/usr/bin/env bash

# **fw_lb.sh**

# Sanity check that firewall and loadbalancer service chain is created with NFP

echo "*********************************************************************"
echo "Begin NFP Exercise: $0"
echo "*********************************************************************"

# Settings
# ========

# This script exits on an error so that errors don't compound and you see
# only the first error that occurred.
set -o errexit

# Keep track of the current directory
EXERCISE_DIR=$(cd $(dirname "$0") && pwd)
TOP_DIR=$(cd $EXERCISE_DIR/..; pwd)

source $TOP_DIR/openrc neutron service

#service chain node and spec creation
gbp servicechain-node-create --service-profile base_mode_fw --template-file $TOP_DIR/nfp-templates/fw_template.yml FW_LB-FWNODE
gbp servicechain-node-create --service-profile base_mode_lb --template-file $TOP_DIR/nfp-templates/haproxy.template FW_LB-LBNODE
gbp servicechain-spec-create --nodes "FW_LB-FWNODE FW_LB-LBNODE" fw_lb_chainspec

# Redirect action, rule, classifier and rule-set
gbp policy-action-create --action-type REDIRECT --action-value fw_lb_chainspec redirect-to-fw_lb
gbp policy-classifier-create --protocol tcp --direction bi fw_lb-webredirect
gbp policy-rule-create --classifier fw_lb-webredirect --actions redirect-to-fw_lb fw_lb-web-redirect-rule
gbp policy-rule-set-create --policy-rules "fw_lb-web-redirect-rule" fw_lb-webredirect-ruleset

# Network service policy
gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet fw_lb_nsp

# For N-S create external-policy, for E-W create policy-target-group(consumer-group)
# gbp external-policy-create --external-segments default --consumed-policy-rule-sets webredirect-ruleset=None web-consumer-external-policy
# (or for E-W)
gbp group-create fw_lb-consumer --consumed-policy-rule-sets "fw_lb-webredirect-ruleset=None"

# Provider PTG
gbp group-create fw_lb-provider --provided-policy-rule-sets "fw_lb-webredirect-ruleset=None" --network-service-policy fw_lb_nsp

# Here, add validation for the firewall creation

# Delete PTG
gbp group-delete fw_lb-provider
gbp group-delete fw_lb-consumer

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

