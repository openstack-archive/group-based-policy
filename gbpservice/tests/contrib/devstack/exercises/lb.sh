
#!/usr/bin/env bash

# **lb.sh**

# Sanity check that loadbalancer service is created with NFP

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

# Service chain node and spec creation
gbp servicechain-node-create --service-profile base_mode_lb --template-file $TOP_DIR/nfp-templates/haproxy.template LB-NODE
gbp servicechain-spec-create --nodes "LB-NODE" lb_chainspec

# REDIRECT action, classifier, rule and rule-set
gbp policy-action-create --action-type REDIRECT --action-value lb_chainspec redirect-to-lb
gbp policy-classifier-create --protocol tcp --direction bi lb-webredirect
gbp policy-rule-create --classifier lb-webredirect --actions redirect-to-lb lb-webredirect-rule
gbp policy-rule-set-create --policy-rules "lb-webredirect-rule" lb-webredirect-ruleset

# Network service policy
gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet lb_nsp

# For N-S create external-policy, for E-W create policy-target-group(consumer-group)
# gbp external-policy-create --external-segments default --consumed-policy-rule-sets webredirect-ruleset=None web-consumer-external-policy
# (or for E-W)
gbp group-create lb-consumer --consumed-policy-rule-sets "lb-webredirect-ruleset=None"

# Provider PTG
gbp group-create lb-provider --provided-policy-rule-sets "lb-webredirect-ruleset=None" --network-service-policy lb_nsp

# Here, add the validations for loadbalancer created

# Delete PTG
gbp group-delete lb-consumer
gbp group-delete lb-provider

# Delete network service policy
gbp network-service-policy-delete lb_nsp

# Delete rule-set
gbp policy-rule-set-delete lb-webredirect-ruleset

# Delete rules
gbp policy-rule-delete lb-webredirect-rule

# Delete classifier
gbp policy-classifier-delete lb-webredirect

# Delete actions
gbp policy-action-delete redirect-to-lb

# Delete service chain node and specs
gbp servicechain-spec-delete lb_chainspec
gbp servicechain-node-delete LB-NODE

