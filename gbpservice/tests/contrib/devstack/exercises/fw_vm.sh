#!/usr/bin/env bash

# **fw_vm.sh**

# Sanity check that firewall(in service VM) service is created with NFP

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

source $TOP_DIR/openrc admin admin

#service chain node and spec creation
gbp servicechain-node-create --service-profile base_mode_fw_vm --config 'custom_json:{"mimetype": "config/custom+json","rules": [{"action": "log", "name": "tcp", "service": "tcp/80"}, {"action": "log", "name": "tcp", "service": "tcp/8080"}, {"action": "accept", "name": "tcp", "service": "tcp/22"}, {"action": "accept", "name": "icmp", "service": "icmp"}]}' FWNODE
gbp servicechain-spec-create --nodes "FWNODE" fw-chainspec

# Redirect action, rule, classifier and rule-set
gbp policy-action-create --action-type REDIRECT --action-value fw-chainspec redirect-to-fw
gbp policy-action-create --action-type ALLOW allow-to-fw
gbp policy-classifier-create --protocol tcp --direction bi fw-web-classifier-tcp
gbp policy-classifier-create --protocol udp --direction bi fw-web-classifier-udp
gbp policy-classifier-create --protocol icmp --direction bi fw-web-classifier-icmp
gbp policy-rule-create --classifier fw-web-classifier-tcp --actions redirect-to-fw fw-web-redirect-rule
gbp policy-rule-create --classifier fw-web-classifier-tcp --actions allow-to-fw fw-web-allow-rule-tcp
gbp policy-rule-create --classifier fw-web-classifier-udp --actions allow-to-fw fw-web-allow-rule-udp
gbp policy-rule-create --classifier fw-web-classifier-icmp --actions allow-to-fw fw-web-allow-rule-icmp
gbp policy-rule-set-create --policy-rules "fw-web-redirect-rule fw-web-allow-rule-tcp fw-web-allow-rule-udp fw-web-allow-rule-icmp" fw-webredirect-ruleset

#provider, consumer E-W groups creation
gbp group-create fw-consumer --consumed-policy-rule-sets "fw-webredirect-ruleset=None"
gbp group-create fw-provider --provided-policy-rule-sets "fw-webredirect-ruleset=None"

# Here, add validation for the firewall creation

gbp group-delete fw-provider
gbp group-delete fw-consumer

gbp policy-rule-set-delete fw-webredirect-ruleset
gbp policy-rule-delete fw-web-redirect-rule
gbp policy-rule-delete fw-web-allow-rule-tcp
gbp policy-rule-delete fw-web-allow-rule-icmp
gbp policy-rule-delete fw-web-allow-rule-udp
gbp policy-classifier-delete fw-web-classifier-tcp
gbp policy-classifier-delete fw-web-classifier-icmp
gbp policy-classifier-delete fw-web-classifier-udp
gbp policy-action-delete redirect-to-fw
gbp policy-action-delete allow-to-fw

gbp servicechain-spec-delete fw-chainspec
gbp servicechain-node-delete FWNODE

