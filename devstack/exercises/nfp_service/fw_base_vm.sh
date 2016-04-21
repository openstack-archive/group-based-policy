#!/bin/bash

source /home/stack/devstack/openrc neutron service

#service chain node and spec creation
gbp servicechain-node-create  --service-profile base_mode_fw_vm --config 'custom_json:{"mimetype": "config/custom+json","rules": [{"action": "log", "name": "tcp", "service": "tcp/80"}, {"action": "log", "name": "tcp", "service": "tcp/8080"}, {"action": "accept", "name": "tcp", "service": "tcp/22"}, {"action": "accept", "name": "icmp", "service": "icmp"}]}' FWNODE
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
