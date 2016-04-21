#!/bin/bash

source /home/stack/devstack/openrc demo demo

# Service chain node and spec creation
gbp servicechain-node-create --service-profile base_mode_lb --template-file ./templates/haproxy_base_mode.template LBNODE
gbp servicechain-spec-create --nodes "LBNODE" lb_chainspec

# REDIRECT action, classifier, rule and rule-set
gbp policy-action-create --action-type REDIRECT --action-value lb_chainspec redirect-to-lb
gbp policy-classifier-create --protocol tcp --direction bi lb-webredirect
gbp policy-rule-create --classifier lb-webredirect --actions redirect-to-lb lb-web-redirect-rule
gbp policy-rule-set-create --policy-rules "lb-web-redirect-rule" lb-webredirect-ruleset

# Network service policy
gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet lb_nsp

# Consumer PTG
gbp group-create lb-consumer --consumed-policy-rule-sets "lb-webredirect-ruleset=None"

# Provider PTG
gbp group-create lb-provider --provided-policy-rule-sets "lb-webredirect-ruleset=None" --network-service-policy lb_nsp
