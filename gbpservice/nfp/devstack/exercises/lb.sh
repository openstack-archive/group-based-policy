#!/bin/bash

source /home/stack/devstack/openrc neutron service

# Service chain node and spec creation
gbp servicechain-node-create --service-profile base-mode-lb --template-file ./templates/haproxy.template LB-NODE
gbp servicechain-spec-create --nodes "LB-NODE" lb_chainspec

# REDIRECT action, classifier, rule and rule-set
gbp policy-action-create --action-type REDIRECT --action-value lb_chainspec redirect-to-lb
gbp policy-classifier-create --protocol tcp --direction bi lb-webredirect
gbp policy-rule-create --classifier lb-webredirect --actions redirect-to-lb lb-webredirect-rule
gbp policy-rule-set-create --policy-rules "lb-webredirect-rule" lb-webredirect-ruleset

# Network service policy
gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet lb_nsp

#   For N-S create external-policy, for E-W create policy-target-group(consumer-group)
#gbp external-policy-create --external-segments default --consumed-policy-rule-sets webredirect-ruleset=None web-consumer-external-policy
#	(or for E-W)                                           
gbp group-create lb-consumer --consumed-policy-rule-sets "lb-webredirect-ruleset=None"

# Provider PTG
gbp group-create lb-provider --provided-policy-rule-sets "lb-webredirect-ruleset=None" --network-service-policy lb_nsp
