#!/bin/bash

source /home/stack/devstack/openrc demo demo

echo "Make sure that policy-targets associated to PTGs are deleted!!"

# Delete PTG
gbp group-delete lb-consumer
gbp group-delete lb-provider

# Delete network service policy
gbp network-service-policy-delete lb_nsp

# Delete rule-set
gbp policy-rule-set-delete lb-webredirect-ruleset

# Delete rules
gbp policy-rule-delete lb-web-redirect-rule

# Delete classifier
gbp policy-classifier-delete lb-webredirect

# Delete actions
gbp policy-action-delete redirect-to-lb

# Delete service chain node and specs
gbp servicechain-spec-delete lb_chainspec
gbp servicechain-node-delete LBNODE
