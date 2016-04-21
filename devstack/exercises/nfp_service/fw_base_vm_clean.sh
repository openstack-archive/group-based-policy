#!/bin/bash

source /home/stack/devstack/openrc neutron service

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

