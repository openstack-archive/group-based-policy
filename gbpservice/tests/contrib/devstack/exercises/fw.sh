#!/usr/bin/env bash

# **fw.sh**

# Sanity check that firewall service is created with NFP

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

create_gbp_resources() {
    gbp servicechain-node-create --service-profile base_mode_fw --template-file $TOP_DIR/nfp-templates/fw_template.yml FWNODE
    gbp servicechain-spec-create --nodes "FWNODE" fw-chainspec
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
    gbp group-create fw-consumer --consumed-policy-rule-sets "fw-webredirect-ruleset=None"
    gbp group-create fw-provider --provided-policy-rule-sets "fw-webredirect-ruleset=None"
}

delete_gbp_resources() {
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
}

validate_gbp_resources() {
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "1" ]; then
        echo "Chain creation Succeded"
    else
        echo "Chain creation failed"
    fi
}

validate_firewall_resources() {
    FirewallRuleCount=`neutron firewall-rule-list -f value | grep Rule | wc -l`
    if [ "$FirewallRuleCount" -eq "4" ]; then
        echo "Firewall Rule resource created"
    else
        echo "Firewall Rule resource not created"
    fi

    FirewallPolicyCount=`neutron firewall-policy-list -f value | grep fw | wc -l`
    if [ "$FirewallPolicyCount" -eq "1" ]; then
        echo "Firewall Policy resource created"
    else
        echo "Firewall Policy resource not created"
    fi

    FirewallCount=`neutron firewall-list -f value | wc -l`
    if [ "$FirewallCount" -eq "1" ]; then
        echo "Firewall resource created"
        FirewallUUID=`neutron firewall-list -f value | awk '{print $1}'`
        FirewallStatus=`neutron firewall-show $FirewallUUID -f value -c status`
        echo "Firewall resource is in $FirewallStatus state"
    else
        echo "Firewall resource not created"
    fi
}

update_gbp_resources() {
    # Update existing chain, by removing 2 rules
    #gbp servicechain-node-update FWNODE --template-file $TOP_DIR/nfp-templates/fw_updated_template.yml

    #FirewallRuleCount=`neutron firewall-rule-list -f value | wc -l`
    #if [ "$FirewallRuleCount" -eq "2" ]; then
    #    echo "Chain created"
    #else
    #    echo "Chain not created"
    #fi

    gbp group-delete fw-provider
    gbp group-delete fw-consumer
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "0" ]; then
        echo "Chain deleted"
    else
        echo "Chain not deleted"
    fi

    # Service chain creation/deletion through PRS update
    gbp group-create fw-consumer --consumed-policy-rule-sets "fw-webredirect-ruleset=None"
    gbp group-create fw-provider
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "0" ]; then
        echo "Chain not created"
    else
        echo "Chain not deleted"
    fi
    
    gbp group-update fw-provider --provided-policy-rule-sets "fw-webredirect-ruleset=None"
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "1" ]; then
        echo "Chain created"
    else
        echo "Chain not created"
    fi
}

create_gbp_resources
validate_gbp_resources
validate_firewall_resources

update_gbp_resources

delete_gbp_resources
