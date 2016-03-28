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

source $TOP_DIR/openrc admin admin

create_gbp_resources () {
    #service chain node and spec creation
    gbp servicechain-node-create --service-profile base_mode_fw --template-file $TOP_DIR/nfp-templates/fw_template.yml FWNODE
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
}

delete_gbp_resources () {
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


# Create GBP resources
create_gbp_resources

# Here, add validation for the firewall creation
FirewallRuleCount=`neutron firewall-rule-list | wc -l | awk '{print $1}'`
if [ "$FirewallRuleCount" -eq "4" ]; then
    echo "Chain creation Succeded"
else
    echo "Chain creation failed"
    delete_gbp_resources
    exit
fi

ServiceChainInstanceCount=`gbp sci-list | grep fw-provider | wc -l | awk '{print $1}'`
if [ "$ServiceChainInstanceCount" -eq "1" ]; then
    echo "Chain creation Succeded"
else
    echo "Chain creation failed"
    delete_gbp_resources
    exit
fi

gbp group-delete fw-provider
gbp group-delete fw-consumer
ServiceChainInstanceCount=`gbp sci-list | grep fw-provider | wc -l | awk '{print $1}'`
if [ "$ServiceChainInstanceCount" -eq "0" ]; then
    echo "Chain creation Passed"
else
    echo "Chain creation failed"
    delete_gbp_resources
    exit
fi

# Service chain creation/deletion through PRS update
gbp group-create fw-consumer --consumed-policy-rule-sets "fw-webredirect-ruleset=None"
gbp group-create fw-provider
ServiceChainInstanceCount=`gbp sci-list | grep fw-provider | wc -l | awk '{print $1}'`
if [ "$ServiceChainInstanceCount" -eq "0" ]; then
    echo "Chain creation Passed"
else
    echo "Chain creation failed"
    delete_gbp_resources
    exit
fi

gbp group-update fw-provider --provided-policy-rule-sets "fw-webredirect-ruleset=None"
ServiceChainInstanceCount=`gbp sci-list | grep fw-provider | wc -l | awk '{print $1}'`
if [ "$ServiceChainInstanceCount" -eq "1" ]; then
    echo "Chain creation Passed"
else
    echo "Chain creation failed"
    delete_gbp_resources
    exit
fi

# Delete GBP resources
delete_gbp_resources

