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

create_gbp_resources() {
    # E-W insertion
    gbp servicechain-node-create --service-profile base_mode_fw --template-file $TOP_DIR/nfp-templates/fw_template.yml FW_LB-FWNODE
    gbp servicechain-node-create --service-profile base_mode_lb --template-file $TOP_DIR/nfp-templates/haproxy.template FW_LB-LBNODE
    gbp servicechain-spec-create --nodes "FW_LB-FWNODE FW_LB-LBNODE" fw_lb_chainspec
    gbp policy-action-create --action-type REDIRECT --action-value fw_lb_chainspec redirect-to-fw_lb
    gbp policy-classifier-create --protocol tcp --direction bi fw_lb-webredirect
    gbp policy-rule-create --classifier fw_lb-webredirect --actions redirect-to-fw_lb fw_lb-web-redirect-rule
    gbp policy-rule-set-create --policy-rules "fw_lb-web-redirect-rule" fw_lb-webredirect-ruleset
    gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet fw_lb_nsp
    gbp group-create fw_lb-consumer --consumed-policy-rule-sets "fw_lb-webredirect-ruleset=None"
    gbp group-create fw_lb-provider --provided-policy-rule-sets "fw_lb-webredirect-ruleset=None" --network-service-policy fw_lb_nsp
}

delete_gbp_resources() {
    gbp group-delete fw_lb-provider
    gbp group-delete fw_lb-consumer
    gbp network-service-policy-delete fw_lb_nsp
    gbp policy-rule-set-delete fw_lb-webredirect-ruleset
    gbp policy-rule-delete fw_lb-web-redirect-rule
    gbp policy-classifier-delete fw_lb-webredirect
    gbp policy-action-delete redirect-to-fw_lb
    gbp servicechain-spec-delete fw_lb_chainspec
    gbp servicechain-node-delete FW_LB-LBNODE
    gbp servicechain-node-delete FW_LB-FWNODE
}

validate_gbp_resources() {
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw_lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "1" ]; then
        echo "Chain creation Succeded"
    else
        echo "Chain creation failed"
    fi

    ServiceChainNodeCount=`gbp scn-list -f value | grep FW_LB | wc -l`
    if [ "$ServiceChainNodeCount" -eq "2" ]; then
        echo "Network function creation Succeded"
    else
        echo "Network function creation failed"
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

validate_loadbalancer_resources() {
    LBPoolCount=`neutron lb-pool-list -f value | wc -l`
    if [ "$LBPoolCount" -eq "1" ]; then
        echo "LB Pool resource created"
        LBPoolUUID=`neutron lb-pool-list -f value | awk '{print $1}'`
        LBPoolStatus=`neutron lb-pool-show $LBPoolUUID -f value -c status`
        echo "LB Pool resource is in $LBPoolStatus state"
    else
        echo "LB Pool resource not created"
    fi

    LBVIPCount=`neutron lb-vip-list -f value | wc -l`
    if [ "$LBVIPCount" -eq "1" ]; then
        echo "LB VIP resource created"
        LBVIPUUID=`neutron lb-vip-list -f value | awk '{print $1}'`
        LBVIPStatus=`neutron lb-vip-show $LBVIPUUID -f value -c status`
        echo "LB VIP resource is in $LBVIPStatus state"
    else
        echo "LB VIP resource not created"
    fi

    LBHMCount=`neutron lb-healthmonitor-list -f value | wc -l`
    if [ "$LBHMCount" -eq "1" ]; then
        echo "LB Healthmonitor resource created"
    else
        echo "LB Healthmonitor resource not created"
    fi

    gbp policy-target-create --policy-target-group fw_lb-provider provider_pt1
    sleep 5
    LBMemberCount=`neutron lb-member-list -f value | wc -l`
    if [ "$LBMemberCount" -eq "1" ]; then
        echo "LB Member resource created"
    else
        echo "LB Member resource not created"
    fi

    gbp policy-target-create --policy-target-group fw_lb-provider provider_pt2
    sleep 5
    LBMemberCount=`neutron lb-member-list -f value | wc -l`
    if [ "$LBMemberCount" -eq "2" ]; then
        echo "LB Member resource created"
    else
        echo "LB Member resource not created"
    fi

    gbp policy-target-delete provider_pt1
    sleep 5
    LBMemberCount=`neutron lb-member-list -f value | wc -l`
    if [ "$LBMemberCount" -eq "1" ]; then
        echo "LB Member resource deleted"
    else
        echo "LB Member resource not deleted"
    fi

    gbp policy-target-delete provider_pt2
    sleep 5
    LBMemberCount=`neutron lb-member-list -f value | wc -l`
    if [ "$LBMemberCount" -eq "0" ]; then
        echo "LB Member resource deleted"
    else
        echo "LB Member resource not deleted"
    fi
}

update_gbp_resources() {
    # Update existing chain, by removing 2 rules
    #gbp servicechain-node-update FW_LB-FWNODE --template-file $TOP_DIR/nfp-templates/fw_updated_template.yml

    #FirewallRuleCount=`neutron firewall-rule-list -f value | wc -l`
    #if [ "$FirewallRuleCount" -eq "2" ]; then
    #    echo "Chain created"
    #else
    #    echo "Chain not created"
    #fi

    gbp group-delete fw_lb-provider
    gbp group-delete fw_lb-consumer
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw_lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "0" ]; then
        echo "Chain deleted"
    else
        echo "Chain not deleted"
    fi

    # Service chain creation/deletion through PRS update
    gbp group-create fw_lb-consumer --consumed-policy-rule-sets "fw_lb-webredirect-ruleset=None"
    gbp group-create fw_lb-provider
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw_lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "0" ]; then
        echo "Chain not created"
    else
        echo "Chain not deleted"
    fi
    
    gbp group-update fw_lb-provider --provided-policy-rule-sets "fw_lb-webredirect-ruleset=None" --network-service-policy fw_lb_nsp
    ServiceChainInstanceCount=`gbp sci-list -f value | grep fw_lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "1" ]; then
        echo "Chain created"
    else
        echo "Chain not created"
    fi
}

create_gbp_resources
validate_gbp_resources
validate_firewall_resources
validate_loadbalancer_resources

update_gbp_resources

delete_gbp_resources
