
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

create_gbp_resources() {
    # E-W insertion
    gbp servicechain-node-create --service-profile base_mode_lb --template-file $TOP_DIR/nfp-templates/haproxy.template LB-NODE
    gbp servicechain-spec-create --nodes "LB-NODE" lb_chainspec
    gbp policy-action-create --action-type REDIRECT --action-value lb_chainspec redirect-to-lb
    gbp policy-classifier-create --protocol tcp --direction bi lb-webredirect
    gbp policy-rule-create --classifier lb-webredirect --actions redirect-to-lb lb-webredirect-rule
    gbp policy-rule-set-create --policy-rules "lb-webredirect-rule" lb-webredirect-ruleset
    gbp network-service-policy-create --network-service-params type=ip_single,name=vip_ip,value=self_subnet lb_nsp
    gbp group-create lb-consumer --consumed-policy-rule-sets "lb-webredirect-ruleset=None"
    gbp group-create lb-provider --provided-policy-rule-sets "lb-webredirect-ruleset=None" --network-service-policy lb_nsp
}

delete_gbp_resources() {
    gbp group-delete lb-consumer
    gbp group-delete lb-provider
    gbp network-service-policy-delete lb_nsp
    gbp policy-rule-set-delete lb-webredirect-ruleset
    gbp policy-rule-delete lb-webredirect-rule
    gbp policy-classifier-delete lb-webredirect
    gbp policy-action-delete redirect-to-lb
    gbp servicechain-spec-delete lb_chainspec
    gbp servicechain-node-delete LB-NODE
}

validate_gbp_resources() {
    ServiceChainInstanceCount=`gbp sci-list -f value | grep lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "1" ]; then
        echo "Chain creation Succeded"
    else
        echo "Chain creation failed"
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

    gbp policy-target-create --policy-target-group lb-provider provider_pt1
    sleep 5
    LBMemberCount=`neutron lb-member-list -f value | wc -l`
    if [ "$LBMemberCount" -eq "1" ]; then
        echo "LB Member resource created"
    else
        echo "LB Member resource not created"
    fi

    gbp policy-target-create --policy-target-group lb-provider provider_pt2
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
    gbp group-delete lb-provider
    gbp group-delete lb-consumer
    ServiceChainInstanceCount=`gbp sci-list -f value | grep lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "0" ]; then
        echo "Chain deleted"
    else
        echo "Chain not deleted"
    fi

    # Service chain creation/deletion through PRS update
    gbp group-create lb-consumer --consumed-policy-rule-sets "lb-webredirect-ruleset=None"
    gbp group-create lb-provider
    ServiceChainInstanceCount=`gbp sci-list -f value | grep lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "0" ]; then
        echo "Chain not created"
    else
        echo "Chain not deleted"
    fi
    
    gbp group-update lb-provider --provided-policy-rule-sets "lb-webredirect-ruleset=None" --network-service-policy lb_nsp
    ServiceChainInstanceCount=`gbp sci-list -f value | grep lb-provider | wc -l`
    if [ "$ServiceChainInstanceCount" -eq "1" ]; then
        echo "Chain created"
    else
        echo "Chain not created"
    fi
}

create_gbp_resources
validate_gbp_resources
validate_loadbalancer_resources

update_gbp_resources

delete_gbp_resources
