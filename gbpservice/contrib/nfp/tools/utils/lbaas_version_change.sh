#!/bin/bash

# This is utility script to move from LBaaSV1 to LBaaSV2 and vice-versa.
# This can be used only when NFP LBaaSV1 or LBaaSV2 is already installed.
# script usage:
#    bash lb_version_change.sh <lb version which you want to move to>
#    e.g bash lb_version_change.sh v1 ---> move from v2 to v1
#     or bash lb_version_change.sh v2 ---> move from v1 to v2



move_to_v2() { #LBaaSV1 to LBaaSV2

    exists=$(gbp service-profile-show LB-V2)
    if [[ "$exists" ]] ; then
        echo "It is already LBaaSV2 version on the system."
        exit
    fi

    # Change service plugin
    sudo sed -i "s/lbaas/lbaasv2/g" /etc/neutron/neutron.conf

    # Change service provider
    sudo sed -i "s/LOADBALANCER:loadbalancer:gbpservice.contrib.nfp.service_plugins.loadbalancer.drivers.nfp_lbaas_plugin_driver.HaproxyOnVMPluginDriver/LOADBALANCERV2:loadbalancerv2:gbpservice.contrib.nfp.service_plugins.loadbalancer.drivers.nfp_lbaasv2_plugin_driver.HaproxyOnVMPluginDriver/g" /etc/neutron/neutron_lbaas.conf

    gbp service-profile-delete LB
    gbp service-profile-create --servicetype LOADBALANCERV2 --insertion-mode l3 --shared True --service-flavor service_vendor=haproxy_lbaasv2,device_type=nova --vendor NFP LB-V2

    echo "---- Please follow below steps now ----"
    echo "1) Restart neutron service 'q-svc'"
    echo "2) If LBaaSV2 image is not there then please upload using command "
    echo "   glance image-create --name haproxy_lbaasv2 --disk-format qcow2 --container-format bare --visibility public --file <image file location>"

}


move_to_v1() { #LBaaSV2 to LBaaSV1

    exists=$(gbp service-profile-show LB)
    if [[ "$exists" ]] ; then
        echo "It is already LBaaSV1 version on the system."
        exit
    fi

    # Change service plugin
    sudo sed -i "s/lbaasv2/lbaas/g" /etc/neutron/neutron.conf

    # Change service provider
    sudo sed -i "s/LOADBALANCERV2:loadbalancerv2:gbpservice.contrib.nfp.service_plugins.loadbalancer.drivers.nfp_lbaasv2_plugin_driver.HaproxyOnVMPluginDriver/LOADBALANCER:loadbalancer:gbpservice.contrib.nfp.service_plugins.loadbalancer.drivers.nfp_lbaas_plugin_driver.HaproxyOnVMPluginDriver/g" /etc/neutron/neutron_lbaas.conf

    gbp service-profile-delete LB-V2
    gbp service-profile-create --servicetype LOADBALANCER --insertion-mode l3 --shared True --service-flavor service_vendor=haproxy,device_type=nova --vendor NFP LB

    echo "---- Please follow below steps now ----"
    echo "1) Restart neutron service 'q-svc'"
    echo "2) If LBaaSV1 image is not there then please upload using command - "
    echo "   glance image-create --name haproxy --disk-format qcow2 --container-format bare --visibility public --file <image file location>"

}

usage() {
    echo -e "\nUsage: bash lbass_version_change.sh <v2/v1>"
}

case $1 in
    "v2")
        move_to_v2
    ;;
    "v1")
        move_to_v1
    ;;
    *)
        usage
    ;;
esac

