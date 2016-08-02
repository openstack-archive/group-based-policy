GBP="Group-Based Policy"
[[ $ENABLE_NFP = True ]] && NFP="Network Function Plugin"

function gbp_configure_nova {
    iniset $NOVA_CONF neutron allow_duplicate_networks "True"
}

function gbp_configure_heat {
    local HEAT_PLUGINS_DIR="/opt/stack/gbpautomation/gbpautomation/heat"
    iniset $HEAT_CONF DEFAULT plugin_dirs "$HEAT_PLUGINS_DIR"
}

function gbp_configure_neutron {
    iniset $NEUTRON_CONF group_policy policy_drivers "implicit_policy,resource_mapping,chain_mapping"
    iniset $NEUTRON_CONF group_policy extension_drivers "proxy_group"
    iniset $NEUTRON_CONF servicechain servicechain_drivers "simplechain_driver"
    iniset $NEUTRON_CONF node_composition_plugin node_plumber "stitching_plumber"
    iniset $NEUTRON_CONF node_composition_plugin node_drivers "heat_node_driver"
    iniset $NEUTRON_CONF quotas default_quota "-1"
    iniset $NEUTRON_CONF quotas quota_network "-1"
    iniset $NEUTRON_CONF quotas quota_subnet "-1"
    iniset $NEUTRON_CONF quotas quota_port "-1"
    iniset $NEUTRON_CONF quotas quota_security_group "-1"
    iniset $NEUTRON_CONF quotas quota_security_group_rule "-1"
    iniset $NEUTRON_CONF quotas quota_router "-1"
    iniset $NEUTRON_CONF quotas quota_floatingip "-1"
}

function nfp_configure_neutron {
    iniset $NEUTRON_CONF keystone_authtoken admin_tenant_name "service"
    iniset $NEUTRON_CONF keystone_authtoken admin_user "neutron"
    iniset $NEUTRON_CONF keystone_authtoken admin_password $ADMIN_PASSWORD
    iniset $NEUTRON_CONF node_composition_plugin node_plumber "admin_owned_resources_apic_plumber"
    iniset $NEUTRON_CONF node_composition_plugin node_drivers "nfp_node_driver"
    iniset $NEUTRON_CONF admin_owned_resources_apic_tscp plumbing_resource_owner_user "neutron"
    iniset $NEUTRON_CONF admin_owned_resources_apic_tscp plumbing_resource_owner_password $ADMIN_PASSWORD
    iniset $NEUTRON_CONF admin_owned_resources_apic_tscp plumbing_resource_owner_tenant_name "service"
    iniset $NEUTRON_CONF group_policy_implicit_policy default_external_segment_name "default"
    iniset $NEUTRON_CONF nfp_node_driver is_service_admin_owned "True"
    iniset $NEUTRON_CONF nfp_node_driver svc_management_ptg_name "svc_management_ptg"
}

function configure_nfp_loadbalancer {
    echo "Configuring NFP Loadbalancer plugin driver"
    sudo\
 sed\
 -i\
 '/^service_provider.*HaproxyOnHostPluginDriver:default/'\
's'/\
':default'/\
'\n'\
'service_provider = LOADBALANCER:loadbalancer:gbpservice.contrib.nfp.service_plugins.loadbalancer.drivers.nfp_lbaas_plugin_driver.HaproxyOnVMPluginDriver:default'/\
 /etc/neutron/neutron_lbaas.conf
}

function configure_nfp_firewall {
    echo "Configuring NFP Firewall plugin"
    sudo\
 sed\
 -i\
 '/^service_plugins/'\
's'/\
'neutron_fwaas.services.firewall.fwaas_plugin.FirewallPlugin'/\
'gbpservice.contrib.nfp.service_plugins.firewall.nfp_fwaas_plugin.NFPFirewallPlugin'/\
 /etc/neutron/neutron.conf
}

function configure_nfp_vpn {
    echo "Configuring NFP VPN plugin driver"
    sudo\
 sed\
 -i\
 '/^service_provider.*IPsecVPNDriver:default/'\
's'/\
':default'/\
'\n'\
'service_provider = VPN:vpn:gbpservice.contrib.nfp.service_plugins.vpn.drivers.nfp_vpnaas_driver.NFPIPsecVPNDriver:default'/\
 /etc/neutron/neutron_vpnaas.conf
}

# Process contract
if is_service_enabled group-policy; then
    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        echo_summary "Preparing $GBP"
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing $GBP"
        [[ $ENABLE_APIC_AIM = True ]] && install_apic_aim
        if [[ $ENABLE_NFP = True ]]; then
            echo_summary "Installing $NFP"
            prepare_nfp_image_builder
        fi
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring $GBP"
        gbp_configure_nova
        gbp_configure_heat
        gbp_configure_neutron
        if [[ $ENABLE_NFP = True ]]; then
            echo_summary "Configuring $NFP"
            nfp_configure_neutron
            if [[ $NFP_DEVSTACK_MODE = advanced ]]; then
                configure_nfp_loadbalancer
                configure_nfp_firewall
                configure_nfp_vpn
            fi
        fi
        # REVISIT move installs to install phase?
        # install_apic_ml2
        install_gbpclient
        install_gbpservice
        [[ $ENABLE_NFP = True ]] && install_nfpgbpservice
        init_gbpservice
        [[ $ENABLE_NFP = True ]] && init_nfpgbpservice
        install_gbpheat
        install_gbpui
        [[ $ENABLE_APIC_AIM = True ]] && configure_apic_aim
        stop_apache_server
        start_apache_server
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Initializing $GBP"
        if [[ $ENABLE_NFP = True ]]; then
            echo_summary "Initializing $NFP"
            assign_user_role_credential
            create_nfp_gbp_resources
            create_nfp_image
            [[ $NFP_DEVSTACK_MODE = advanced ]] && launch_configuratorVM
            copy_nfp_files_and_start_process
        fi
    fi

    if [[ "$1" == "unstack" ]]; then
        echo_summary "Removing $GBP"
    fi

    if [[ "$1" == "clean" ]]; then
        echo_summary "Cleaning $GBP"
    fi
fi
