GBP="Group-Based Policy"
HEAT_PLUGINS_DIR="/opt/stack/gbpautomation/gbpautomation/heat"

function configure_nova {
    iniset $NOVA_CONF neutron allow_duplicate_networks "True"
}

function configure_heat {
    iniset $HEAT_CONF DEFAULT plugin_dirs "$HEAT_PLUGINS_DIR"
}

function configure_neutron {
    iniset $NEUTRON_CONF group_policy policy_drivers "implicit_policy"
    iniadd $NEUTRON_CONF group_policy policy_drivers "resource_mapping"
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

# Process contract
if is_service_enabled group-policy; then
    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        echo_summary "Preparing $GBP"
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing $GBP"
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring $GBP"
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Initializing $GBP"
        install_apic_ml2
        install_aim
        init_aim
        install_gbpclient
        install_gbpservice
        init_gbpservice
        install_gbpheat
        install_gbpui
        sudo service apache2 restart
    fi

    if [[ "$1" == "unstack" ]]; then
        echo_summary "Removing $GBP"
    fi

    if [[ "$1" == "clean" ]]; then
        echo_summary "Cleaning $GBP"
    fi
fi
