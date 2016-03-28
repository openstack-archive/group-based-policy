NFP="NFP"
NEUTRON_CONF=/etc/neutron/neutron.conf

function nfp_configure_neutron {
    iniset $NEUTRON_CONF keystone_authtoken admin_tenant_name "service"
    iniset $NEUTRON_CONF keystone_authtoken admin_user "neutron"
    iniset $NEUTRON_CONF keystone_authtoken admin_password "admin_pass"
    iniset $NEUTRON_CONF node_composition_plugin node_plumber "admin_owned_resources_apic_plumber"
    iniset $NEUTRON_CONF node_composition_plugin node_drivers "nfp_node_driver"
    iniset $NEUTRON_CONF admin_owned_resources_apic_tscp plumbing_resource_owner_user "neutron"
    iniset $NEUTRON_CONF admin_owned_resources_apic_tscp plumbing_resource_owner_password "admin_pass"
    iniset $NEUTRON_CONF admin_owned_resources_apic_tscp plumbing_resource_owner_tenant_name "service"
    iniset $NEUTRON_CONF group_policy_implicit_policy default_ip_pool "11.0.0.0/8"
    iniset $NEUTRON_CONF group_policy_implicit_policy default_proxy_ip_pool "192.169.0.0/16"
    iniset $NEUTRON_CONF group_policy_implicit_policy default_external_segment_name "default"
    iniset $NEUTRON_CONF device_lifecycle_drivers drivers "haproxy, vyos"
    iniset $NEUTRON_CONF nfp_node_driver is_service_admin_owned "True"
    iniset $NEUTRON_CONF nfp_node_driver svc_management_ptg_name "svc_management_ptg"
}
# Process contract
if is_service_enabled nfp-group-policy; then
    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        echo_summary "Preparing $NFP"
    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        echo_summary "Installing $NFP"
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        echo_summary "Configuring $NFP"
        #nfp_configure_neutron
        install_nfpgbpservice
        init_nfpgbpservice
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        echo_summary "Initializing $NFP"
        assign_user_role_credential
        create_nfp_gbp_resources
        get_router_namespace
        copy_nfp_files_and_start_process
    fi

    if [[ "$1" == "unstack" ]]; then
        echo_summary "Removing $NFP"
    fi

    if [[ "$1" == "clean" ]]; then
        echo_summary "Cleaning $NFP"
    fi
fi
