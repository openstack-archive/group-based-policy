#!/bin/sh


# configure_configurator_user_data() - Configure Configurator user data
function configure_configurator_user_data {
    rm -rf ssh_key ssh_key.pub
    ssh-keygen -t rsa -N "" -f ssh_key
    value=`cat ssh_key.pub`
    sed -i "8 i\      -\ $value" configurator_user_data
    sed -i '9d' configurator_user_data
}


configure_configurator_user_data

