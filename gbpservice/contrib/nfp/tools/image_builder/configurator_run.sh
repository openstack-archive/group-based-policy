#!/bin/bash

service rabbitmq-server start
screen -dmS "configurator" /usr/bin/python2 /usr/bin/nfp --config-file=/etc/nfp_configurator.ini --log-file=/var/log/nfp/nfp_configurator.log
cd /usr/local/lib/python2.7/dist-packages/gbpservice/nfp/pecan/api/
python setup.py develop
screen -dmS  "pecan" pecan configurator_decider config.py --mode  advanced
/bin/bash

