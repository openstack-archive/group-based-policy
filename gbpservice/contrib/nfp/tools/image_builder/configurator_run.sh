#!/bin/bash

service rabbitmq-server start
service nfp-controller start
cd /usr/local/lib/python2.7/dist-packages/gbpservice/nfp/pecan/api/
python setup.py develop
service nfp-pecan start
/bin/bash

