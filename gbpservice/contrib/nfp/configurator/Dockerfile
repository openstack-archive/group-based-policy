FROM ubuntu:14.04 

RUN apt-get -y update --fix-missing

# dependencies
RUN apt-get -y --force-yes install vim\
 python2.7\
 python-pip\
 python2.7-dev\
 build-essential libssl-dev libffi-dev\
 libyaml-dev\
 python-ipaddr\
 git\
 rabbitmq-server\
 unzip
 

# python dependencies
RUN pip install python-keystoneclient \
oslo.config==3.6.0 \
oslo.log==2.4.0 \
oslo.messaging==4.2.0 \
oslo.db==4.4.0 \
oslo.policy \
iptools \
cryptography \
pecan==1.0.4 \
amqp==1.4.9 \
wsme

#haproxy lbaasv2 depedencies
RUN sudo apt-get -y --force-yes install python-dev
RUN sudo pip install "octavia<0.8"

RUN git clone -b stable/mitaka --single-branch https://github.com/openstack/neutron-lbaas.git neutron-lbaas
RUN sudo pip install -r /neutron-lbaas/requirements.txt --allow-all-external
RUN cur_dir=$PWD
RUN cd /neutron-lbaas && sudo python setup.py install
RUN cd $cur_dir

RUN git clone https://github.com/kevinsteves/pan-python.git pan-python
RUN cur_dir=$PWD
RUN cd /pan-python && sudo ./setup.py install
RUN cd $cur_dir

RUN git clone -b stable/mitaka --single-branch https://github.com/openstack/neutron-lib.git neutron_lib
RUN cp -r  /neutron_lib/neutron_lib /usr/local/lib/python2.7/dist-packages/
RUN git clone -b stable/mitaka --single-branch https://github.com/openstack/neutron.git neutron
RUN cp -r /neutron/neutron /usr/local/lib/python2.7/dist-packages/
RUN git clone https://github.com/openstack/group-based-policy.git group-based-policy
RUN cd /group-based-policy && git fetch https://git.openstack.org/openstack/group-based-policy GIT-BRANCH-NAME && git checkout FETCH_HEAD
RUN cp -r /group-based-policy/gbpservice /usr/local/lib/python2.7/dist-packages/
RUN cp /group-based-policy/gbpservice/nfp/bin/nfp /usr/bin/
RUN chmod +x /usr/bin/nfp
RUN cp /group-based-policy/gbpservice/contrib/nfp/bin/nfp_configurator.ini /etc/
RUN sed -i "s/log_forward_ip_address=*.*/log_forward_ip_address=VIS_VM_IP_ADDRESS/" /etc/nfp_configurator.ini
RUN cp /group-based-policy/gbpservice/contrib/nfp/bin/policy.json /etc/
RUN mkdir -p /var/log/nfp
RUN touch /var/log/nfp/nfp_configurator.log
RUN touch /var/log/nfp/nfp_pecan.log
RUN sed -i "/version = version.encode('utf-8')/a\    version = '1.8.0'" /usr/local/lib/python2.7/dist-packages/pbr/packaging.py
RUN apt-get -y --force-yes install screen
COPY  ./run.sh /run.sh
RUN chmod +777 /run.sh

EXPOSE 8070:8080
EXPOSE 5672:5672
ENV HOME /root
CMD ["/run.sh"]
