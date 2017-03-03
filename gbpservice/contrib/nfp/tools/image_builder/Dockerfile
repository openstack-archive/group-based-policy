FROM ubuntu:14.04 

# dependencies
RUN apt-get -y update --fix-missing && apt-get -y --force-yes install\
 python2.7\
 python-pip\
 python2.7-dev\
 build-essential libssl-dev libffi-dev\
 libyaml-dev\
 python-ipaddr\
 rabbitmq-server\
 python-dev

# python dependencies
RUN python -m pip install -U pip
RUN pip install\
 python-keystoneclient\
 oslo.config==3.6.0\
 oslo.log==2.4.0\
 oslo.messaging==4.6.1\
 oslo.db==4.4.0\
 oslo.policy\
 pecan==1.0.4\
 pika==0.10.0\
 amqp==2.0.3\
 wsme\
 neutron-lib\
 octavia==0.9

# copy local src to docker image
COPY ./gbpservice /usr/local/lib/python2.7/dist-packages/gbpservice
COPY ./neutron /usr/local/lib/python2.7/dist-packages/neutron
COPY ./neutron_lbaas /usr/local/lib/python2.7/dist-packages/neutron_lbaas
COPY ./configurator_run.sh /configurator_run.sh

# Cache buster
ADD https://www.random.org/strings/?num=10&len=8&digits=on&upperalpha=on&loweralpha=on&unique=on&format=plain&rnd=new cache-buster

# clean-up
RUN rm -rf /var/lib/apt/lists/* && apt-get autoremove -y

RUN cp /usr/local/lib/python2.7/dist-packages/gbpservice/nfp/bin/nfp /usr/bin/
RUN chmod +x /usr/bin/nfp
RUN cp /usr/local/lib/python2.7/dist-packages/gbpservice/contrib/nfp/bin/nfp_controller.ini /etc/
RUN cp /usr/local/lib/python2.7/dist-packages/gbpservice/contrib/nfp/bin/policy.json /etc/
RUN cp /usr/local/lib/python2.7/dist-packages/gbpservice/contrib/nfp/tools/image_builder/nfp-controller /etc/init.d/
RUN cp /usr/local/lib/python2.7/dist-packages/gbpservice/contrib/nfp/tools/image_builder/nfp-pecan /etc/init.d/
RUN mkdir -p /var/log/nfp
RUN touch /var/log/nfp/nfp_configurator.log
RUN touch /var/log/nfp/nfp_pecan.log
RUN sed -i "/version = version.encode('utf-8')/a\    version = '1.8.0'" /usr/local/lib/python2.7/dist-packages/pbr/packaging.py
RUN chmod +555 /configurator_run.sh

EXPOSE 8070:8080
EXPOSE 5672:5672
ENV HOME /root
CMD ["/configurator_run.sh"]
