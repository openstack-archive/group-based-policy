#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import socket
import time

from gbpservice.contrib.nfp.config_orchestrator.common import topics
from gbpservice.nfp.core import log as nfp_logging
from neutron.common import rpc as n_rpc
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron import manager
from neutron_lib import exceptions
from neutron_vpnaas.db.vpn import vpn_validator
from neutron_vpnaas.services.vpn.plugin import VPNDriverPlugin
from neutron_vpnaas.services.vpn.plugin import VPNPlugin
from neutron_vpnaas.services.vpn.service_drivers import base_ipsec

import oslo_messaging

LOG = nfp_logging.getLogger(__name__)
BASE_VPN_VERSION = '1.0'
AGENT_TYPE_VPN = 'NFP Vpn agent'
ACTIVE = 'ACTIVE'
DOWN = 'DOWN'
ERROR = 'ERROR'
TIMEOUT = 80


class VPNAgentHostingServiceNotFound(exceptions.NeutronException):
    message = _("VPN Agent hosting vpn service '%(vpnservice_id)s' not found")


class VPNAgentNotFound(exceptions.NeutronException):
    message = _("VPN Agent not found in agent_db")


class VPNPluginExt(VPNPlugin, agentschedulers_db.AgentSchedulerDbMixin):
    """
    Extends the base VPN Plugin class to inherit agentdb too.
    Required to get agent entry into the database.
    """

    def __init__(self):
        super(VPNPluginExt, self).__init__()


class NFPIPsecVPNDriverCallBack(base_ipsec.IPsecVpnDriverCallBack):
    """Callback for IPSecVpnDriver rpc."""

    target = oslo_messaging.Target(version=BASE_VPN_VERSION)

    def __init__(self, driver):
        super(NFPIPsecVPNDriverCallBack, self).__init__(driver)
        self.driver = driver

    def update_status(self, context, status):
        """Update status of vpnservices."""
        if 'ipsec_site_connections' not in status[0]:
            status[0]['ipsec_site_connections'] = {}
        plugin = self.driver.service_plugin
        plugin.update_status_by_agent(context, status)


class NFPIPsecVpnAgentApi(base_ipsec.IPsecVpnAgentApi):
    """API and handler for NFP IPSec plugin to agent RPC messaging."""
    target = oslo_messaging.Target(version=BASE_VPN_VERSION)

    def __init__(self, topic, default_version, driver):
        super(NFPIPsecVpnAgentApi, self).__init__(
            topic, default_version, driver)

    def _is_agent_hosting_vpnservice(self, agent):
        """
        In case we have agent running on each compute node.
        We have to write logic here to get
        the agent which is hosting this vpn service
        """
        host = agent['host']
        lhost = socket.gethostname()
        if host == lhost:
            return True
        return False

    def _get_agent_hosting_vpnservice(self, admin_context, vpnservice_id):
        filters = {'agent_type': [AGENT_TYPE_VPN]}
        agents = manager.NeutronManager.get_plugin().get_agents(
            admin_context, filters=filters)

        try:
            for agent in agents:
                if not agent['alive']:
                    continue
                res = self._is_agent_hosting_vpnservice(agent)
                if res is True:
                    return agent

            # valid vpn agent is not found, hostname comparison might be
            # failed. Return whichever agent is available.
            for agent in agents:
                if not agent['alive']:
                    continue
                return agent
        except Exception:
            raise VPNAgentNotFound()

        msg = ('No active vpn agent found. Configuration will fail.')
        LOG.error(msg)
        raise VPNAgentHostingServiceNotFound(vpnservice_id=vpnservice_id)

    def _agent_notification(self, context, method, vpnservice_id,
                            version=None, **kwargs):
        admin_context = context.is_admin and context or context.elevated()

        if not version:
            version = self.target.version
        vpn_agent = self._get_agent_hosting_vpnservice(
            admin_context, vpnservice_id)

        msg = (('Notify agent at %(topic)s.%(host)s the message '
                '%(method)s %(args)s')
               % {'topic': self.topic,
                  'host': vpn_agent['host'],
                  'method': method, 'args': kwargs})
        LOG.debug(msg)

        cctxt = self.client.prepare(server=vpn_agent['host'],
                                    version=version)
        cctxt.cast(context, method, **kwargs)

    def vpnservice_updated(self, context, vpnservice_id, **kwargs):
        """
        Make rpc to agent for 'vpnservice_updated'
        """
        try:
            self._agent_notification(
                context, 'vpnservice_updated',
                vpnservice_id, **kwargs)
        except Exception:
            msg = ('Notifying agent failed')
            LOG.error(msg)


class VPNValidator(vpn_validator.VpnReferenceValidator):
    """This class overrides the vpnservice validator method"""
    def __init__(self):
        super(VPNValidator, self).__init__()

    def validate_vpnservice(self, context, vpns):
        pass


class NFPIPsecVPNDriver(base_ipsec.BaseIPsecVPNDriver):
    """VPN Service Driver class for IPsec."""

    def __init__(self, service_plugin):
        super(NFPIPsecVPNDriver, self).__init__(
            service_plugin)
        self.validator = VPNValidator()

    def create_rpc_conn(self):
        self.endpoints = [
            NFPIPsecVPNDriverCallBack(self),
            agents_db.AgentExtRpcCallback(VPNPluginExt())]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.VPN_NFP_PLUGIN_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = NFPIPsecVpnAgentApi(
            topics.VPN_NFP_CONFIGAGENT_TOPIC, BASE_VPN_VERSION, self)

    def _get_service_vendor(self, context, vpnservice_id):
        vpnservice = self.service_plugin.get_vpnservice(
                context, vpnservice_id)
        desc = vpnservice['description']
        # if the call is through GBP workflow,
        # fetch the service profile from description
        # else, use 'VYOS' as the service profile
        if 'service_vendor=' in desc:
            tokens = desc.split(';')
            service_vendor = tokens[5].split('=')[1]
        else:
            service_vendor = 'VYOS'
        return service_vendor

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        service_vendor = self._get_service_vendor(
                                    context,
                                    ipsec_site_connection['vpnservice_id'])

        starttime = 0
        while starttime < TIMEOUT:
            vpnservice = self.service_plugin.get_vpnservice(
                                        context,
                                        ipsec_site_connection['vpnservice_id'])
            #(Revisit):Due to device driver issue neutron is making vpnservice
            #          state in Down state, At this point of time,
            #           Allowing ipsec site connection to gets created though
            #          vpnservice is in down state.
            if vpnservice['status'] in [ACTIVE, DOWN]:
                self.agent_rpc.vpnservice_updated(
                    context,
                    ipsec_site_connection['vpnservice_id'],
                    rsrc_type='ipsec_site_connection',
                    svc_type=self.service_type,
                    rsrc_id=ipsec_site_connection['id'],
                    resource=ipsec_site_connection,
                    reason='create', service_vendor=service_vendor)
                break
            elif vpnservice['status'] == ERROR:
                msg = ('updating ipsec_site_connection with id %s to'
                       'ERROR state' % (ipsec_site_connection['id']))
                LOG.error(msg)
                VPNPluginExt().update_ipsec_site_conn_status(
                                            context,
                                            ipsec_site_connection['id'],
                                            ERROR)
                break
            time.sleep(5)
            starttime += 5
        else:
            msg = ('updating ipsec_site_connection with id %s to'
                   'ERROR state' % (ipsec_site_connection['id']))
            LOG.error(msg)
            VPNPluginExt().update_ipsec_site_conn_status(
                                                context,
                                                ipsec_site_connection['id'],
                                                ERROR)

    def _move_ipsec_conn_state_to_error(self, context, ipsec_site_connection):
        vpnsvc_status = [{
            'id': ipsec_site_connection['vpnservice_id'],
            'status':ERROR,
            'updated_pending_status':False,
            'ipsec_site_connections':{
                ipsec_site_connection['id']: {
                    'status': ERROR,
                    'updated_pending_status': True}}}]
        driver = VPNDriverPlugin()._get_driver_for_ipsec_site_connection(
                                                    context,
                                                    ipsec_site_connection)
        NFPIPsecVPNDriverCallBack(driver).update_status(context,
                                                        vpnsvc_status)

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        service_vendor = self._get_service_vendor(
                                    context,
                                    ipsec_site_connection['vpnservice_id'])

        self.agent_rpc.vpnservice_updated(
            context,
            ipsec_site_connection['vpnservice_id'],
            rsrc_type='ipsec_site_connection',
            svc_type=self.service_type,
            rsrc_id=ipsec_site_connection['id'],
            resource=ipsec_site_connection,
            reason='delete', service_vendor=service_vendor)

    def create_vpnservice(self, context, vpnservice):
        service_vendor = self._get_service_vendor(context,
                                                  vpnservice['id'])

        self.agent_rpc.vpnservice_updated(
            context,
            vpnservice['id'],
            rsrc_type='vpn_service',
            svc_type=self.service_type,
            rsrc_id=vpnservice['id'],
            resource=vpnservice,
            reason='create', service_vendor=service_vendor)

    def delete_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpnservice, new_vpnservice):
        pass
