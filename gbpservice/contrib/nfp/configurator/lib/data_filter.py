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

import copy

from gbpservice.contrib.nfp.configurator.lib import (
    filter_constants as constants)


class Filter(object):
    """ Filter class which provides data asked in a specific format.

    This class mocks all rpc calls going from *aaS agent/driver to respective
        *aaS plugin.
    """

    def __init__(self, topic, default_version):
        pass

    def call(self, context, msg):
        """Returns data in specific format after applying filter on context

        :param context
        :param msg e.g  {'args': {'key': value,..},'method': 'function_name'}}

        Returns: data after applying filter on it

        """
        filters = {}
        try:
            for fk, fv in msg['args'].items():
                if dict == type(fv):
                    filters = fv
                    break
                if fv:
                    filters = {fk: fv}
                    break

            method = getattr(self, '_%s' % (msg['method']))
            return method(context, filters)
        except Exception as e:
            raise e

    def make_msg(self, method, **kwargs):
        """ Helper function needed to invoke Filter.call()
        :param method - method name
        :kwargs kwargs - filters to be used

        Returns: dict
        """
        return {'method': method,
                'args': kwargs}

    def apply_filter(self, data, filters):
        """ Apply filters on data

        :param filters e.g  {k:[v],k:[v]}
        :param data e.g [{k:v,k:v,k:v},
                      {k:v,k:v,k:v},
                      {k:v,k:v}]

        Returns: data after applying filter on it

        """

        for fk, fv in filters.items():
            for d in data[:]:
                if d.get(fk) is None:
                    data.remove(d)
                if fk in d and d[fk] != fv[0]:
                    data.remove(d)
        return data

    def get_record(self, data, key, value):
        """Get single record based on key and value

        :param data
        :praam key
        :param value

        Returns: record
        """
        for d in data:
            if key in d and d[key] == value:
                return d

    def _get_vpn_services(self, context, filters):
        """ Get vpn service from context after applying filter

        :param context - vpn related resources
        e.g context = {'service_info':{'vpnservices': [vpnservices],
                                       'ikepolicies': [ikepolicies],
                                       'ipsecpolicies':[ipsecpolicies],
                                       'ipsec_site_conns':
                                                [ipsec_site_connections],
                                        'routers': [routers],
                                        'subnets': [subnets]
                                      }
                      }
        :param filters
        e.g { 'ids' : [vpn service ids],
              'filters': filters }

        Returns: [vpn services]

        """
        vpn_ids = None
        if 'ids' in filters and filters['ids']:
            vpn_ids = filters['ids']
        service_info = context['service_info']
        vpnservices = service_info['vpnservices']
        filtered_vpns = []
        if vpn_ids:
            for vpn_id in vpn_ids:
                filtered_vpns.append(
                    self.get_record(vpnservices, 'id', vpn_id))
            return filtered_vpns
        else:
            return self.apply_filter(vpnservices, filters)

    def _get_ipsec_conns(self, context, filters):
        """ Get ipsec site conns from context after applying filter

        :param context - vpn related resources
        e.g context = {'service_info':{'vpnservices': [vpnservices],
                                       'ikepolicies': [ikepolicies],
                                       'ipsecpolicies':[ipsecpolicies],
                                       'ipsec_site_conns':
                                                [ipsec_site_connections],
                                        'routers': [routers],
                                        'subnets': [subnets]
                                      }
                      }
        :param filters e.g { 'tenant_id': [tenant_id],
                             'peer_address': [conn['peer_address']]
                           }

        Returns: [ipsec site conns]

        """
        service_info = context['service_info']
        ipsec_conns = copy.deepcopy(service_info['ipsec_site_conns'])

        return self.apply_filter(ipsec_conns, filters)

    def _get_vpn_servicecontext(self, context, filters):
        """Get vpnservice context

        :param context
        :param filters

        Returns IPSec site conns
        """
        return self._get_ipsec_site2site_contexts(context, filters)

    def _get_ipsec_site2site_contexts(self, context, filters=None):
        """ Get ipsec site to site context
        :param filters
        e.g {'tenant_id': <value>,
             'vpnservice_id': <value>,
             'siteconn_id': <value>
            }
        'tenant_id' - To get s2s conns of that tenant
        'vpnservice_id' - To get s2s conns of that vpn service
        'siteconn_id' - To get a specific s2s conn

        Returns: vpnservices
            e.g { 'vpnserviceid':
                    { 'service': <VPNService>,
                  'siteconns':[ {
                                'connection': <IPSECsiteconnections>,
                                'ikepolicy': <IKEPolicy>,
                                'ipsecpolicy': <IPSECPolicy>
                                }
                              ]
                    }
                }
        """
        if not filters:
            filters = {}

        service_info = context['service_info']
        vpnservices = {}
        s_filters = {}
        if 'tenant_id' in filters:
            s_filters['tenant_id'] = [filters['tenant_id']]
        if 'vpnservice_id' in filters:
            s_filters['vpnservice_id'] = [filters['vpnservice_id']]
        if 'siteconn_id' in filters:
            s_filters['id'] = [filters['siteconn_id']]
        if 'peer_address' in filters:
            s_filters['peer_address'] = [filters['peer_address']]

        ipsec_site_conns = self.apply_filter(service_info['ipsec_site_conns'],
                                             s_filters)

        for conn in ipsec_site_conns:

            vpnservice = [vpn for vpn in service_info['vpnservices']
                          if vpn['id'] == conn['vpnservice_id']][0]

            ikepolicy = [ikepolicy for ikepolicy in service_info['ikepolicies']
                         if ikepolicy['id'] == conn['ikepolicy_id']][0]

            ipsecpolicy = [ipsecpolicy for ipsecpolicy in
                           service_info['ipsecpolicies']
                           if ipsecpolicy['id'] == conn['ipsecpolicy_id']][0]
            """
            Get the local subnet cidr
            """

            siteconn = {}
            siteconn['connection'] = conn
            siteconn['ikepolicy'] = ikepolicy
            siteconn['ipsecpolicy'] = ipsecpolicy
            vpnserviceid = vpnservice['id']

            if vpnserviceid not in vpnservices.keys():
                vpnservices[vpnserviceid] = \
                    {'service': vpnservice, 'siteconns': []}

            vpnservices[vpnserviceid]['siteconns'].append(siteconn)

        site2site_context = self._make_vpnservice_context(vpnservices)
        return site2site_context

    def _make_vpnservice_context(self, vpnservices):
        """Generate vpnservice context from the dictionary of vpnservices.
        See, if some values are not needed by agent-driver, do not pass them.
        As of now, passing everything.
        """

        return vpnservices.values()

    def _get_logical_device(self, context, filters):
        """ Get logical device from context after applying filter.
            Logical device here means pool and its related resources like vip,
            member,hm etc

        :param context
        e.g context = {'service_info': { 'pools': [pools],
                                         'members': [members],
                                         'vips': [vips],
                                         'health_monitors': [health_monitors],
                                         'ports': [ports],
                                         'subnets': [subnets],
                                       }
                      }
        :param filters e.g {'pool_id': pool_id}

        Returns: logical divice

        """
        service_info = context['service_info']
        pool_id = filters.get('pool_id')
        pool = self.get_record(service_info['pools'], 'id', pool_id)

        retval = {}
        retval['pool'] = pool  # self._make_pool_dict(pool)

        if 'vip_id' in pool and pool['vip_id'] is not None:
            vip = self.get_record(
                service_info['vips'], 'id', pool['vip_id'])
            retval['vip'] = vip  # self._make_vip_dict(vip)

        pool_members = pool['members']
        retval['members'] = []

        for pm in pool_members:
            member = self.get_record(service_info['members'], 'id', pm)
            if (member['status'] in constants.ACTIVE_PENDING_STATUSES or
                    member['status'] == constants.INACTIVE):
                retval['members'].append(member)

        pool_health_monitors = pool['health_monitors_status']
        retval['healthmonitors'] = []

        for phm in pool_health_monitors:
            if phm['status'] in constants.ACTIVE_PENDING_STATUSES:
                health_monitor = self.get_record(
                    service_info['health_monitors'],
                    'id', phm['monitor_id'])
                retval['healthmonitors'].append(health_monitor)

        retval['driver'] = pool['provider']
        return retval
