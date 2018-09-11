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

from neutron.api import extensions
from neutron.db import address_scope_db
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.objects import subnetpool as subnetpool_obj
from neutron.plugins.ml2 import db as ml2_db
from neutron_lib.api import attributes
from neutron_lib.api import validators
from neutron_lib import exceptions
from neutron_lib.exceptions import address_scope as as_exc
from oslo_log import log
from oslo_utils import excutils
from sqlalchemy import event
from sqlalchemy.orm import session as sql_session


LOG = log.getLogger(__name__)
PUSH_NOTIFICATIONS_METHOD = None
DISCARD_NOTIFICATIONS_METHOD = None


def gbp_after_transaction(session, transaction):
    if transaction and not transaction._parent and (
        not transaction.is_active and not transaction.nested):
        if transaction in session.notification_queue:
            # push the queued notifications only when the
            # outermost transaction completes
            PUSH_NOTIFICATIONS_METHOD(session, transaction)


def gbp_after_rollback(session):
    # We discard all queued notifiactions if the transaction fails.
    DISCARD_NOTIFICATIONS_METHOD(session)


# This module is loaded twice, once by way of imports,
# and once explicitly by Neutron's extension loading
# mechanism. We do the following to ensure that the
# patching happens only once and we preserve the reference
# to the original method.
if not hasattr(sql_session.Session, 'GBP_PATCHED'):
    orig_session_init = getattr(sql_session.Session, '__init__')

    def new_session_init(self, **kwargs):
        self.notification_queue = {}

        orig_session_init(self, **kwargs)

        from gbpservice.network.neutronv2 import local_api
        if local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS:
            global PUSH_NOTIFICATIONS_METHOD
            global DISCARD_NOTIFICATIONS_METHOD
            PUSH_NOTIFICATIONS_METHOD = (
                local_api.post_notifications_from_queue)
            DISCARD_NOTIFICATIONS_METHOD = (
                local_api.discard_notifications_after_rollback)
            event.listen(self, "after_transaction_end",
                         gbp_after_transaction)
            event.listen(self, "after_rollback",
                         gbp_after_rollback)

    setattr(sql_session.Session, '__init__', new_session_init)
    setattr(sql_session.Session, 'GBP_PATCHED', True)


import copy
from neutron.api.v2 import resource as neutron_resource
from neutron.quota import resource as quota_resource
from neutron_lib.plugins import directory

from gbpservice.common import utils as gbp_utils


if not hasattr(quota_resource, 'GBP_PATCHED'):
    orig_count_resource = quota_resource._count_resource

    def new_count_resource(*kwargs):
        request = gbp_utils.get_obj_from_stack(neutron_resource.Request)
        orig_plugins = directory._get_plugin_directory()._plugins
        if request and request.environ['PATH_INFO'] == (
                '/servicechain/service_profiles.json'):
            new_plugins = copy.copy(directory._get_plugin_directory()._plugins)
            # The service_profile resource is supported by the FLAVORS
            # plugin as well as the SERVICECHAIN plugin. At this point
            # we know that we are dealing with the service_profile from
            # SERVICECHAIN, and since the original implementation of the
            # count_resource will think of service_profile from FLAVORS
            # (in the sorted order of plugins, FLAVORS preceedes SERVICECHAIN)
            # we temporarily remove the FLAVORS plugin reference from the
            # plugins directory.
            new_plugins.pop('FLAVORS')
            directory._get_plugin_directory()._plugins = new_plugins

        count_resource = orig_count_resource(*kwargs)
        directory._get_plugin_directory()._plugins = orig_plugins
        return count_resource

    quota_resource._count_resource = new_count_resource
    quota_resource.GBP_PATCHED = True


# REVISIT(ivar): Monkey patch to allow explicit router_id to be set in Neutron
# for Floating Ip creation (for internal calls only). Once we split the server,
# this could be part of a GBP Neutron L3 driver.
def _get_assoc_data(self, context, fip, floatingip_db):
    (internal_port, internal_subnet_id,
     internal_ip_address) = self._internal_fip_assoc_data(
         context, fip, floatingip_db['tenant_id'])
    if fip.get('router_id'):
        router_id = fip['router_id']
        del fip['router_id']
    else:
        router_id = self._get_router_for_floatingip(
            context, internal_port, internal_subnet_id,
            floatingip_db['floating_network_id'])

    return fip['port_id'], internal_ip_address, router_id


l3_db.L3_NAT_dbonly_mixin._get_assoc_data = _get_assoc_data


# REVISIT(ivar): Neutron adds a tenant filter on SG lookup for a given port,
# this breaks our service chain plumbing model so for now we should monkey
# patch the specific method. A follow up with the Neutron team is needed to
# figure out the reason for this and how to proceed for future releases.
def _get_security_groups_on_port(self, context, port):
    """Check that all security groups on port belong to tenant.

    :returns: all security groups IDs on port belonging to tenant.
    """
    p = port['port']
    if not validators.is_attr_set(
            p.get(securitygroups_db.ext_sg.SECURITYGROUPS)):
        return
    if p.get('device_owner') and p['device_owner'].startswith('network:'):
        return

    port_sg = p.get(securitygroups_db.ext_sg.SECURITYGROUPS, [])
    filters = {'id': port_sg}
    valid_groups = set(g['id'] for g in
                       self.get_security_groups(context, fields=['id'],
                                                filters=filters))

    requested_groups = set(port_sg)
    port_sg_missing = requested_groups - valid_groups
    if port_sg_missing:
        raise securitygroups_db.ext_sg.SecurityGroupNotFound(
            id=', '.join(port_sg_missing))

    return requested_groups

securitygroups_db.SecurityGroupDbMixin._get_security_groups_on_port = (
    _get_security_groups_on_port)


def get_port_from_device_mac(context, device_mac):
    LOG.debug("get_port_from_device_mac() called for mac %s", device_mac)
    qry = context.session.query(models_v2.Port).filter_by(
        mac_address=device_mac).order_by(models_v2.Port.device_owner.desc())
    return qry.first()

ml2_db.get_port_from_device_mac = get_port_from_device_mac


# REVISIT: This is temporary, the correct fix is to use
# the 'project_id' directly from the context rather than
# calling this method.
def _get_tenant_id_for_create(self, context, resource):
    if context.is_admin and 'tenant_id' in resource:
        tenant_id = resource['tenant_id']
    elif ('tenant_id' in resource and
          resource['tenant_id'] != context.project_id):
        reason = _('Cannot create resource for another tenant')
        raise exceptions.AdminRequired(reason=reason)
    else:
        tenant_id = context.project_id

    return tenant_id


common_db_mixin.CommonDbMixin._get_tenant_id_for_create = (
    _get_tenant_id_for_create)


# REVISIT: In ocata, the switch to new engine facade in neutron is partial.
# This can result in different facades being mixed up within same transaction,
# and inconsistent behavior. Specifically, when L3 policy is deleted,
# subnetpool is deleted (old facade), and address scope (new facade) fails to
# be deleted since the dependent subnetpool deletion is in different session
# that is not yet commited. The workaround is to switch address scope to old
# engine facade. This workaround should be removed in Pike.
def _delete_address_scope(self, context, id):
    with context.session.begin(subtransactions=True):
        if subnetpool_obj.SubnetPool.get_objects(context,
                                                 address_scope_id=id):
            raise as_exc.AddressScopeInUse(address_scope_id=id)
        address_scope = self._get_address_scope(context, id)
        address_scope.delete()

address_scope_db.AddressScopeDbMixin.delete_address_scope = (
    _delete_address_scope)


def extend_resources(self, version, attr_map):
        """Extend resources with additional resources or attributes.

        :param attr_map: the existing mapping from resource name to
        attrs definition.

        After this function, we will extend the attr_map if an extension
        wants to extend this map.
        """
        processed_exts = {}
        exts_to_process = self.extensions.copy()
        check_optionals = True
        # Iterate until there are unprocessed extensions or if no progress
        # is made in a whole iteration
        while exts_to_process:
            processed_ext_count = len(processed_exts)
            for ext_name, ext in list(exts_to_process.items()):
                # Process extension only if all required extensions
                # have been processed already
                required_exts_set = set(ext.get_required_extensions())
                if required_exts_set - set(processed_exts):
                    continue
                optional_exts_set = set(ext.get_optional_extensions())
                if check_optionals and optional_exts_set - set(processed_exts):
                    continue
                extended_attrs = ext.get_extended_resources(version)
                for res, resource_attrs in extended_attrs.items():
                    res_to_update = attr_map.setdefault(res, {})
                    if self._is_sub_resource(res_to_update):
                        # kentwu: service_profiles defined in servicechain
                        # plugin has a name conflict with service_profiles
                        # sub-resource defined in flavor plugin. The attr_map
                        # can only have one service_profiles so here we make
                        # this very same service_profiles to have the
                        # attributes from both plugins. This behavior is now
                        # consistent with Pike.
                        if (ext_name == 'servicechain' and
                                res == 'service_profiles'):
                            res_to_update.update(resource_attrs)
                        # in the case of an existing sub-resource, we need to
                        # update the parameters content rather than overwrite
                        # it, and also keep the description of the parent
                        # resource unmodified
                        else:
                            res_to_update['parameters'].update(
                                resource_attrs['parameters'])
                    else:
                        res_to_update.update(resource_attrs)
                processed_exts[ext_name] = ext
                del exts_to_process[ext_name]
            if len(processed_exts) == processed_ext_count:
                # if we hit here, it means there are unsatisfied
                # dependencies. try again without optionals since optionals
                # are only necessary to set order if they are present.
                if check_optionals:
                    check_optionals = False
                    continue
                # Exit loop as no progress was made
                break
        if exts_to_process:
            unloadable_extensions = set(exts_to_process.keys())
            LOG.error("Unable to process extensions (%s) because "
                      "the configured plugins do not satisfy "
                      "their requirements. Some features will not "
                      "work as expected.",
                      ', '.join(unloadable_extensions))
            self._check_faulty_extensions(unloadable_extensions)
        # Extending extensions' attributes map.
        for ext in processed_exts.values():
            ext.update_attributes_map(attr_map)

extensions.ExtensionManager.extend_resources = extend_resources


def fill_post_defaults(
        self, res_dict,
        exc_cls=lambda m: exceptions.InvalidInput(error_message=m),
        check_allow_post=True):
    """Fill in default values for attributes in a POST request.

    When a POST request is made, the attributes with default values do not
    need to be specified by the user. This function fills in the values of
    any unspecified attributes if they have a default value.

    If an attribute is not specified and it does not have a default value,
    an exception is raised.

    If an attribute is specified and it is not allowed in POST requests, an
    exception is raised. The caller can override this behavior by setting
    check_allow_post=False (used by some internal admin operations).

    :param res_dict: The resource attributes from the request.
    :param exc_cls: Exception to be raised on error that must take
        a single error message as it's only constructor arg.
    :param check_allow_post: Raises an exception if a non-POST-able
        attribute is specified.
    :raises: exc_cls If check_allow_post is True and this instance of
        ResourceAttributes doesn't support POST.
    """
    for attr, attr_vals in self.attributes.items():
        # kentwu: Patch needed for our GBP service_profiles attribute. Since
        # parent and parameters are both sub-resource's attributes picked up
        # from flavor plugin so we can just ignore those. These 2 attributes
        # don't have allow_post defined so it will just fail without this
        # patch.
        if attr == 'parent' or attr == 'parameters':
            if 'allow_post' not in attr_vals:
                continue
        if attr_vals['allow_post']:
            if 'default' not in attr_vals and attr not in res_dict:
                msg = _("Failed to parse request. Required "
                        "attribute '%s' not specified") % attr
                raise exc_cls(msg)
            res_dict[attr] = res_dict.get(attr,
                                          attr_vals.get('default'))
        elif check_allow_post:
            if attr in res_dict:
                msg = _("Attribute '%s' not allowed in POST") % attr
                raise exc_cls(msg)

attributes.AttributeInfo.fill_post_defaults = fill_post_defaults


# TODO(ivar): while this block would be better place in the patch_neutron
# module, it seems like being part of an "extension" package is the only
# way to make it work at the moment. Tests have shown that Neutorn reloads
# the extensions at every call (at least in the UTs) and this causes the
# AIM_FLC_L7_PARAMS to be reset over and over. By patching at this point,
# we make sure we always have the proper value for that variable.
try:
    import six
    import sys

    from networking_sfc.db import flowclassifier_db
    from networking_sfc.db import sfc_db
    from networking_sfc.extensions import flowclassifier as fc_ext
    from networking_sfc.extensions import sfc as sfc_ext  # noqa
    from networking_sfc.services.flowclassifier.common import (
        exceptions as fc_exc)
    from networking_sfc.services.flowclassifier import driver_manager as fc_mgr
    from networking_sfc.services.flowclassifier import plugin as fc_plugin
    from networking_sfc.services.sfc.common import exceptions as sfc_exc
    from networking_sfc.services.sfc import driver_manager as sfc_mgr
    from networking_sfc.services.sfc import plugin as sfc_plugin
    from neutron.services.trunk import constants
    from oslo_utils import uuidutils

    from gbpservice.neutron.services.sfc.aim import constants as sfc_cts

    if 'flowclassifier' in sys.modules:
        sys.modules['flowclassifier'].SUPPORTED_L7_PARAMETERS.update(
            sfc_cts.AIM_FLC_L7_PARAMS)
    if 'networking_sfc.extensions.flowclassifier' in sys.modules:
        sys.modules[
            ('networking_sfc.extensions.'
             'flowclassifier')].SUPPORTED_L7_PARAMETERS.update(
            sfc_cts.AIM_FLC_L7_PARAMS)
    if 'sfc' in sys.modules:
        sys.modules['sfc'].RESOURCE_ATTRIBUTE_MAP['port_pair_groups'][
            'port_pair_group_parameters']['validate']['type:dict'].update(
                sfc_cts.AIM_PPG_PARAMS)
    if 'networking_sfc.extensions.sfc' in sys.modules:
        sys.modules['networking_sfc.extensions.sfc'].RESOURCE_ATTRIBUTE_MAP[
            'port_pair_groups']['port_pair_group_parameters']['validate'][
            'type:dict'].update(sfc_cts.AIM_PPG_PARAMS)
    # REVISIT(ivar): The following diff will fix flow classifier creation
    # method when using L7 parameters.
    # -            key: L7Parameter(key, val)
    # +            key: L7Parameter(keyword=key, value=val)

    def create_flow_classifier(self, context, flow_classifier):
        fc = flow_classifier['flow_classifier']
        tenant_id = fc['tenant_id']
        l7_parameters = {
            key: flowclassifier_db.L7Parameter(keyword=key, value=val)
            for key, val in six.iteritems(fc['l7_parameters'])}
        ethertype = fc['ethertype']
        protocol = fc['protocol']
        source_port_range_min = fc['source_port_range_min']
        source_port_range_max = fc['source_port_range_max']
        self._check_port_range_valid(source_port_range_min,
                                     source_port_range_max,
                                     protocol)
        destination_port_range_min = fc['destination_port_range_min']
        destination_port_range_max = fc['destination_port_range_max']
        self._check_port_range_valid(destination_port_range_min,
                                     destination_port_range_max,
                                     protocol)
        source_ip_prefix = fc['source_ip_prefix']
        self._check_ip_prefix_valid(source_ip_prefix, ethertype)
        destination_ip_prefix = fc['destination_ip_prefix']
        self._check_ip_prefix_valid(destination_ip_prefix, ethertype)
        logical_source_port = fc['logical_source_port']
        logical_destination_port = fc['logical_destination_port']
        with db_api.context_manager.writer.using(context):
            if logical_source_port is not None:
                self._get_port(context, logical_source_port)
            if logical_destination_port is not None:
                self._get_port(context, logical_destination_port)
            query = self._model_query(
                context, flowclassifier_db.FlowClassifier)
            for flow_classifier_db in query.all():
                if self.flowclassifier_conflict(
                    fc,
                    flow_classifier_db
                ):
                    raise fc_ext.FlowClassifierInConflict(
                        id=flow_classifier_db['id'])
            flow_classifier_db = flowclassifier_db.FlowClassifier(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=fc['name'],
                description=fc['description'],
                ethertype=ethertype,
                protocol=protocol,
                source_port_range_min=source_port_range_min,
                source_port_range_max=source_port_range_max,
                destination_port_range_min=destination_port_range_min,
                destination_port_range_max=destination_port_range_max,
                source_ip_prefix=source_ip_prefix,
                destination_ip_prefix=destination_ip_prefix,
                logical_source_port=logical_source_port,
                logical_destination_port=logical_destination_port,
                l7_parameters=l7_parameters
            )
            context.session.add(flow_classifier_db)
            return self._make_flow_classifier_dict(flow_classifier_db)
    flowclassifier_db.FlowClassifierDbPlugin.create_flow_classifier = (
        create_flow_classifier)

    # Flowclassifier validation should also take into account l7_parameters.

    old_validation = (
        flowclassifier_db.FlowClassifierDbPlugin.flowclassifier_basic_conflict)

    def flowclassifier_basic_conflict(cls, first_flowclassifier,
                                      second_flowclassifier):
        def _l7_params_conflict(fc1, fc2):
            if (validators.is_attr_set(fc1['l7_parameters']) and
                    validators.is_attr_set(fc2['l7_parameters'])):
                if fc1['l7_parameters'] == fc2['l7_parameters']:
                    return True
            return all(not validators.is_attr_set(fc['l7_parameters'])
                       for fc in [fc1, fc2])
        return cls._old_flowclassifier_basic_conflict(
            first_flowclassifier, second_flowclassifier) and (
            _l7_params_conflict(first_flowclassifier, second_flowclassifier))

    if getattr(flowclassifier_db.FlowClassifierDbPlugin,
               '_old_flowclassifier_basic_conflict', None) is None:
        flowclassifier_db.FlowClassifierDbPlugin.\
            _old_flowclassifier_basic_conflict = old_validation
        flowclassifier_db.FlowClassifierDbPlugin.\
            flowclassifier_basic_conflict = classmethod(
                flowclassifier_basic_conflict)

    # NOTE(ivar): Trunk subports don't have a device ID, we need this
    # validation to pass
    # NOTE(ivar): It would be ideal to re-use the original function and call
    # it instead of copying it here. However, it looks like this module gets
    # reloaded a number of times and this would cause the original definition
    # to be overridden with the new one, thus causing an endless recursion.
    def _validate_port_pair_ingress_egress(self, ingress, egress):
        if any(port.get('device_owner') == constants.TRUNK_SUBPORT_OWNER
               for port in [ingress, egress]):
            return
        if 'device_id' not in ingress or not ingress['device_id']:
            raise sfc_db.ext_sfc.PortPairIngressNoHost(
                ingress=ingress['id']
            )
        if 'device_id' not in egress or not egress['device_id']:
            raise sfc_db.ext_sfc.PortPairEgressNoHost(
                egress=egress['id']
            )
        if ingress['device_id'] != egress['device_id']:
            raise sfc_db.ext_sfc.PortPairIngressEgressDifferentHost(
                ingress=ingress['id'],
                egress=egress['id'])
    sfc_db.SfcDbPlugin._validate_port_pair_ingress_egress = (
        _validate_port_pair_ingress_egress)

    if not getattr(sfc_plugin.SfcPlugin, '_patch_db_retry', False):
        sfc_plugin.SfcPlugin.create_port_pair = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.create_port_pair))
        sfc_plugin.SfcPlugin.create_port_pair_group = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.create_port_pair_group))
        sfc_plugin.SfcPlugin.create_port_chain = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.create_port_chain))

        sfc_plugin.SfcPlugin.update_port_pair = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.update_port_pair))
        sfc_plugin.SfcPlugin.update_port_pair_group = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.update_port_pair_group))
        sfc_plugin.SfcPlugin.update_port_chain = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.update_port_chain))

        sfc_plugin.SfcPlugin.delete_port_pair = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.delete_port_pair))
        sfc_plugin.SfcPlugin.delete_port_pair_group = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.delete_port_pair_group))
        sfc_plugin.SfcPlugin.delete_port_chain = (
            db_api.retry_if_session_inactive()(
                sfc_plugin.SfcPlugin.delete_port_chain))
        sfc_plugin.SfcPlugin._patch_db_retry = True

    if not getattr(fc_plugin.FlowClassifierPlugin, '_patch_db_retry', False):
        fc_plugin.FlowClassifierPlugin.create_flow_classifier = (
            db_api.retry_if_session_inactive()(
                fc_plugin.FlowClassifierPlugin.create_flow_classifier))
        fc_plugin.FlowClassifierPlugin.update_flow_classifier = (
            db_api.retry_if_session_inactive()(
                fc_plugin.FlowClassifierPlugin.update_flow_classifier))
        fc_plugin.FlowClassifierPlugin.delete_flow_classifier = (
            db_api.retry_if_session_inactive()(
                fc_plugin.FlowClassifierPlugin.delete_flow_classifier))
        fc_plugin.FlowClassifierPlugin._patch_db_retry = True

    # Overrides SFC implementation to avoid eating retriable exceptions
    def get_call_drivers(exception, name):
        def _call_drivers(self, method_name, context, raise_orig_exc=False):
            for driver in self.ordered_drivers:
                try:
                    getattr(driver.obj, method_name)(context)
                except Exception as e:
                    # This is an internal failure.
                    if db_api.is_retriable(e):
                        with excutils.save_and_reraise_exception():
                            LOG.debug(
                                "DB exception raised by extension driver "
                                "'%(name)s' in %(method)s",
                                {'name': driver.name, 'method': method_name},
                                exc_info=e)
                    LOG.exception(e)
                    LOG.error("%(plugin)s driver '%(name)s' "
                              "failed in %(method)s",
                              {'name': driver.name, 'method': method_name,
                               'plugin': name})
                    if raise_orig_exc:
                        raise
                    else:
                        raise exception(method=method_name)
        return _call_drivers

    sfc_mgr.SfcDriverManager._call_drivers = get_call_drivers(
        sfc_exc.SfcDriverError, 'SFC')
    fc_mgr.FlowClassifierDriverManager._call_drivers = get_call_drivers(
        fc_exc.FlowClassifierDriverError, 'FlowClassifier')

except ImportError as e:
    LOG.warning("Import error while patching networking-sfc: %s",
                e.message)
