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

from neutron.db import api as db_api
from neutron_lib import context as lib_context

# REVISIT(Sumit): The neutron_lib context uses
# a neutron_lib version of db_api. In ocata this
# version of the db_api is different from the
# db_api in neutron, and does not work for GBP.
# Revisit for Pike.
lib_context.db_api = db_api

import sys

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import address_scope_db
from neutron.db import common_db_mixin
from neutron.db import l3_db
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.db import securitygroups_db
from neutron.extensions import address_scope as ext_address_scope
from neutron.extensions import securitygroup as ext_sg
from neutron.objects import subnetpool as subnetpool_obj
from neutron.plugins.ml2 import db as ml2_db
from neutron_lib.api import validators
from neutron_lib import exceptions as n_exc
from oslo_log import log
from oslo_utils import uuidutils
from sqlalchemy import event
from sqlalchemy.orm import exc

from gbpservice.neutron.services.sfc.aim import constants as sfc_cts


LOG = log.getLogger(__name__)


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


# REVISIT(kent): Neutron doesn't pass the remote_group_id while creating the
# ingress rule for the default SG. It also doesn't pass the newly created SG
# for the PRECOMMIT_CREATE event. Note that we should remove this in Pike as
# upstream has fixed the bug there
def create_security_group(self, context, security_group, default_sg=False):
    """Create security group.

    If default_sg is true that means we are a default security group for
    a given tenant if it does not exist.
    """
    s = security_group['security_group']
    kwargs = {
        'context': context,
        'security_group': s,
        'is_default': default_sg,
    }

    self._registry_notify(resources.SECURITY_GROUP, events.BEFORE_CREATE,
                          exc_cls=ext_sg.SecurityGroupConflict, **kwargs)

    tenant_id = s['tenant_id']

    if not default_sg:
        self._ensure_default_security_group(context, tenant_id)
    else:
        existing_def_sg_id = self._get_default_sg_id(context, tenant_id)
        if existing_def_sg_id is not None:
            # default already exists, return it
            return self.get_security_group(context, existing_def_sg_id)

    with db_api.autonested_transaction(context.session):
        security_group_db = sg_models.SecurityGroup(id=s.get('id') or (
                                          uuidutils.generate_uuid()),
                                          description=s['description'],
                                          tenant_id=tenant_id,
                                          name=s['name'])
        context.session.add(security_group_db)
        if default_sg:
            context.session.add(sg_models.DefaultSecurityGroup(
                security_group=security_group_db,
                tenant_id=security_group_db['tenant_id']))
        for ethertype in ext_sg.sg_supported_ethertypes:
            if default_sg:
                # Allow intercommunication
                ingress_rule = sg_models.SecurityGroupRule(
                    id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                    security_group=security_group_db,
                    direction='ingress',
                    ethertype=ethertype,
                    remote_group_id=security_group_db.id,
                    source_group=security_group_db)
                context.session.add(ingress_rule)

            egress_rule = sg_models.SecurityGroupRule(
                id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                security_group=security_group_db,
                direction='egress',
                ethertype=ethertype)
            context.session.add(egress_rule)

        secgroup_dict = self._make_security_group_dict(security_group_db)
        kwargs['security_group'] = secgroup_dict
        self._registry_notify(resources.SECURITY_GROUP,
                              events.PRECOMMIT_CREATE,
                              exc_cls=ext_sg.SecurityGroupConflict,
                              **kwargs)

    registry.notify(resources.SECURITY_GROUP, events.AFTER_CREATE, self,
                    **kwargs)
    return secgroup_dict

securitygroups_db.SecurityGroupDbMixin.create_security_group = (
    create_security_group)


# REVISIT(kent): Neutron doesn't pass the updated SG for the PRECOMMIT_UPDATE
# event. Note that we should remove this in Pike as upstream has fixed the bug
# there
def update_security_group(self, context, id, security_group):
    s = security_group['security_group']

    kwargs = {
        'context': context,
        'security_group_id': id,
        'security_group': s,
    }
    self._registry_notify(resources.SECURITY_GROUP, events.BEFORE_UPDATE,
                          exc_cls=ext_sg.SecurityGroupConflict, **kwargs)

    with context.session.begin(subtransactions=True):
        sg = self._get_security_group(context, id)
        if sg['name'] == 'default' and 'name' in s:
            raise ext_sg.SecurityGroupCannotUpdateDefault()
        sg_dict = self._make_security_group_dict(sg)
        kwargs['original_security_group'] = sg_dict
        sg.update(s)
        sg_dict = self._make_security_group_dict(sg)
        kwargs['security_group'] = sg_dict
        self._registry_notify(
                resources.SECURITY_GROUP,
                events.PRECOMMIT_UPDATE,
                exc_cls=ext_sg.SecurityGroupConflict, **kwargs)

    registry.notify(resources.SECURITY_GROUP, events.AFTER_UPDATE, self,
                    **kwargs)
    return sg_dict

securitygroups_db.SecurityGroupDbMixin.update_security_group = (
    update_security_group)


# REVISIT(kent): Neutron doesn't pass the SG rules for the PRECOMMIT_DELETE
# event. Note that we should remove this in Pike as upstream has fixed the bug
# there
def delete_security_group(self, context, id):
    filters = {'security_group_id': [id]}
    ports = self._get_port_security_group_bindings(context, filters)
    if ports:
        raise ext_sg.SecurityGroupInUse(id=id)
    # confirm security group exists
    sg = self._get_security_group(context, id)

    if sg['name'] == 'default' and not context.is_admin:
        raise ext_sg.SecurityGroupCannotRemoveDefault()
    kwargs = {
        'context': context,
        'security_group_id': id,
        'security_group': sg,
    }
    self._registry_notify(resources.SECURITY_GROUP, events.BEFORE_DELETE,
                          exc_cls=ext_sg.SecurityGroupInUse, id=id,
                          **kwargs)

    with context.session.begin(subtransactions=True):
        # pass security_group_rule_ids to ensure
        # consistency with deleted rules
        kwargs['security_group_rule_ids'] = [r['id'] for r in sg.rules]
        kwargs['security_group'] = self._make_security_group_dict(sg)
        self._registry_notify(resources.SECURITY_GROUP,
                              events.PRECOMMIT_DELETE,
                              exc_cls=ext_sg.SecurityGroupInUse, id=id,
                              **kwargs)
        context.session.delete(sg)

    kwargs.pop('security_group')
    registry.notify(resources.SECURITY_GROUP, events.AFTER_DELETE, self,
                    **kwargs)

securitygroups_db.SecurityGroupDbMixin.delete_security_group = (
    delete_security_group)


# REVISIT(kent): Neutron doesn't pass the newly created SG rule for the
# PRECOMMIT_CREATE event. Note that we should remove this in Pike as upstream
# has fixed the bug there
def _create_security_group_rule(self, context, security_group_rule,
                                validate=True):
    if validate:
        self._validate_security_group_rule(context, security_group_rule)
    rule_dict = security_group_rule['security_group_rule']
    kwargs = {
        'context': context,
        'security_group_rule': rule_dict
    }
    self._registry_notify(resources.SECURITY_GROUP_RULE,
                          events.BEFORE_CREATE,
                          exc_cls=ext_sg.SecurityGroupConflict, **kwargs)

    with context.session.begin(subtransactions=True):
        if validate:
            self._check_for_duplicate_rules_in_db(context,
                                                  security_group_rule)
        db = sg_models.SecurityGroupRule(
            id=(rule_dict.get('id') or uuidutils.generate_uuid()),
            tenant_id=rule_dict['tenant_id'],
            security_group_id=rule_dict['security_group_id'],
            direction=rule_dict['direction'],
            remote_group_id=rule_dict.get('remote_group_id'),
            ethertype=rule_dict['ethertype'],
            protocol=rule_dict['protocol'],
            port_range_min=rule_dict['port_range_min'],
            port_range_max=rule_dict['port_range_max'],
            remote_ip_prefix=rule_dict.get('remote_ip_prefix'),
            description=rule_dict.get('description')
        )
        context.session.add(db)
        res_rule_dict = self._make_security_group_rule_dict(db)
        kwargs['security_group_rule'] = res_rule_dict
        self._registry_notify(resources.SECURITY_GROUP_RULE,
                          events.PRECOMMIT_CREATE,
                          exc_cls=ext_sg.SecurityGroupConflict, **kwargs)
    registry.notify(
        resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, self,
        **kwargs)
    return res_rule_dict

securitygroups_db.SecurityGroupDbMixin._create_security_group_rule = (
    _create_security_group_rule)


# REVISIT(kent): Neutron doesn't pass the SG ID of the rule for the
# PRECOMMIT_DELETE event. Note that we should remove this in Pike as upstream
# has fixed the bug there
def delete_security_group_rule(self, context, id):
    kwargs = {
        'context': context,
        'security_group_rule_id': id
    }
    self._registry_notify(resources.SECURITY_GROUP_RULE,
                          events.BEFORE_DELETE, id=id,
                          exc_cls=ext_sg.SecurityGroupRuleInUse, **kwargs)

    with context.session.begin(subtransactions=True):
        query = self._model_query(context,
                                  sg_models.SecurityGroupRule).filter(
            sg_models.SecurityGroupRule.id == id)
        try:
            # As there is a filter on a primary key it is not possible for
            # MultipleResultsFound to be raised
            sg_rule = query.one()
        except exc.NoResultFound:
            raise ext_sg.SecurityGroupRuleNotFound(id=id)

        kwargs['security_group_id'] = sg_rule['security_group_id']
        self._registry_notify(resources.SECURITY_GROUP_RULE,
                              events.PRECOMMIT_DELETE,
                              exc_cls=ext_sg.SecurityGroupRuleInUse, id=id,
                              **kwargs)
        context.session.delete(sg_rule)

    registry.notify(
        resources.SECURITY_GROUP_RULE, events.AFTER_DELETE, self,
        **kwargs)

securitygroups_db.SecurityGroupDbMixin.delete_security_group_rule = (
    delete_security_group_rule)


def get_port_from_device_mac(context, device_mac):
    LOG.debug("get_port_from_device_mac() called for mac %s", device_mac)
    qry = context.session.query(models_v2.Port).filter_by(
        mac_address=device_mac).order_by(models_v2.Port.device_owner.desc())
    return qry.first()

ml2_db.get_port_from_device_mac = get_port_from_device_mac

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


def pre_session():
    from gbpservice.network.neutronv2 import local_api

    # The folowing are declared as global so that they can
    # used in the inner functions that follow.
    global PUSH_NOTIFICATIONS_METHOD
    global DISCARD_NOTIFICATIONS_METHOD
    PUSH_NOTIFICATIONS_METHOD = (
        local_api.post_notifications_from_queue)
    DISCARD_NOTIFICATIONS_METHOD = (
        local_api.discard_notifications_after_rollback)


def post_session(new_session):
    from gbpservice.network.neutronv2 import local_api
    new_session.notification_queue = {}

    if local_api.QUEUE_OUT_OF_PROCESS_NOTIFICATIONS:
        event.listen(new_session, "after_transaction_end",
                     gbp_after_transaction)
        event.listen(new_session, "after_rollback",
                     gbp_after_rollback)


def get_session(autocommit=True, expire_on_commit=False, use_slave=False):

    pre_session()
    # The following two lines are copied from the original
    # implementation of db_api.get_session() and should be updated
    # if the original implementation changes.
    new_session = db_api.context_manager.get_legacy_facade().get_session(
        autocommit=autocommit, expire_on_commit=expire_on_commit,
        use_slave=use_slave)

    post_session(new_session)
    return new_session


def get_writer_session():
    pre_session()

    new_session = db_api.context_manager.writer.get_sessionmaker()()
    post_session(new_session)
    return new_session


db_api.get_session = get_session
db_api.get_writer_session = get_writer_session


# REVISIT: This is temporary, the correct fix is to use
# the 'project_id' directly from the context rather than
# calling this method.
def _get_tenant_id_for_create(self, context, resource):
    if context.is_admin and 'tenant_id' in resource:
        tenant_id = resource['tenant_id']
    elif ('tenant_id' in resource and
          resource['tenant_id'] != context.project_id):
        reason = _('Cannot create resource for another tenant')
        raise n_exc.AdminRequired(reason=reason)
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
            raise ext_address_scope.AddressScopeInUse(address_scope_id=id)
        address_scope = self._get_address_scope(context, id)
        address_scope.delete()

address_scope_db.AddressScopeDbMixin.delete_address_scope = (
    _delete_address_scope)

try:
    import six

    from networking_sfc.db import flowclassifier_db
    from networking_sfc.extensions import flowclassifier as fc_ext

    if 'flowclassifier' in sys.modules:
        sys.modules['flowclassifier'].SUPPORTED_L7_PARAMETERS.update(
            sfc_cts.AIM_FLC_L7_PARAMS)
    if 'networking_sfc.extensions.flowclassifier' in sys.modules:
        sys.modules[
            ('networking_sfc.extensions.'
             'flowclassifier')].SUPPORTED_L7_PARAMETERS.update(
            sfc_cts.AIM_FLC_L7_PARAMS)
    # REVISIT(ivar): The following diff will fix flow classifier creation
    # method when using L7 parameters.
    # -            key: L7Parameter(key, val)
    # +            key: L7Parameter(keyword=key, value=val)
    # Also, make sure classifiers with different l7 params are not considered
    # conflicting

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
        with context.session.begin(subtransactions=True):
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
                    # REVISIT(ivar): Conflict considers l7_parameters
                    if (validators.is_attr_set(fc['l7_parameters']) and
                        validators.is_attr_set(
                            flow_classifier_db['l7_parameters'])):
                        if (fc['l7_parameters'] ==
                                flow_classifier_db['l7_parameters']):
                            raise fc_ext.FlowClassifierInConflict(
                                id=flow_classifier_db['id']
                            )
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

except ImportError:
    pass
