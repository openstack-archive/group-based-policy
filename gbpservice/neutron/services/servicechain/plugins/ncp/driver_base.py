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

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class NodeDriverBase(object):
    """Node Driver Base class for Node Composition Plugin (NCP).

    A Node Driver is the fundamental unit of the NCP service chain plugin.
    It is invoked every time an operation has to be executed on Service Node
    instances (eg. services that are part of a deployed chain)
    which the Node Driver is capable of deploy, destroy and update.
    The Node Driver may expose resource needs to the NCP plugin, that will
    make sure that the NodeDriverContext is enriched with all that's needed by
    the driver.
    """

    @abc.abstractmethod
    def initialize(self, name):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called. Name is a unique attribute
        that identifies the driver.
        """
        pass

    @abc.abstractmethod
    def get_plumbing_info(self, context):
        """ Tells the NCP Plugin which kind of plumbing is needed by the Node.

        The plumbing info is defined as a collection of needed policy targets
        on a specific role, this may vary based on the node
        (obtained from the NodeDriverContext) that the specific driver is asked
        to deploy. An example of plumbing info is the following:

        {
            "management": <list of updated PT body dicts, one for each needed>,
            "provider": <list of updated PT body dicts, one for each needed>,
            "consumer": <list of updated PT body dicts, one for each needed>
        }

        The role (key of the above dictionary) specifies in which "side" the
        policy target has to exist. Depending on the kind of chaining the
        Neutron port could actually be placed somewhere else! The value
        is a list of attributes intended to override the PT body. This could
        be used, for example, for providing explicit Neutron Ports when the
        driver requires it or for establishing a naming convention for the PTs.
        An empty dictionary will be mostly used in this case, which will
        indicate a basic PT creation:

        {
            "management": [{}],  # One PT needed in the management
            "provider": [{}, {port_id: 'a'}],  # Two PT needed in the provider
            "consumer": []  # Zero PT needed in the consumer
        }
        """
        pass

    @abc.abstractmethod
    def validate_create(self, context):
        """Validate whether a SCN can be processed or not for creation.

        This method is intended as a indicative measure of whether the NCP
        plugin should use this specific driver for scheduling a given node.
        A successful validation is a prerequisite but doesn't guarantee that
        this driver will ultimately be chosen.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        """
        pass

    @abc.abstractmethod
    def validate_update(self, context):
        """Validate whether a SCN can be processed or not.

        This method will be called whenever a specific Node owned by this
        driver needs to be updated. It should be used to verify whether the
        Driver is capable of enforcing the update or not.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        """
        pass

    @abc.abstractmethod
    def create(self, context):
        """Instantiate a Service Chain Node based on the chain context.

        This method will be called at Service Chain instantiation time by the
        NCP plugin. Every scheduled Node Driver will be assigned a Node of the
        chain that has to be deployed based on the node definition and the
        service chain context. The same driver could be called multiple times
        on different nodes of the same chain.
        The datapath is expected to work according to the user intent at the
        end of the chain instantiation.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        """
        pass

    @abc.abstractmethod
    def delete(self, context):
        """Destroy a deployed Service Chain Node.

        This method will be called when a Service Chain Instance is destroyed
        or in case of node rescheduling. The driver is expected to undeploy the
        specific node and free the owned resources. Freeing the resources
        created by the NCP plugin as a consequence of the plumbing_info
        method belongs to the NCP plugin, and it is in charge of disposing
        them if needed.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        """
        pass

    @abc.abstractmethod
    def update(self, context):
        """Update a deployed Service Chain Node.

        Some changes in the Service Chain Node could need modifications in all
        its instances. This method will be used in order to synchronize the
        service configuration with the user expectation.
        The original node definition is provided in the context in order to
        calculate the difference if needed.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        """
        pass

    @abc.abstractmethod
    def update_policy_target_added(self, context, policy_target):
        """Update a deployed Service Chain Node on adding of a PT.

        This method can be used for auto scaling some services whenever a
        Policy Target is added to a relevant PTG.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        :param policy_target: Dict representing a Policy Target.
        """
        pass

    @abc.abstractmethod
    def update_policy_target_removed(self, context, policy_target):
        """Update a deployed Service Chain Node on removal of a PT.

        This method can be used for auto scaling some services whenever a
        Policy Target is removed from a relevant PTG.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        :param policy_target: Dict representing a Policy Target.
        """
        pass

    @abc.abstractmethod
    def update_node_consumer_ptg_added(self, context, policy_target_group):
        """Update a deployed Service Chain Node on addition of a consumer PTG.

        This method can be used for auto scaling some services whenever a
        Policy Target is added to a relevant PTG.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        :param policy_target_group: Dict representing a Policy Target Group.
        """
        pass

    @abc.abstractmethod
    def update_node_consumer_ptg_removed(self, context, policy_target_group):
        """Update a deployed Service Chain Node on removal of a consumer PTG.

        This method can be used for auto scaling some services whenever a
        Policy Target is removed from a relevant PTG.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        :param policy_target_group: Dict representing a Policy Target Group.
        """
        pass

    @abc.abstractmethod
    def notify_chain_parameters_updated(self, context):
        """Update a deployed Service Chain Node on GBP PRS updates

        This method can be used to inform the node driver that some parameter
        that affects the service chain is updated. The update may be
        something like adding or removing an Allow Rule to the ruleset and
        this has to be enforced in the Firewall Service VM, or it could simply
        be a classifier update.

        :param context: NodeDriverContext instance describing the service chain
        and the specific node to be processed by this driver.
        """
        pass

    @abc.abstractproperty
    def name(self):
        pass
