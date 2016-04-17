..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Heat Support
============

To enable simplified application oriented interfaces, OpenStack networking was
extended with policy and connectivity abstractions. Heat is extended with more
resources, which include policy and connectivity abstractions, through a new
Heat plugin.

Terminology
-----------

The terminology is consistent with the GBP resources
that the Heat resources refer to.

Internals
---------

The following Group-Based Policy Heat resources are available for consumption:
OS::GroupBasedPolicy::ExternalPolicy
OS::GroupBasedPolicy::ExternalSegment
OS::GroupBasedPolicy::L2Policy
OS::GroupBasedPolicy::L3Policy
OS::GroupBasedPolicy::NATPool
OS::GroupBasedPolicy::NetworkServicePolicy
OS::GroupBasedPolicy::PolicyAction
OS::GroupBasedPolicy::PolicyClassifier
OS::GroupBasedPolicy::PolicyRule
OS::GroupBasedPolicy::PolicyRuleSet
OS::GroupBasedPolicy::PolicyTarget
OS::GroupBasedPolicy::PolicyTargetGroup
OS::GroupBasedPolicy::ServiceChainNode
OS::GroupBasedPolicy::ServiceChainSpec
OS::GroupBasedPolicy::ServiceProfile
