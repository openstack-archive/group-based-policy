..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

Group-Based Policy Heat Support
==============================

To enable simplified application oriented interfaces, OpenStack networking was
extended with policy and connectivity abstractions. Heat is extended with more
resources, which include policy and connectivity abstractions, through a new
Heat plugin.

Terminology
-----------
The terminology is consistent with the GBP resources
that the Heat resources refer to.

Requirements
------------

Database models
---------------

Internals
---------
The following Group-Based Policy Heat resources are available for consumption:
* PolicyTarget
* PolicyTargetGroup
* L2Policy
* L3Policy
* PolicyClassifier
* PolicyAction
* PolicyRule
* PolicyRuleSet
* NetworkServicePolicy
* ExternalPolicy
* ExternalSegment
* NATPool

Configuration
-------------

References
----------
