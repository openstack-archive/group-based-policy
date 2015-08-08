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


# An Endpoint needs to be directly reachable by the consumers,
# it is basically a traditi onal PT presented in the form of a service.
# This kind of services are typically useful only when directly addressed, and
# are irrelevant to the traffic course otherwise. The Endpoint Services
# typically get a VIP on the provider subnet.
# Example Services: L4-7 Load Balancer (Reverse Proxy)
PLUMBING_TYPE_ENDPOINT = 'endpoint'

# A gateway service is a router that the PTs will use for reaching certain
# (or all the) destinations. This kind of service usually works on the packets
# that it's entitled to route, never modifying the Source IP Address.
# Traffic can indeed be dropped, inspected or otherwise manipulated by this
# kind of service.
# Router, Firewall, -Transport- Mode VPN
PLUMBING_TYPE_GATEWAY = 'gateway'

# Rationale: A transparent service is either a L2 or a BITW service.
# This kind of service usually has 2 logical data interfaces, and everything
# that is received in either of them is pushed on the other after processing.
# The 2 interfaces typically exist in the same subnet, so traffic is not router
# but switched (or simply mirrored) instead.
# Example Services: Transparent FW, IDS, IPS, Accounting, Traffic Shaping
PLUMBING_TYPE_TRANSPARENT = 'transparent'

PLUMBING_TYPES = [PLUMBING_TYPE_ENDPOINT,
                  PLUMBING_TYPE_GATEWAY,
                  PLUMBING_TYPE_TRANSPARENT]
