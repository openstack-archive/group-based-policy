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

from gbpservice.nfp.core.event import Event
from gbpservice.nfp.proxy_agent.notifications import pull


def events_init(sc, conf):
    """Register event with its handler."""
    evs = [
        Event(id='PULL_NOTIFICATIONS',
              handler=pull.PullNotification(sc, conf))]
    sc.register_events(evs)


def nfp_module_init(sc, conf):
    """Initialize module to register rpc & event handler"""
    events_init(sc, conf)


def nfp_module_post_init(sc, conf):
    """Post a event for pull notification after each periodic_task_interval"""
    ev = sc.new_event(id='PULL_NOTIFICATIONS',
                      key='PULL_NOTIFICATIONS')
    sc.post_event(ev)
