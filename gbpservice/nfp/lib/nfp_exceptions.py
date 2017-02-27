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


class GenericException(Exception):

    def __init__(self, type, value, traceback):
        super(GenericException, self).__init__(type, value)


class DbException(GenericException):
    pass


class NeutronException(GenericException):
    pass


class NovaException(GenericException):
    pass


class KeystoneException(GenericException):
    pass


class GBPException(GenericException):
    pass


class HeatException(GenericException):
    pass
