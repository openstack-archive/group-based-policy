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

try:
    import setuptools
except ImportError:
    import ez_setup
    ez_setup.use_setuptools()
    import setuptools

setuptools.setup(
    name='api',
    version='0.1',
    description='',
    author='',
    author_email='',
    install_requires=[
        "pecan",
    ],
    test_suite='api',
    zip_safe=False,
    include_package_data=True,
    packages=setuptools.find_packages(exclude=['ez_setup']),
    # Having entry point gives the option to define custom classes
    # to improve the flexibility in accessing different configurators
    entry_points="""
    [pecan.command]
    configurator_decider = configurator_decider:DecideConfigurator
    """
)
