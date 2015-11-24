#########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from setuptools import setup


setup(
    zip_safe=True,
    name='cloudify-ldap-plugin',
    version='1.3',
    packages=[
        'active_directory',
        'active_directory.authentication'
    ],
    license='LICENSE',
    description='Cloudify security plugin for authentication and authorization'
                ' against active directory',
    install_requires=[
        'flask-securest==0.7',
        'python-ldap==2.4.6'
    ]
)