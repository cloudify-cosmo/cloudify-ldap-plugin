#########
# Copyright (c) 2016 GigaSpaces Technologies Ltd. All rights reserved
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
import logging

from ldap_authentication_provider import LDAPAuthenticationProvider
from flask_securest import constants

DEFAULT_AUTH_ATTR_NAME = 'sAMAccountName'

_logger = logging.getLogger(constants.FLASK_SECUREST_LOGGER_NAME)


class ActiveDirectoryAuthenticationProvider(LDAPAuthenticationProvider):

    def __init__(self, ldap_url, domain_name=None, search_properties=None):
        super(ActiveDirectoryAuthenticationProvider, self)\
            .__init__(ldap_url, search_properties)
        self.domain_name = domain_name

    def authenticate(self, *args, **kwargs):
        who, password = self.get_creds_from_request()

        if self.search_props:
            self.search_props.setdefault('user_id_attribute',
                                         DEFAULT_AUTH_ATTR_NAME)
            user_dn = self.get_dn_by_user_attribute(who,
                                                    self.ldap_url,
                                                    **self.search_props)
        else:
            _logger.debug('Attempting to bind using the user id provided: '
                          '{user_id} and domain name: {domain}'
                          .format(user_id=who, domain=self.domain_name))
            if self.domain_name:
                user_dn = '{0}@{1}'.format(who, self.domain_name)
            else:
                user_dn = who
        _logger.debug('Validating bind for user {who} according to user_id '
                      '{id}'.format(who=who, id=user_dn))
        self.validate_bind(self.ldap_url, user_dn, password)
        return who
