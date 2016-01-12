#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
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

import ldap
from flask_securest.authentication_providers.abstract_authentication_provider \
    import AbstractAuthenticationProvider
from flask_securest import utils
from flask_securest import constants
from flask_securest.exceptions import AuthenticationException

DN_ATTRIBUTE_NAME = 'DN'
DEFAULT_AUTH_ATTR_NAME = 'uid'

REQ_SEARCH_FIELDS = ('base_dn', 'admin_user_id', 'admin_password')

_logger = logging.getLogger(constants.FLASK_SECUREST_LOGGER_NAME)


class LDAPAuthenticationProvider(AbstractAuthenticationProvider):

    def __init__(self, ldap_url, search_properties=None):
        self.ldap_url = ldap_url
        self.search_props = search_properties
        self.validate_search_props()

    def validate_search_props(self):
        if self.search_props:
            valid = all(test in self.search_props for test in
                        REQ_SEARCH_FIELDS)
            if not valid:
                err = 'The configured search_properties are missing required '\
                      'search fields. Search properties must hold values for '\
                      'the following fields: \'{req_fields}\', got '\
                      '\'{props_fields}\''\
                    .format(req_fields=REQ_SEARCH_FIELDS,
                            props_fields=tuple(self.search_props.keys()))
                _logger.warning(err)
                raise RuntimeError(err)

    def authenticate(self, *args, **kwargs):
        who, password = self.get_creds_from_request()
        # LDAP bind authentication can be done by subtree match or according to
        # dn attribute.
        if self.search_props:
            user_dn = self.get_dn_by_user_attribute(who,
                                                    self.ldap_url,
                                                    **self.search_props)
        else:
            user_dn = who
        # attempt to bind using the matching user ID/DN and provided password.
        self.validate_bind(self.ldap_url, user_dn, password)
        return who

    @staticmethod
    def handle_authentication_error(err, conn=None):
        if conn:
            conn.unbind()
        _logger.warning(err)
        raise AuthenticationException(err)

    @staticmethod
    def validate_bind(ldap_url, who, password):
            conn = LDAPAuthenticationProvider.create_bind_conn(ldap_url,
                                                               who,
                                                               password)
            conn.unbind()

    @staticmethod
    def get_dn_by_user_attribute(who,
                                 ldap_url,
                                 base_dn,
                                 admin_user_id,
                                 admin_password,
                                 user_id_attribute=DEFAULT_AUTH_ATTR_NAME):

        search_filter = '{0}={1}'.format(user_id_attribute, who)
        try:
            conn = LDAPAuthenticationProvider.create_bind_conn(ldap_url,
                                                               admin_user_id,
                                                               admin_password)
            # Search for matches under the base_dn subtree using the attribute
            # search filter.
            ldap_result_id = conn.search(base_dn,
                                         ldap.SCOPE_SUBTREE,
                                         search_filter,
                                         [DN_ATTRIBUTE_NAME])
        except AuthenticationException as e:
            err = 'Failed binding to \'{0}\' using the dedicated ' \
                  'admin_user_id: {1}, provided in the configuration; {2}' \
                  .format(ldap_url, admin_user_id, e)
            LDAPAuthenticationProvider.handle_authentication_error(err)
        except ldap.LDAPError as e:
            err = 'Failed searching for user under base DN: {0}, according ' \
                  'to the following attribute filter pattern {1}; {2}' \
                .format(base_dn, search_filter, e)
            LDAPAuthenticationProvider.handle_authentication_error(err, conn)

        try:
            # Retrieve query results according to the result ID in order to
            # obtain the user DN to bind with.
            result_type, result_data = conn.result(ldap_result_id, 1)
            if result_data:
                if result_type != ldap.RES_SEARCH_RESULT:
                    raise RuntimeError('An unexpected result object was '
                                       'returned by the search: {result_type}'
                                       .format(result_type=result_type))
            else:
                raise RuntimeError('An empty result was returned by the search'
                                   ' for user id \'{user_id}\''
                                   .format(user_id=who))
        except ldap.LDAPError as e:
            err = 'User \'{user_id}\' not found; {error}' \
                .format(user_id=who, error=e)
            LDAPAuthenticationProvider.handle_authentication_error(err, conn)

        # unbind admin connection.
        conn.unbind()

        if len(result_data) != 1:
            err = 'Expecting a single result matching for user with ' \
                  'user_id {0}. Found {1}.' \
                .format(who, len(result_data))
            LDAPAuthenticationProvider.handle_authentication_error(err, conn)

        # extract the user DN from the search result.
        return result_data[0][0]

    @staticmethod
    def create_bind_conn(ldap_url, who, password):
        # initialize connection to the LDAP server
        try:
            conn = ldap.initialize(ldap_url)
        except ldap.LDAPError as e:
            err = 'Failed to initialize LDAP connection to {0}; {1}'\
                .format(ldap_url, e)
            _logger.warning(err)
            raise RuntimeError(err)

        # bind using the provided credentials
        try:
            conn.bind_s(who, password)
        except ldap.INVALID_CREDENTIALS as e:
            err = 'Invalid credentials provided for user: \'{0}\'; error {1}'\
                .format(who, e)
            LDAPAuthenticationProvider.handle_authentication_error(err, conn)
        except ldap.LDAPError as e:
            err = 'Failed to bind user \'{0}\'; {1}' \
                .format(who, e)
            LDAPAuthenticationProvider.handle_authentication_error(err, conn)

        return conn

    @staticmethod
    def get_creds_from_request():
        return utils.get_basic_http_authentication_info()
