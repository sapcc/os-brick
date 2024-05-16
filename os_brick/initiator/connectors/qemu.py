# All Rights Reserved.
#
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

from os_brick.initiator import initiator_connector


class QemuConnector(initiator_connector.InitiatorConnector):
    """"Base for enabling the use of qemu block drivers."""

    def __init__(self, root_helper, driver=None,
                 *args, **kwargs):
        super(QemuConnector, self).__init__(root_helper, driver=driver,
                                            *args, **kwargs)

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        """The Qemu connector properties."""
        return {}

    def check_valid_device(self, path, run_as_root=True):
        # No point to check, as it is just a url conversion not a real device
        return True

    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        return True

    def get_volume_paths(self, connection_properties):
        """Return the list of existing paths for a volume.

        The job of this method is to find out what paths in
        the system are associated with a volume as described
        by the connection_properties.

        :param connection_properties: The dictionary that describes all
                                      of the target volume attributes.
        :type connection_properties: dict
        """
        return []

    def get_search_path(self):
        return None

    def extend_volume(self, connection_properties):
        raise NotImplementedError

    def get_all_available_volumes(self, connection_properties=None):
        return []

    def check_IO_handle_valid(self, handle, data_type, protocol):
        raise NotImplementedError


class QemuIScsiConnector(QemuConnector):
    """"Qemu internal IScsi block-driver"""

    def __init__(self, root_helper, driver=None,
                 *args, **kwargs):
        super(QemuIScsiConnector, self).__init__(root_helper, driver=driver,
                                                 *args, **kwargs)

    def connect_volume(self, connection_properties):
        data = connection_properties
        portal = data.get('target_portal') or data.get('target_portals')[0]
        iqn = data.get('target_iqn') or data.get('target_iqns')[0]
        lun = data.get('target_lun') or data.get('target_luns')[0]
        # auth_method = data.get('auth_method')
        username = data.get('auth_username')
        password = data.get('auth_password', '')
        if username:
            path = f'iscsi://{username}:{password}@{portal}/{iqn}/{lun}'
        else:
            path = f'iscsi://{portal}/{iqn}/{lun}'
        return {'path': path}
