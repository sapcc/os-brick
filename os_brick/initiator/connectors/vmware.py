# Copyright (c) 2016 VMware, Inc.
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

from oslo_log import log as logging
try:
    from oslo_vmware import api
    from oslo_vmware import exceptions as oslo_vmw_exceptions
    from oslo_vmware import image_transfer
    from oslo_vmware.objects import datastore
    from oslo_vmware import rw_handles
    from oslo_vmware import vim_util
except ImportError:
    vim_util = None

from os_brick import exception
from os_brick.i18n import _
from os_brick.initiator import initiator_connector

LOG = logging.getLogger(__name__)


class VmdkConnector(initiator_connector.InitiatorConnector):
    """Connector for volumes created by the VMDK driver.

    This connector is only used for backup and restore of Cinder volumes.
    """

    TMP_IMAGES_DATASTORE_FOLDER_PATH = "cinder_temp"

    def __init__(self, *args, **kwargs):
        # Check if oslo.vmware library is available.
        if vim_util is None:
            message = _("Missing oslo_vmware python module, ensure oslo.vmware"
                        " library is installed and available.")
            raise exception.BrickException(message=message)

        super(VmdkConnector, self).__init__(*args, **kwargs)

        self._ip = None
        self._port = None
        self._username = None
        self._password = None
        self._api_retry_count = None
        self._task_poll_interval = None
        self._ca_file = None
        self._insecure = None
        self._tmp_dir = None
        self._timeout = None

    @staticmethod
    def get_connector_properties(root_helper, *args, **kwargs):
        return {}

    def check_valid_device(self, path, *args, **kwargs):
        try:
            with open(path, 'r') as dev:
                dev.read(1)
        except IOError:
            LOG.exception(
                "Failed to access the device on the path "
                "%(path)s", {"path": path})
            return False
        return True

    def get_volume_paths(self, connection_properties):
        return []

    def get_search_path(self):
        return None

    def get_all_available_volumes(self, connection_properties=None):
        pass

    def _load_config(self, connection_properties):
        config = connection_properties['config']
        self._ip = config['vmware_host_ip']
        self._port = config['vmware_host_port']
        self._username = config['vmware_host_username']
        self._password = config['vmware_host_password']
        self._api_retry_count = config['vmware_api_retry_count']
        self._task_poll_interval = config['vmware_task_poll_interval']
        self._ca_file = config['vmware_ca_file']
        self._insecure = config['vmware_insecure']
        self._tmp_dir = config['vmware_tmp_dir']
        self._timeout = config['vmware_image_transfer_timeout_secs']

    def _create_session(self):
        return api.VMwareAPISession(self._ip,
                                    self._username,
                                    self._password,
                                    self._api_retry_count,
                                    self._task_poll_interval,
                                    port=self._port,
                                    cacert=self._ca_file,
                                    insecure=self._insecure)

    def connect_volume(self, connection_properties):
        self._load_config(connection_properties)
        session = self._create_session()
        if connection_properties.get('import_data'):
            handle = self.connect_volume_write_handle(session,
                                                      connection_properties)
        else:
            handle = self.connect_volume_read_handle(session,
                                                     connection_properties)
        return {'path': handle}

    def connect_volume_read_handle(self, session, connection_properties):
        vm_ref = vim_util.get_moref(connection_properties['volume'],
                                    'VirtualMachine')

        return rw_handles.VmdkReadHandle(session,
                                           self._ip,
                                           self._port,
                                           vm_ref,
                                           None,
                                           connection_properties['vmdk_size'])

    def connect_volume_write_handle(self, session, connection_properties):
        volume_ops = VolumeOps(session)
        vmdk_size = connection_properties['vmdk_size']
        import_data = connection_properties['import_data']
        import_data['profile_id'] = connection_properties['profile_id']
        import_data['vm']['name'] = "%s_brick" % connection_properties['name']
        return self._get_write_handle(import_data, volume_ops, vmdk_size)

    def _snapshot_exists(self, session, backing):
        snapshot = session.invoke_api(vim_util,
                                      'get_object_property',
                                      session.vim,
                                      backing,
                                      'snapshot')
        if snapshot is None or snapshot.rootSnapshotList is None:
            return False
        return len(snapshot.rootSnapshotList) != 0

    def _get_write_handle(self, import_data, volume_ops, file_size):
        import_spec = volume_ops.get_import_spec(import_data)
        folder = vim_util.get_moref(import_data['folder'],
                                    'Folder')
        rp = vim_util.get_moref(import_data['resource_pool'],
                                'ResourcePool')

        return rw_handles.VmdkWriteHandle(
            volume_ops._session,
            self._ip,
            self._port,
            rp,
            folder,
            import_spec,
            file_size,
            'POST')

    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        vmdk_handle = device_info['path']
        vmdk_handle.close()
        session = vmdk_handle._session
        if connection_properties.get('import_data'):
            volume_ops = VolumeOps(session)
            backing = vim_util.get_moref(connection_properties['volume'],
                                         "VirtualMachine")
            new_backing = vmdk_handle.get_imported_vm()
            # Currently there is no way we can restore the volume if it
            # contains redo-log based snapshots (bug 1599026).
            if self._snapshot_exists(session, backing):
                msg = (_("Backing of volume: %s contains one or more "
                         "snapshots; cannot disconnect.") %
                       connection_properties['volume_id'])
                volume_ops.delete_backing(new_backing)
                raise exception.BrickException(message=msg)

            volume_ops.delete_backing(backing)
            volume_ops.update_instance_uuid(new_backing,
                                            connection_properties['volume_id'])

        session.logout()

    def extend_volume(self, connection_properties):
        raise NotImplementedError


class VolumeOps:

    def __init__(self, session):
        self._session = session

    def get_import_spec(self, import_data):
        cf = self._session.vim.client.factory
        vm_import_spec = cf.create('ns0:VirtualMachineImportSpec')
        vm_import_spec.configSpec = self.get_vm_config_spec(import_data)

        return vm_import_spec

    def update_instance_uuid(self, vm_ref, uuid):
        cf = self._session.vim.client.factory
        config_spec = cf.create('ns0:VirtualMachineConfigSpec')
        config_spec.instanceUuid = uuid
        task = self._session.invoke_api(self._session.vim,
                                        'ReconfigVM_Task',
                                         vm_ref,
                                         spec=config_spec)
        self._session.wait_for_task(task)

    def get_vm_config_spec(self, import_data):
        vm = import_data['vm']
        cf = self._session.vim.client.factory
        vm_file_info = cf.create('ns0:VirtualMachineFileInfo')
        vm_file_info.vmPathName = vm['path_name']

        config_spec = cf.create('ns0:VirtualMachineConfigSpec')
        config_spec.name = vm['name']
        config_spec.guestId = vm['guest_id']
        config_spec.numCPUs = vm['num_cpus']
        config_spec.memoryMB = vm['memory_mb']
        config_spec.files = vm_file_info
        config_spec.version = vm['vmx_version']

        extra_config = vm['extra_config']
        if extra_config:
            config_spec.extraConfig = self._get_extra_config_option_values(
                extra_config)
        profile_id = import_data['profile_id']
        if profile_id:
            vm_profile = cf.create('ns0:VirtualMachineDefinedProfileSpec')
            vm_profile.profileId = profile_id
            config_spec.vmProfile = vm_profile

        config_spec.managedBy = self.\
            _create_managed_by_info(vm['extension_key'], vm['extension_type'])

        controller = import_data['controller']

        controller_spec = None
        if controller['create']:
            controller_device = cf.create('ns0:%s' % controller['type'])
            controller_device.key = controller['key']
            controller_device.busNumber = controller['bus_number']
            shared_bus = controller['shared_bus']
            if shared_bus:
                controller_device.sharedBus = shared_bus

            controller_spec = cf.create('ns0:VirtualDeviceConfigSpec')
            controller_spec.operation = 'add'
            controller_spec.device = controller_device

        disk = import_data['disk']
        disk_device = cf.create('ns0:VirtualDisk')
        disk_device.capacityInKB = disk['capacity_in_kb']
        disk_device.key = disk['key']
        disk_device.unitNumber = 0
        disk_device.controllerKey = controller['key']

        disk_device_bkng = cf.create('ns0:VirtualDiskFlatVer2BackingInfo')
        eagerly_scrub = disk['eagerly_scrub']
        thin_provisioned = disk['thin_provisioned']
        if eagerly_scrub:
            disk_device_bkng.eagerlyScrub = True
        elif thin_provisioned:
            disk_device_bkng.thinProvisioned = True
        disk_device_bkng.fileName = ''
        disk_device_bkng.diskMode = 'persistent'
        disk_device.backing = disk_device_bkng

        disk_spec = cf.create('ns0:VirtualDeviceConfigSpec')
        disk_spec.operation = 'add'
        disk_spec.fileOperation = 'create'
        disk_spec.device = disk_device
        profile_id = import_data['profile_id']
        if profile_id:
            disk_profile = cf.create('ns0:VirtualMachineDefinedProfileSpec')
            disk_profile.profileId = profile_id
            disk_spec.profile = [disk_profile]

        specs = [disk_spec]
        if controller_spec:
            specs.append(controller_spec)
        config_spec.deviceChange = specs

        return config_spec

    def _create_managed_by_info(self, extension_key, extension_type):
        managed_by = self._session.vim.client.factory.create(
            'ns0:ManagedByInfo')
        managed_by.extensionKey = extension_key
        managed_by.type = extension_type
        return managed_by

    def _get_extra_config_option_values(self, extra_config):
        cf = self._session.vim.client.factory
        option_values = []

        for key, value in extra_config.items():
            opt = cf.create('ns0:OptionValue')
            opt.key = key
            opt.value = value
            option_values.append(opt)

        return option_values

    def delete_backing(self, backing):
        """Delete the backing.

        :param backing: Managed object reference to the backing
        """
        LOG.debug("Deleting the VM backing: %s.", backing)
        task = self._session.invoke_api(self._session.vim, 'Destroy_Task',
                                        backing)
        LOG.debug("Initiated deletion of VM backing: %s.", backing)
        self._session.wait_for_task(task)
        LOG.info("Deleted the VM backing: %s.", backing)
