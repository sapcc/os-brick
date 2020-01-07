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

import os
import tempfile

from oslo_log import log as logging
from oslo_utils import fileutils
try:
    from oslo_vmware import api
    from oslo_vmware import exceptions as oslo_vmw_exceptions
    from oslo_vmware import image_transfer
    from oslo_vmware.objects import datastore
    from oslo_vmware import rw_handles
    from oslo_vmware import vim_util
except ImportError:
    vim_util = None
import six

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

    def _create_temp_file(self, *args, **kwargs):
        fileutils.ensure_tree(self._tmp_dir)
        fd, tmp = tempfile.mkstemp(dir=self._tmp_dir, *args, **kwargs)
        os.close(fd)
        return tmp

    def _download_vmdk(
            self, tmp_file_path, session, backing, vmdk_path, vmdk_size):
        with open(tmp_file_path, "wb") as tmp_file:
            image_transfer.copy_stream_optimized_disk(
                None,
                self._timeout,
                tmp_file,
                session=session,
                host=self._ip,
                port=self._port,
                vm=backing,
                vmdk_file_path=vmdk_path,
                vmdk_size=vmdk_size)

    def connect_volume(self, connection_properties):
        # Download the volume vmdk from vCenter server to a temporary file
        # and return its path.
        self._load_config(connection_properties)
        session = self._create_session()

        tmp_file_path = self._create_temp_file(
            suffix=".vmdk", prefix=connection_properties['volume_id'])
        backing = vim_util.get_moref(connection_properties['volume'],
                                     "VirtualMachine")
        vmdk_path = connection_properties['vmdk_path']
        vmdk_size = connection_properties['vmdk_size']
        try:
            self._download_vmdk(
                tmp_file_path, session, backing, vmdk_path, vmdk_size)
        finally:
            session.logout()

        # Save the last modified time of the temporary so that we can decide
        # whether to upload the file back to vCenter server during disconnect.
        last_modified = os.path.getmtime(tmp_file_path)
        return {'path': tmp_file_path, 'last_modified': last_modified}

    def _snapshot_exists(self, session, backing):
        snapshot = session.invoke_api(vim_util,
                                      'get_object_property',
                                      session.vim,
                                      backing,
                                      'snapshot')
        if snapshot is None or snapshot.rootSnapshotList is None:
            return False
        return len(snapshot.rootSnapshotList) != 0

    def _create_temp_ds_folder(self, session, ds_folder_path, dc_ref):
        fileManager = session.vim.service_content.fileManager
        try:
            session.invoke_api(session.vim,
                               'MakeDirectory',
                               fileManager,
                               name=ds_folder_path,
                               datacenter=dc_ref)
        except oslo_vmw_exceptions.FileAlreadyExistsException:
            pass

    # Note(vbala) remove this method when we implement it in oslo.vmware
    def _upload_vmdk(
            self, read_handle, host, port, dc_name, ds_name, cookies,
            upload_file_path, file_size, cacerts, timeout_secs):
        write_handle = rw_handles.FileWriteHandle(host,
                                                  port,
                                                  dc_name,
                                                  ds_name,
                                                  cookies,
                                                  upload_file_path,
                                                  file_size,
                                                  cacerts=cacerts)
        image_transfer._start_transfer(read_handle, write_handle, timeout_secs)

    def _get_disk_device(self, session, backing):
        hardware_devices = session.invoke_api(vim_util,
                                              'get_object_property',
                                              session.vim,
                                              backing,
                                              'config.hardware.device')
        if hardware_devices.__class__.__name__ == "ArrayOfVirtualDevice":
            hardware_devices = hardware_devices.VirtualDevice
        for device in hardware_devices:
            if device.__class__.__name__ == "VirtualDisk":
                return device

    def _create_spec_for_disk_remove(self, session, disk_device):
        cf = session.vim.client.factory
        disk_spec = cf.create('ns0:VirtualDeviceConfigSpec')
        disk_spec.operation = 'remove'
        disk_spec.fileOperation = 'destroy'
        disk_spec.device = disk_device
        return disk_spec

    def _reconfigure_backing(self, session, backing, reconfig_spec):
        LOG.debug("Reconfiguring backing VM: %(backing)s with spec: %(spec)s.",
                  {'backing': backing,
                   'spec': reconfig_spec})
        reconfig_task = session.invoke_api(session.vim,
                                           "ReconfigVM_Task",
                                           backing,
                                           spec=reconfig_spec)
        LOG.debug("Task: %s created for reconfiguring backing VM.",
                  reconfig_task)
        session.wait_for_task(reconfig_task)

    def _detach_disk_from_backing(self, session, backing, disk_device):
        LOG.debug("Reconfiguring backing VM: %(backing)s to remove disk: "
                  "%(disk_device)s.",
                  {'backing': backing, 'disk_device': disk_device})

        cf = session.vim.client.factory
        reconfig_spec = cf.create('ns0:VirtualMachineConfigSpec')
        spec = self._create_spec_for_disk_remove(session, disk_device)
        reconfig_spec.deviceChange = [spec]
        self._reconfigure_backing(session, backing, reconfig_spec)

    def _attach_disk_to_backing(self, session, backing, disk_device):
        LOG.debug("Reconfiguring backing VM: %(backing)s to add disk: "
                  "%(disk_device)s.",
                  {'backing': backing, 'disk_device': disk_device})

        cf = session.vim.client.factory
        reconfig_spec = cf.create('ns0:VirtualMachineConfigSpec')
        disk_spec = cf.create('ns0:VirtualDeviceConfigSpec')
        disk_spec.operation = 'add'
        disk_spec.device = disk_device
        reconfig_spec.deviceChange = [disk_spec]
        self._reconfigure_backing(session, backing, reconfig_spec)

    def _disconnect(self, backing, session, tmp_file_path, tmp_file,
                    tmp_file_size, ds_ref, dc_ref, vmdk_path):
        # The restored volume is in compressed (streamOptimized) format.
        # So we upload it to a temporary location in vCenter datastore and copy
        # the compressed vmdk to the volume vmdk. The copy operation
        # decompresses the disk to a format suitable for attaching to Nova
        # instances in vCenter.
        dstore = datastore.get_datastore_by_ref(session, ds_ref)
        ds_path = dstore.build_path(
            VmdkConnector.TMP_IMAGES_DATASTORE_FOLDER_PATH,
            os.path.basename(tmp_file_path))
        self._create_temp_ds_folder(
            session, six.text_type(ds_path.parent), dc_ref)

        dc_name = session.invoke_api(
                vim_util, 'get_object_property', session.vim, dc_ref, 'name')
        cookies = session.vim.client.options.transport.cookiejar
        cacerts = self._ca_file if self._ca_file else not self._insecure
        self._upload_vmdk(
                tmp_file, self._ip, self._port, dc_name, dstore.name, cookies,
                ds_path.rel_path, tmp_file_size, cacerts,
                self._timeout)

        disk_device = self._get_disk_device(session, backing)
        self._detach_disk_from_backing(session, backing, disk_device)

        src = six.text_type(ds_path)
        LOG.debug("Copying %(src)s to %(dest)s", {'src': src,
                                                  'dest': vmdk_path})
        disk_mgr = session.vim.service_content.virtualDiskManager
        task = session.invoke_api(session.vim,
                                  'CopyVirtualDisk_Task',
                                  disk_mgr,
                                  sourceName=src,
                                  sourceDatacenter=dc_ref,
                                  destName=vmdk_path,
                                  destDatacenter=dc_ref)
        session.wait_for_task(task)

        self._attach_disk_to_backing(session, backing, disk_device)

        # Delete the compressed vmdk at the temporary location.
        LOG.debug("Deleting %s", src)
        file_mgr = session.vim.service_content.fileManager
        task = session.invoke_api(session.vim,
                                  'DeleteDatastoreFile_Task',
                                  file_mgr,
                                  name=src,
                                  datacenter=dc_ref)
        session.wait_for_task(task)

    def _disconnect_with_import(self, import_data, volume_ops, backing,
                                tmp_file, file_size):
        import_spec = volume_ops.get_import_spec(import_data)
        folder = vim_util.get_moref(import_data['folder'],
                                    'Folder')
        rp = vim_util.get_moref(import_data['resource_pool'],
                                'ResourcePool')

        volume_ops.delete_backing(backing)
        write_handle = rw_handles.VmdkWriteHandle(
            volume_ops._session,
            self._ip,
            self._port,
            rp,
            folder,
            import_spec,
            file_size,
            'POST')
        image_transfer._start_transfer(tmp_file, write_handle, self._timeout)

    def disconnect_volume(self, connection_properties, device_info,
                          force=False, ignore_errors=False):
        tmp_file_path = device_info['path']
        if not os.path.exists(tmp_file_path):
            msg = _("Vmdk: %s not found.") % tmp_file_path
            raise exception.NotFound(message=msg)

        session = None
        try:
            # We upload the temporary file to vCenter server only if it is
            # modified after connect_volume.
            if os.path.getmtime(tmp_file_path) > device_info['last_modified']:
                self._load_config(connection_properties)
                session = self._create_session()
                backing = vim_util.get_moref(connection_properties['volume'],
                                             "VirtualMachine")
                # Currently there is no way we can restore the volume if it
                # contains redo-log based snapshots (bug 1599026).
                if self._snapshot_exists(session, backing):
                    msg = (_("Backing of volume: %s contains one or more "
                             "snapshots; cannot disconnect.") %
                           connection_properties['volume_id'])
                    raise exception.BrickException(message=msg)

                ds_ref = vim_util.get_moref(
                    connection_properties['datastore'], "Datastore")
                dc_ref = vim_util.get_moref(
                    connection_properties['datacenter'], "Datacenter")
                vmdk_path = connection_properties['vmdk_path']

                with open(tmp_file_path, "rb") as tmp_file:
                    file_size = os.path.getsize(tmp_file_path)
                    import_data = connection_properties.get('import_data')
                    if import_data:
                        import_data = connection_properties['import_data']
                        import_data['profile_id'] = connection_properties[
                            'profile_id']
                        import_data['vm']['name'] = connection_properties[
                            'name']
                        import_data['vm']['uuid'] = connection_properties[
                            'volume_id']
                        self._disconnect_with_import(import_data,
                                                     VolumeOps(session),
                                                     backing,
                                                     tmp_file,
                                                     file_size)
                    else:
                        self._disconnect(backing, session, tmp_file_path,
                                         tmp_file, file_size, ds_ref, dc_ref,
                                         vmdk_path)
        finally:
            os.remove(tmp_file_path)
            if session:
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
        config_spec.instanceUuid = vm['uuid']

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
