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

import ddt
import mock
from oslo_utils import units
from oslo_vmware.objects import datastore
from oslo_vmware import vim_util

from os_brick import exception
from os_brick.initiator.connectors import vmware
from os_brick.tests.initiator import test_connector


@ddt.ddt
class VmdkConnectorTestCase(test_connector.ConnectorTestCase):

    IP = '127.0.0.1'
    PORT = 443
    USERNAME = 'username'
    PASSWORD = 'password'
    API_RETRY_COUNT = 3
    TASK_POLL_INTERVAL = 5.0
    CA_FILE = "/etc/ssl/rui-ca-cert.pem"
    TMP_DIR = "/vmware-tmp"
    IMG_TX_TIMEOUT = 10

    VMDK_CONNECTOR = vmware.VmdkConnector
    VMDK_VOLUMEOPS = vmware.VolumeOps

    def setUp(self):
        super(VmdkConnectorTestCase, self).setUp()

        self._connector = vmware.VmdkConnector(None)
        self._connector._ip = self.IP
        self._connector._port = self.PORT
        self._connector._username = self.USERNAME
        self._connector._password = self.PASSWORD
        self._connector._api_retry_count = self.API_RETRY_COUNT
        self._connector._task_poll_interval = self.TASK_POLL_INTERVAL
        self._connector._ca_file = self.CA_FILE
        self._connector._insecure = True
        self._connector._tmp_dir = self.TMP_DIR
        self._connector._timeout = self.IMG_TX_TIMEOUT

    def test_load_config(self):
        config = {
            'vmware_host_ip': 'localhost',
            'vmware_host_port': 1234,
            'vmware_host_username': 'root',
            'vmware_host_password': 'pswd',
            'vmware_api_retry_count': 1,
            'vmware_task_poll_interval': 1.0,
            'vmware_ca_file': None,
            'vmware_insecure': False,
            'vmware_tmp_dir': '/tmp',
            'vmware_image_transfer_timeout_secs': 5,
        }
        self._connector._load_config({'config': config})

        self.assertEqual('localhost', self._connector._ip)
        self.assertEqual(1234, self._connector._port)
        self.assertEqual('root', self._connector._username)
        self.assertEqual('pswd', self._connector._password)
        self.assertEqual(1, self._connector._api_retry_count)
        self.assertEqual(1.0, self._connector._task_poll_interval)
        self.assertIsNone(self._connector._ca_file)
        self.assertFalse(self._connector._insecure)
        self.assertEqual('/tmp', self._connector._tmp_dir)
        self.assertEqual(5, self._connector._timeout)

    @mock.patch('oslo_vmware.api.VMwareAPISession')
    def test_create_session(self, session):
        session.return_value = mock.sentinel.session

        ret = self._connector._create_session()

        self.assertEqual(mock.sentinel.session, ret)
        session.assert_called_once_with(
            self._connector._ip,
            self._connector._username,
            self._connector._password,
            self._connector._api_retry_count,
            self._connector._task_poll_interval,
            port=self._connector._port,
            cacert=self._connector._ca_file,
            insecure=self._connector._insecure)

    @mock.patch('oslo_utils.fileutils.ensure_tree')
    @mock.patch('tempfile.mkstemp')
    @mock.patch('os.close')
    def test_create_temp_file(
            self, close, mkstemp, ensure_tree):
        fd = mock.sentinel.fd
        tmp = mock.sentinel.tmp
        mkstemp.return_value = (fd, tmp)

        prefix = ".vmdk"
        suffix = "test"
        ret = self._connector._create_temp_file(prefix=prefix, suffix=suffix)

        self.assertEqual(tmp, ret)
        ensure_tree.assert_called_once_with(self._connector._tmp_dir)
        mkstemp.assert_called_once_with(dir=self._connector._tmp_dir,
                                        prefix=prefix,
                                        suffix=suffix)
        close.assert_called_once_with(fd)

    @mock.patch('os_brick.initiator.connectors.vmware.open', create=True)
    @mock.patch('oslo_vmware.image_transfer.copy_stream_optimized_disk')
    def test_download_vmdk(self, copy_disk, file_open):
        file_open_ret = mock.Mock()
        tmp_file = mock.sentinel.tmp_file
        file_open_ret.__enter__ = mock.Mock(return_value=tmp_file)
        file_open_ret.__exit__ = mock.Mock(return_value=None)
        file_open.return_value = file_open_ret

        tmp_file_path = mock.sentinel.tmp_file_path
        session = mock.sentinel.session
        backing = mock.sentinel.backing
        vmdk_path = mock.sentinel.vmdk_path
        vmdk_size = mock.sentinel.vmdk_size
        self._connector._download_vmdk(
            tmp_file_path, session, backing, vmdk_path, vmdk_size)

        file_open.assert_called_once_with(tmp_file_path, 'wb')
        copy_disk.assert_called_once_with(None,
                                          self._connector._timeout,
                                          tmp_file,
                                          session=session,
                                          host=self._connector._ip,
                                          port=self._connector._port,
                                          vm=backing,
                                          vmdk_file_path=vmdk_path,
                                          vmdk_size=vmdk_size)

    def _create_connection_properties(self):
        return {'volume_id': 'ed083474-d325-4a99-b301-269111654f0d',
                'volume': 'ref-1',
                'vmdk_path': '[ds] foo/bar.vmdk',
                'profile_id': 'profile-1',
                'name': 'volume-name-001',
                'vmdk_size': units.Gi,
                'datastore': 'ds-1',
                'datacenter': 'dc-1',
                }

    @mock.patch.object(VMDK_CONNECTOR, '_load_config')
    @mock.patch.object(VMDK_CONNECTOR, '_create_session')
    @mock.patch.object(VMDK_CONNECTOR, '_create_temp_file')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch.object(VMDK_CONNECTOR, '_download_vmdk')
    @mock.patch('os.path.getmtime')
    def test_connect_volume(
            self, getmtime, download_vmdk, get_moref, create_temp_file,
            create_session, load_config):
        session = mock.Mock()
        create_session.return_value = session

        tmp_file_path = mock.sentinel.tmp_file_path
        create_temp_file.return_value = tmp_file_path

        backing = mock.sentinel.backing
        get_moref.return_value = backing

        last_modified = mock.sentinel.last_modified
        getmtime.return_value = last_modified

        props = self._create_connection_properties()
        ret = self._connector.connect_volume(props)

        self.assertEqual(tmp_file_path, ret['path'])
        self.assertEqual(last_modified, ret['last_modified'])
        load_config.assert_called_once_with(props)
        create_session.assert_called_once_with()
        create_temp_file.assert_called_once_with(
            suffix=".vmdk", prefix=props['volume_id'])
        download_vmdk.assert_called_once_with(
            tmp_file_path, session, backing, props['vmdk_path'],
            props['vmdk_size'])
        session.logout.assert_called_once_with()

    @ddt.data((None, False), ([mock.sentinel.snap], True))
    @ddt.unpack
    def test_snapshot_exists(self, snap_list, exp_return_value):
        snapshot = mock.Mock(rootSnapshotList=snap_list)
        session = mock.Mock()
        session.invoke_api.return_value = snapshot

        backing = mock.sentinel.backing
        ret = self._connector._snapshot_exists(session, backing)

        self.assertEqual(exp_return_value, ret)
        session.invoke_api.assert_called_once_with(
            vim_util, 'get_object_property', session.vim, backing, 'snapshot')

    def test_create_temp_ds_folder(self):
        session = mock.Mock()
        ds_folder_path = mock.sentinel.ds_folder_path
        dc_ref = mock.sentinel.dc_ref
        self._connector._create_temp_ds_folder(session, ds_folder_path, dc_ref)

        session.invoke_api.assert_called_once_with(
            session.vim,
            'MakeDirectory',
            session.vim.service_content.fileManager,
            name=ds_folder_path,
            datacenter=dc_ref)

    @mock.patch('oslo_vmware.objects.datastore.get_datastore_by_ref')
    @mock.patch.object(VMDK_CONNECTOR, '_create_temp_ds_folder')
    @mock.patch.object(VMDK_CONNECTOR, '_upload_vmdk')
    def test_disconnect(self, upload_vmdk, create_temp_ds_folder,
                        get_ds_by_ref):
        ds_ref = mock.sentinel.ds_ref
        ds_name = 'datastore-1'
        dstore = datastore.Datastore(ds_ref, ds_name)
        get_ds_by_ref.return_value = dstore

        tmp_file = mock.sentinel.tmp_file

        dc_name = mock.sentinel.dc_name
        delete_task = mock.sentinel.delete_vdisk_task
        copy_task = mock.sentinel.copy_vdisk_task
        delete_file_task = mock.sentinel.delete_file_task
        session = mock.Mock()
        session.invoke_api.side_effect = [
            dc_name, delete_task, copy_task, delete_file_task]

        tmp_file_path = '/tmp/foo.vmdk'
        dc_ref = mock.sentinel.dc_ref
        vmdk_path = mock.sentinel.vmdk_path
        file_size = 1024
        self._connector._disconnect(
            session, tmp_file_path, tmp_file, file_size, ds_ref, dc_ref,
            vmdk_path)

        tmp_folder_path = self._connector.TMP_IMAGES_DATASTORE_FOLDER_PATH
        ds_folder_path = '[%s] %s' % (ds_name, tmp_folder_path)
        create_temp_ds_folder.assert_called_once_with(
            session, ds_folder_path, dc_ref)

        self.assertEqual(
            mock.call(vim_util, 'get_object_property', session.vim, dc_ref,
                      'name'), session.invoke_api.call_args_list[0])

        exp_rel_path = '%s/foo.vmdk' % tmp_folder_path
        upload_vmdk.assert_called_once_with(
            tmp_file, self._connector._ip, self._connector._port, dc_name,
            ds_name, session.vim.client.options.transport.cookiejar,
            exp_rel_path, file_size, self._connector._ca_file,
            self._connector._timeout)

        disk_mgr = session.vim.service_content.virtualDiskManager
        self.assertEqual(
            mock.call(session.vim, 'DeleteVirtualDisk_Task', disk_mgr,
                      name=vmdk_path, datacenter=dc_ref),
            session.invoke_api.call_args_list[1])
        self.assertEqual(mock.call(delete_task),
                         session.wait_for_task.call_args_list[0])

        src = '[%s] %s' % (ds_name, exp_rel_path)
        self.assertEqual(
            mock.call(session.vim, 'CopyVirtualDisk_Task', disk_mgr,
                      sourceName=src, sourceDatacenter=dc_ref,
                      destName=vmdk_path, destDatacenter=dc_ref),
            session.invoke_api.call_args_list[2])
        self.assertEqual(mock.call(copy_task),
                         session.wait_for_task.call_args_list[1])

        file_mgr = session.vim.service_content.fileManager
        self.assertEqual(
            mock.call(session.vim, 'DeleteDatastoreFile_Task', file_mgr,
                      name=src, datacenter=dc_ref),
            session.invoke_api.call_args_list[3])
        self.assertEqual(mock.call(delete_file_task),
                         session.wait_for_task.call_args_list[2])

    @mock.patch('oslo_vmware.image_transfer._start_transfer')
    @mock.patch('oslo_vmware.rw_handles.VmdkWriteHandle')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch('os_brick.initiator.connectors.vmware.VolumeOps')
    def test_disconnect_with_import(self, vops, get_moref, vmdk_write_handle,
                                    start_transfer):
        import_spec = mock.Mock()
        session = mock.sentinel.session
        backing = mock.sentinel.backing
        tmp_file = mock.sentinel.file
        file_size = 1024
        import_data = {
            'folder': mock.sentinel.folder,
            'resource_pool': mock.sentinel.resource_pool
        }
        vops._session = mock.sentinel._session
        vops.get_import_spec.return_value = import_spec
        get_moref.side_effect = [import_data['folder'], import_data[
            'resource_pool']]
        vmdk_write_handle_ret = mock.sentinel.vmdk_write_handle
        vmdk_write_handle.return_value = vmdk_write_handle_ret

        self._connector._disconnect_with_import(import_data, vops,
                                                backing, tmp_file, file_size)

        vops.delete_backing.assert_called_once_with(backing)

        vmdk_write_handle.assert_called_once_with(vops._session,
                                    self._connector._ip,
                                    self._connector._port,
                                    import_data['resource_pool'],
                                    import_data['folder'],
                                    import_spec,
                                    file_size,
                                    'POST')

        start_transfer.assert_called_once_with(tmp_file,
                                               vmdk_write_handle_ret,
                                               self._connector._timeout)


    @mock.patch('os.path.exists')
    def test_disconnect_volume_with_missing_temp_file(self, path_exists):
        path_exists.return_value = False

        path = mock.sentinel.path
        self.assertRaises(exception.NotFound,
                          self._connector.disconnect_volume,
                          mock.ANY,
                          {'path': path})
        path_exists.assert_called_once_with(path)

    @mock.patch('os.path.exists')
    @mock.patch('os.path.getmtime')
    @mock.patch.object(VMDK_CONNECTOR, '_disconnect')
    @mock.patch('os.remove')
    def test_disconnect_volume_with_unmodified_file(
            self, remove, disconnect, getmtime, path_exists):
        path_exists.return_value = True

        mtime = 1467802060
        getmtime.return_value = mtime

        path = mock.sentinel.path
        self._connector.disconnect_volume(mock.ANY, {'path': path,
                                                     'last_modified': mtime})

        path_exists.assert_called_once_with(path)
        getmtime.assert_called_once_with(path)
        disconnect.assert_not_called()
        remove.assert_called_once_with(path)

    @mock.patch('os_brick.initiator.connectors.vmware.VolumeOps')
    @mock.patch('os_brick.initiator.connectors.vmware.open', create=True)
    @mock.patch('os.path.getsize')
    @mock.patch('os.path.exists')
    @mock.patch('os.path.getmtime')
    @mock.patch.object(VMDK_CONNECTOR, '_load_config')
    @mock.patch.object(VMDK_CONNECTOR, '_create_session')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch.object(VMDK_CONNECTOR, '_snapshot_exists')
    @mock.patch.object(VMDK_CONNECTOR, '_disconnect')
    @mock.patch('os.remove')
    @mock.patch.object(VMDK_CONNECTOR, '_disconnect_with_import')
    def test_disconnect_volume(
            self, disconnect_with_import, remove, disconnect, snapshot_exists,
            get_moref, create_session, load_config, getmtime, path_exists,
            path_getsize, open_file, vops, import_data=False):

        path_exists.return_value = True
        file_size = 1024
        path_getsize.return_value = file_size
        mtime = 1467802060
        getmtime.return_value = mtime

        session = mock.Mock()
        create_session.return_value = session

        snapshot_exists.return_value = False

        backing = mock.sentinel.backing
        ds_ref = mock.sentinel.ds_ref
        dc_ref = mock.sentinel.dc_ref
        get_moref.side_effect = [backing, ds_ref, dc_ref]

        props = self._create_connection_properties()
        if import_data:
            props['import_data'] = {'vm': {}}

        path = mock.sentinel.path
        tmp_file = mock.sentinel.tmp_file
        file_open_ret = mock.Mock()
        file_open_ret.__enter__ = mock.Mock(return_value=tmp_file)
        file_open_ret.__exit__ = mock.Mock(return_value=None)
        open_file.return_value = file_open_ret
        vops_ret = mock.Mock(_session=session)
        vops.return_value = vops_ret

        self._connector.disconnect_volume(props, {'path': path,
                                                  'last_modified': mtime - 1})
        path_exists.assert_called_once_with(path)
        getmtime.assert_called_once_with(path)
        open_file.assert_called_once_with(path, "rb")
        load_config.assert_called_once_with(props)
        create_session.assert_called_once_with()
        snapshot_exists.assert_called_once_with(session, backing)
        path_getsize.assert_called_once_with(path)
        if import_data:
            disconnect.assert_not_called()
            disconnect_with_import.assert_called_once_with(
                props['import_data'], vops_ret, backing, tmp_file, file_size)
        else:
            disconnect.assert_called_once_with(
            session, path, tmp_file, file_size, ds_ref, dc_ref,
                props['vmdk_path'])
            disconnect_with_import.assert_not_called()
        remove.assert_called_once_with(path)
        session.logout.assert_called_once_with()

    def test_disconnect_volume_with_import(self):
        self.test_disconnect_volume(import_data=True)

    @staticmethod
    def _create_import_data(folder=None, rp=None):
        return {
            'profile_id': 'profile-1',
            'folder': folder.value if folder else mock.Mock(),
            'resource_pool': rp.value if rp else mock.Mock(),
            'vm': {
                'name': 'vm-1',
                'uuid': '0-1-2-3',
                'path_name': '[ds-1]',
                'guest_id': 'guest-id',
                'num_cpus': 1,
                'memory_mb': 128,
                'vmx_version': 'vmx-8',
                'extension_key': 'foo-extension-key',
                'extension_type': 'foo-extension-type',
                'extra_config': {'foo': 'bar'}
            },
            'adapter_type': mock.Mock(),
            'controller': {
                'type': 'controllerTypeOne',
                'key': 1,
                'create': True,
                'shared_bus': 'shared',
                'bus_number': 1
            },
            'disk': {
                'type': 'diskTypeOne',
                'key': -101,
                'capacity_in_kb': 1024 * 1024,
                'eagerly_scrub': None,
                'thin_provisioned': True
            }
        }

    def test_volumeops_get_vm_config_spec(self):
        session = mock.Mock()
        cf = mock.Mock()
        session.vim.client.factory = cf

        vm_file_info = mock.Mock()
        config_spec = mock.Mock()
        extra_config = mock.Mock()
        vm_profile = mock.Mock()
        managed_by = mock.Mock()
        controller_device = mock.Mock()
        controller_spec = mock.Mock()
        disk_device = mock.Mock()
        disk_backing = mock.Mock()
        disk_spec = mock.Mock()
        disk_profile = mock.Mock()

        cf.create.side_effect = [vm_file_info, config_spec, extra_config,
                                 vm_profile, managed_by, controller_device,
                                 controller_spec, disk_device, disk_backing,
                                 disk_spec, disk_profile]

        data = self._create_import_data()

        vops = vmware.VolumeOps(session)
        spec = vops.get_vm_config_spec(data)

        cf.create.assert_has_calls([
            mock.call('ns0:VirtualMachineFileInfo'),
            mock.call('ns0:VirtualMachineConfigSpec'),
            mock.call('ns0:OptionValue'),
            mock.call('ns0:VirtualMachineDefinedProfileSpec'),
            mock.call('ns0:ManagedByInfo'),
            mock.call('ns0:%s' % data['controller']['type']),
            mock.call('ns0:VirtualDeviceConfigSpec'),
            mock.call('ns0:VirtualDisk'),
            mock.call('ns0:VirtualDiskFlatVer2BackingInfo'),
            mock.call('ns0:VirtualDeviceConfigSpec'),
            mock.call('ns0:VirtualMachineDefinedProfileSpec'),
        ])

        vm = data['vm']
        self.assertEqual(spec.files.vmPathName, vm['path_name'])
        self.assertEqual(spec.guestId, vm['guest_id'])
        self.assertEqual(spec.numCPUs, vm['num_cpus'])
        self.assertEqual(spec.memoryMB, vm['memory_mb'])
        self.assertEqual(spec.files, vm_file_info)
        self.assertEqual(spec.version, vm['vmx_version'])
        self.assertEqual(spec.instanceUuid, vm['uuid'])
        self.assertEqual(spec.extraConfig, [extra_config])
        self.assertEqual(spec.vmProfile, vm_profile)
        self.assertEqual(spec.vmProfile.profileId, data['profile_id'])
        self.assertEqual(spec.managedBy, managed_by)
        self.assertEqual(extra_config.key, 'foo')
        self.assertEqual(extra_config.value, 'bar')
        self.assertEqual(spec.deviceChange, [disk_spec, controller_spec])

        disk = data['disk']
        ctrl = data['controller']

        self.assertEqual(controller_spec.device, controller_device)
        self.assertEqual(controller_device.key, ctrl['key'])
        self.assertEqual(controller_device.busNumber, ctrl['bus_number'])
        self.assertEqual(controller_device.sharedBus, ctrl['shared_bus'])

        self.assertEqual(disk_device.capacityInKB, disk['capacity_in_kb'])
        self.assertEqual(disk_device.key, disk['key'])
        self.assertEqual(disk_device.unitNumber, 0)
        self.assertEqual(disk_device.controllerKey, ctrl['key'])

        self.assertEqual(disk_device.backing, disk_backing)
        self.assertEqual(disk_backing.thinProvisioned, True)
        self.assertEqual(disk_backing.fileName, '')
        self.assertEqual(disk_backing.diskMode, 'persistent')

        self.assertEqual(disk_spec.operation, 'add')
        self.assertEqual(disk_spec.fileOperation, 'create')
        self.assertEqual(disk_spec.device, disk_device)
        self.assertEqual(disk_spec.profile, [disk_profile])
        self.assertEqual(disk_profile.profileId, data['profile_id'])

    @mock.patch.object(VMDK_VOLUMEOPS, 'get_vm_config_spec')
    def test_volumeops_get_import_spec(self, get_vm_config_spec):
        session = mock.Mock()
        cf = mock.Mock()
        session.vim.client.factory = cf
        config_spec = mock.Mock()
        get_vm_config_spec.return_value = config_spec

        vops = vmware.VolumeOps(session)
        spec = vops.get_import_spec(self._create_import_data())

        cf.create.assert_called_once_with('ns0:VirtualMachineImportSpec')
        self.assertEquals(spec.configSpec, config_spec)

    def test_volumeops_delete_backing(self):
        session = mock.Mock(vim=mock.Mock())
        backing = mock.Mock()
        task = mock.Mock()
        session.invoke_api.return_value = task

        vops = vmware.VolumeOps(session)
        vops.delete_backing(backing)

        session.invoke_api.assert_called_once_with(session.vim,
                                                   'Destroy_Task', backing)
        session.wait_for_task.assert_called_once_with(task)
