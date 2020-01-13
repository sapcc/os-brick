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
    @mock.patch.object(VMDK_CONNECTOR, '_connect_volume_write_handle')
    @mock.patch.object(VMDK_CONNECTOR, '_connect_volume_read_handle')
    def test_connect_volume(
            self, connect_volume_read_handle, connect_volume_write_handle,
            create_session, load_config, write=False):

        props = self._create_connection_properties()
        if write:
            props['import_data'] = {'vm': {}}

        session = mock.Mock()
        read_handle = mock.Mock()
        write_handle = mock.Mock()

        connect_volume_write_handle.return_value = write_handle
        connect_volume_read_handle.return_value = read_handle
        create_session.return_value = session

        ret = self._connector.connect_volume(props)

        load_config.assert_called_once_with(props)
        create_session.assert_called_once_with()
        handle = None
        if write:
            connect_volume_write_handle.assert_called_once_with(session, props)
            handle = write_handle
        else:
            connect_volume_read_handle.assert_called_once_with(session, props)
            handle = read_handle

        self.assertEqual(ret, {'path': handle})

    def test_connect_volume_with_write(self):
        self.test_connect_volume(write=True)

    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch('oslo_vmware.rw_handles.VmdkReadHandle')
    def test_connect_volume_read_handle(self, vmdk_read_handle, get_moref):
        props = self._create_connection_properties()
        session = mock.Mock()
        vm_ref = mock.Mock()
        vmdk_read_handle_ret = mock.Mock()
        vmdk_read_handle.return_value = vmdk_read_handle_ret
        get_moref.return_value = vm_ref
        ret = self._connector._connect_volume_read_handle(session, props)
        get_moref.assert_called_once_with(props['volume'], 'VirtualMachine')
        vmdk_read_handle.assert_called_once_with(session,
                                                 self._connector._ip,
                                                 self._connector._port,
                                                 vm_ref,
                                                 None,
                                                 props['vmdk_size'])
        self.assertEqual(ret, vmdk_read_handle_ret)

    @mock.patch.object(VMDK_CONNECTOR, '_get_write_handle')
    def test_connect_volume_write_handle(self, get_write_handle):
        props = self._create_connection_properties()
        props['import_data'] = {'vm': {}}
        session = mock.Mock()

        self._connector._connect_volume_write_handle(session, props)
        get_write_handle.assert_called_once_with(props['import_data'],
                                                 session,
                                                 props['vmdk_size'])
        self.assertEqual(props['import_data']['vm']['name'], props['name'] +
                         '_brick')
        self.assertEqual(props['import_data']['profile_id'],
                         props['profile_id'])

    @mock.patch('os_brick.initiator.connectors.vmware.VolumeOps')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch('oslo_vmware.rw_handles.VmdkWriteHandle')
    def test_get_write_handle(self, vmdk_write_handle, get_moref, vops):
        import_data = {
            'folder': mock.Mock(),
            'resource_pool': mock.Mock()
        }
        rp = mock.Mock(value=import_data['resource_pool'])
        folder = mock.Mock(value=import_data['folder'])
        vops_ret = mock.Mock()
        vops.return_value = vops_ret
        session = mock.Mock()
        import_spec = mock.Mock()
        file_size = units.Gi
        get_moref.side_effect = [folder, rp]
        vmdk_write_handle_ret = mock.Mock()
        vmdk_write_handle.return_value = vmdk_write_handle_ret
        vops_ret.get_import_spec.return_value = import_spec

        ret = self._connector._get_write_handle(
            import_data, session, file_size)
        vops.assert_called_once_with(session)
        vops_ret.get_import_spec.assert_called_once_with(import_data)
        get_moref.assert_has_calls([
            mock.call(import_data['folder'], 'Folder'),
            mock.call(import_data['resource_pool'], 'ResourcePool')
        ])
        vmdk_write_handle.assert_called_once_with(session,
                                                  self._connector._ip,
                                                  self._connector._port,
                                                  rp,
                                                  folder,
                                                  import_spec,
                                                  file_size,
                                                  'POST')
        self.assertEqual(ret, vmdk_write_handle_ret)

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

    @mock.patch('os_brick.initiator.connectors.vmware.VolumeOps')
    @mock.patch('oslo_vmware.vim_util.get_moref')
    @mock.patch.object(VMDK_CONNECTOR, '_snapshot_exists')
    def test_disconnect_volume(self, snapshot_exists, get_moref, vops,
                               import_data=None,
                               has_snapshot=False):
        props = self._create_connection_properties()
        session = mock.Mock()
        vmdk_handle = mock.Mock(_session=session)
        vops_ret = mock.Mock(_session=session)
        vops.return_value = vops_ret

        backing = mock.Mock()
        new_backing = mock.Mock()
        if import_data:
            props['import_data'] = import_data
            get_moref.return_value = backing
            vmdk_handle.get_imported_vm.return_value = new_backing
            snapshot_exists.return_value = has_snapshot

        device_info = {'path': vmdk_handle}
        if has_snapshot:
            self.assertRaises(exception.BrickException,
                              self._connector.disconnect_volume,
                              props, device_info)
        else:
            self._connector.disconnect_volume(props, device_info)

        vmdk_handle.close.assert_called_once_with()

        if import_data:
            vops.assert_called_once_with(session)
            get_moref.assert_called_once_with(
                props['volume'], 'VirtualMachine')
            vmdk_handle.get_imported_vm.assert_called_once_with()
            snapshot_exists.assert_called_once_with(session, backing)
            if has_snapshot:
                vops_ret.delete_backing.assert_called_once_with(new_backing)
            else:
                vops_ret.delete_backing.assert_called_once_with(backing)
                vops_ret.update_instance_uuid.assert_called_once_with(
                    new_backing, props['volume_id'])

        session.logout.assert_called_once_with()

    def test_disconnect_volume_write_without_snapshot(self):
        self.test_disconnect_volume(import_data={'vm': {}})

    def test_disconnect_volume_write_having_snapshot(self):
        self.test_disconnect_volume(import_data={'vm': {}}, has_snapshot=False)

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
        self.assertEqual(spec.configSpec, config_spec)

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
