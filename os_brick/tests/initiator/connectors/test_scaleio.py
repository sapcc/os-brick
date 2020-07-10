# (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
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
import json
import mock
import os
import requests
import six

from oslo_concurrency import processutils as putils

from os_brick import exception
from os_brick.initiator.connectors import scaleio
from os_brick.tests.initiator import test_connector


class ScaleIOConnectorTestCase(test_connector.ConnectorTestCase):
    """Test cases for ScaleIO connector."""

    # Fake volume information
    vol = {
        'id': 'vol1',
        'name': 'test_volume',
        'provider_id': 'vol1'
    }

    # Fake SDC GUID
    fake_guid = 'FAKE_GUID'

    def setUp(self):
        super(ScaleIOConnectorTestCase, self).setUp()

        self.fake_connection_properties = {
            'hostIP': test_connector.MY_IP,
            'serverIP': test_connector.MY_IP,
            'scaleIO_volname': self.vol['name'],
            'scaleIO_volume_id': self.vol['provider_id'],
            'serverPort': 443,
            'serverUsername': 'test',
            'config_group': 'test',
            'iopsLimit': None,
            'bandwidthLimit': None
        }

        # Formatting string for REST API calls
        self.action_format = "instances/Volume::{}/action/{{}}".format(
            self.vol['id'])
        self.get_volume_api = 'types/Volume/instances/getByName::{}'.format(
            self.vol['name'])

        # Map of REST API calls to responses
        self.mock_calls = {
            self.get_volume_api:
                self.MockHTTPSResponse(json.dumps(self.vol['id'])),
            self.action_format.format('addMappedSdc'):
                self.MockHTTPSResponse(''),
            self.action_format.format('setMappedSdcLimits'):
                self.MockHTTPSResponse(''),
            self.action_format.format('removeMappedSdc'):
                self.MockHTTPSResponse(''),
        }

        # Default error REST response
        self.error_404 = self.MockHTTPSResponse(content=dict(
            errorCode=0,
            message='HTTP 404',
        ), status_code=404)

        # Patch the request and os calls to fake versions
        self.mock_object(requests, 'get', self.handle_scaleio_request)
        self.mock_object(requests, 'post', self.handle_scaleio_request)
        self.mock_object(os.path, 'isdir', return_value=True)
        self.mock_object(os, 'listdir',
                         return_value=["emc-vol-{}".format(self.vol['id'])])

        self.get_password_mock = self.mock_object(scaleio.ScaleIOConnector,
                                                  '_get_connector_password',
                                                  return_value='fake_password')

        # The actual ScaleIO connector
        self.connector = scaleio.ScaleIOConnector(
            'sudo', execute=self.fake_execute)

    class MockHTTPSResponse(requests.Response):
        """Mock HTTP Response

        Defines the https replies from the mocked calls to do_request()
        """
        def __init__(self, content, status_code=200):
            super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                  self).__init__()

            self._content = content
            self.encoding = 'UTF-8'
            self.status_code = status_code

        def json(self, **kwargs):
            if isinstance(self._content, six.string_types):
                return super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                             self).json(**kwargs)

            return self._content

        @property
        def text(self):
            if not isinstance(self._content, six.string_types):
                return json.dumps(self._content)

            self._content = self._content.encode('utf-8')
            return super(ScaleIOConnectorTestCase.MockHTTPSResponse,
                         self).text

    def fake_execute(self, *cmd, **kwargs):
        """Fakes the rootwrap call"""
        return self.fake_guid, None

    def fake_missing_execute(self, *cmd, **kwargs):
        """Error when trying to call rootwrap drv_cfg"""
        raise putils.ProcessExecutionError("Test missing drv_cfg.")

    def handle_scaleio_request(self, url, *args, **kwargs):
        """Fake REST server"""
        api_call = url.split(':', 2)[2].split('/', 1)[1].replace('api/', '')

        if 'setMappedSdcLimits' in api_call:
            self.assertNotIn("iops_limit", kwargs['data'])
            if "iopsLimit" not in kwargs['data']:
                self.assertIn("bandwidthLimitInKbps",
                              kwargs['data'])
            elif "bandwidthLimitInKbps" not in kwargs['data']:
                self.assertIn("iopsLimit", kwargs['data'])
            else:
                self.assertIn("bandwidthLimitInKbps",
                              kwargs['data'])
                self.assertIn("iopsLimit", kwargs['data'])

        try:
            return self.mock_calls[api_call]
        except KeyError:
            return self.error_404

    def test_get_search_path(self):
        expected = "/dev/disk/by-id"
        actual = self.connector.get_search_path()
        self.assertEqual(expected, actual)

    @mock.patch.object(os.path, 'exists', return_value=True)
    @mock.patch.object(scaleio.ScaleIOConnector, '_wait_for_volume_path')
    def test_get_volume_paths(self, mock_wait_for_path, mock_exists):
        mock_wait_for_path.return_value = "emc-vol-vol1"
        expected = ['/dev/disk/by-id/emc-vol-vol1']
        actual = self.connector.get_volume_paths(
            self.fake_connection_properties)
        self.assertEqual(expected, actual)

    def test_get_connector_properties(self):
        props = scaleio.ScaleIOConnector.get_connector_properties(
            'sudo', multipath=True, enforce_multipath=True)

        expected_props = {}
        self.assertEqual(expected_props, props)

    def test_connect_volume(self):
        """Successful connect to volume"""
        self.connector.connect_volume(self.fake_connection_properties)
        self.get_password_mock.assert_called_once()

    def test_connect_with_bandwidth_limit(self):
        """Successful connect to volume with bandwidth limit"""
        self.fake_connection_properties['bandwidthLimit'] = '500'
        self.test_connect_volume()

    def test_connect_with_iops_limit(self):
        """Successful connect to volume with iops limit"""
        self.fake_connection_properties['iopsLimit'] = '80'
        self.test_connect_volume()

    def test_connect_with_iops_and_bandwidth_limits(self):
        """Successful connect with iops and bandwidth limits"""
        self.fake_connection_properties['bandwidthLimit'] = '500'
        self.fake_connection_properties['iopsLimit'] = '80'
        self.test_connect_volume()

    def test_disconnect_volume(self):
        """Successful disconnect from volume"""
        self.connector.disconnect_volume(self.fake_connection_properties, None)

    def test_error_id(self):
        """Fail to connect with bad volume name"""
        self.fake_connection_properties['scaleIO_volume_id'] = 'bad_id'
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            dict(errorCode='404', message='Test volume not found'), 404)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_no_volume_id(self):
        """Faile to connect with no volume id"""
        self.fake_connection_properties['scaleIO_volume_id'] = None
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            'null', 200)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_bad_login(self):
        """Fail to connect with bad authentication"""
        self.mock_calls[self.get_volume_api] = self.MockHTTPSResponse(
            'null', 401)

        self.mock_calls['login'] = self.MockHTTPSResponse('null', 401)
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=401, message='bad login'), 401)
        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_bad_drv_cfg(self):
        """Fail to connect with missing rootwrap executable"""
        self.connector.set_execute(self.fake_missing_execute)
        self.assertRaises(exception.BrickException, self.test_connect_volume)

    def test_error_map_volume(self):
        """Fail to connect with REST API failure"""
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_NOT_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.assertRaises(exception.BrickException, self.test_connect_volume)

    @mock.patch('time.sleep')
    def test_error_path_not_found(self, sleep_mock):
        """Timeout waiting for volume to map to local file system"""
        self.mock_object(os, 'listdir', return_value=["emc-vol-no-volume"])
        self.assertRaises(exception.BrickException, self.test_connect_volume)
        self.assertTrue(sleep_mock.called)

    def test_map_volume_already_mapped(self):
        """Ignore REST API failure for volume already mapped"""
        self.mock_calls[self.action_format.format(
            'addMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_ALREADY_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.test_connect_volume()

    def test_error_disconnect_volume(self):
        """Fail to disconnect with REST API failure"""
        self.mock_calls[self.action_format.format(
            'removeMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_ALREADY_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.assertRaises(exception.BrickException,
                          self.test_disconnect_volume)

    def test_disconnect_volume_not_mapped(self):
        """Ignore REST API failure for volume not mapped"""
        self.mock_calls[self.action_format.format(
            'removeMappedSdc')] = self.MockHTTPSResponse(
            dict(errorCode=self.connector.VOLUME_NOT_MAPPED_ERROR,
                 message='Test error map volume'), 500)

        self.test_disconnect_volume()

    def test_extend_volume(self):
        self.assertRaises(NotImplementedError,
                          self.connector.extend_volume,
                          self.fake_connection_properties)
