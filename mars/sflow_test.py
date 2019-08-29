"""
ref: http://docs.python-requests.org/zh_CN/latest/user/quickstart.html

Test sFlow RestAPI.
"""


import oftest.base_tests as base_tests
import config as test_config
import requests

URL = test_config.API_BASE_URL
LOGIN = test_config.LOGIN
AUTH_TOKEN = 'BASIC ' + LOGIN
GET_HEADER = {'Authorization': AUTH_TOKEN}
POST_HEADER = {'Authorization': AUTH_TOKEN, 'Content-Type': 'application/json'}


class SFlowTest(base_tests.SimpleDataPlane):
    """
    Test sFlow RestAPI
        - GET /sflow/v1
        - POST /sflow/v1/<device_id>
        - GET /sflow/v1/<device_id>
        - DELETE /sflow/v1/<device_id>
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def runTest(self):
        
        # Get all sFlow settings
        response = requests.get(URL+'sflow/v1', headers=GET_HEADER)
        assert response.status_code == 200, 'Query sFlow settings FAIL!' + response.text
        assert 'sflows' in response.json(), 'Query sFlow settings FAIL!' + response.text

        # Query device_id
        response = requests.get(URL+"v1/devices", headers=GET_HEADER)
        assert response.status_code == 200, 'Query devices is FAIL!'
        assert len(response.json()['devices']) > 0, 'Test sFlow RestAPI need at least one device'
        device_id = response.json()['devices'][0]['id']

        # Post sFlow
        payload = {
            "collector_ip": "192.168.40.141",
            "max_payload_length": 1500,
            "max_header_length": 256,
            "polling_interval": 10000000,
            "sample_rate": 16777215,
            "port": [
                1,
                3,
                5,
                7,
                9
            ],
            "duration": 10000000
        }
        response = requests.post(URL+'sflow/v1/'+device_id, json=payload, headers=POST_HEADER)
        assert response.status_code == 200, 'Add sFlow on device_id = '+device_id+' is FAIL! ' + response.text

        # Query sFlow setting on a device
        response = requests.get(URL+'sflow/v1/'+device_id, headers=GET_HEADER)
        assert response.status_code == 200, 'Query sFlow setting on device_id = '+device_id+' is FAIL! '+response.text
        assert response.json() != {}, 'Query sFlow setting on device_id = '+device_id+' is FAIL! '+response.text

        # Delete sFlow setting for a device
        response = requests.delete(URL+'sflow/v1/'+device_id, headers=GET_HEADER)
        assert response.status_code == 200, 'Delete sFlow setting on device_id = '+device_id+' is FAIL!'

        # Check if delete successfully
        # Get all sFlow settings
        response = requests.get(URL+'sflow/v1', headers=GET_HEADER)
        assert response.status_code == 200, 'Query sFlow settings FAIL!' + response.text
        assert 'sflows' in response.json(), 'Query sFlow settings FAIL!' + response.text
        removed = True
        for item in response.json()['sflows']:
            if item['device_id'] == device_id:
                removed = False
                break
        assert removed, 'Delete sFlow on device_id = '+device_id+' is FAIL!'
