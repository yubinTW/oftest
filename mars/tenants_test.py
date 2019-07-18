"""
ref: http://docs.python-requests.org/zh_CN/latest/user/quickstart.html

Test Tenants RestAPI.
"""


import oftest.base_tests as base_tests
import config as test_config
import requests
import time

URL = test_config.API_BASE_URL
LOGIN = test_config.LOGIN
AUTH_TOKEN = 'BASIC ' + LOGIN
GET_HEADER = {'Authorization': AUTH_TOKEN}
POST_HEADER = {'Authorization': AUTH_TOKEN, 'Content-Type': 'application/json'}


class TenantsGetTest(base_tests.SimpleDataPlane):
    """
    Test tenant GET method
        - /v1/tenants
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def runTest(self):
        response = requests.get(URL+"v1/tenants/v1", headers=GET_HEADER)
        assert(response.status_code == 200)


class TenantsAddNewTest(base_tests.SimpleDataPlane):
    """
    Test adding a new tenant and delete it
      - POST v1/tenants
      - DELETE v1/tenants/{tenant_id}
      - GET v1/tenants
    """

    def runTest(self):
        tenant_id = 'testTenant' + str(int(time.time()))
        # add a tenant
        payload = '{"id": "' + tenant_id + '"}'
        response = requests.post(
            URL+"v1/tenants/v1", headers=POST_HEADER, data=payload)
        assert(response.status_code == 201)

        # query tenants
        response = requests.get(URL + 'v1/tenants/v1', headers=GET_HEADER)
        assert(response.status_code == 200)
        found = False
        for t in response.json()['tenants']:
            if t['id'] == tenant_id:
                found = True
                break
        assert(found)

        # delete test tenant
        response = requests.delete(URL + 'v1/tenants/v1/{}'.format(tenant_id), headers=GET_HEADER)
        assert(response.status_code == 204)

        # query and check
        response = requests.get(URL + 'v1/tenants/v1', headers=GET_HEADER)
        assert(response.status_code == 200)
        not_exist = True
        if len(response.json()) > 0:
            for t in response.json()['tenants']:
                if t['id'] == tenant_id:
                    not_exist = False
                    break
        assert(not_exist)
