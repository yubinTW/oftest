"""
ref: http://docs.python-requests.org/zh_CN/latest/user/quickstart.html
Get Test

Test each flow table can set entry, and packet rx correctly.
"""

import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
import requests
import base64

URL="http://" + config['controller_host'] + ":8181/mars/"
LOGIN=base64.b64encode(bytes('karaf:karaf'))
AUTH_TOKEN='BASIC ' + LOGIN
GET_HEADER={'Authorization': AUTH_TOKEN}
POST_HEADER={'Authorization': AUTH_TOKEN, 'Content-Type': 'application/json'}


class AccountGetTest(base_tests.SimpleDataPlane):
   """
   Testin account login
   """
   def runTest(self):
     #ports = sorted(config["port_map"].keys())
     #input_port=ports[0]
     #output_port=ports[1]

     response = requests.get(URL+"useraccount/v1", headers=GET_HEADER)
     assert(response.status_code == 200)
     #print response.json()
     
     response = requests.get(URL+"useraccount/v1/group/admingroup", headers=GET_HEADER)
     assert(response.status_code == 200)
     #print response.json()['users']
     
     payload='{"user_name": "testUser",  "groups": ["admingroup" ], "password": "testPassword"}'
     response = requests.post(URL+"useraccount/v1", headers=POST_HEADER, data=payload)
     assert(response.status_code == 200)
     response = requests.get(URL+"useraccount/v1/group/admingroup", headers=GET_HEADER)
     #print response.json()['users']
     assert("testUser" in response.json()['users'])

     response = requests.delete(URL+"useraccount/v1/testUser", headers=GET_HEADER)
     assert(response.status_code == 200)

     response = requests.get(URL+"useraccount/v1/group/admingroup", headers=GET_HEADER)
     assert("testUser" not in response.json()['users'])
