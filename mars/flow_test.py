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


class FlowTest(base_tests.SimpleDataPlane):
   """
   Testin account login
   """
   def runTest(self):
     #ports = sorted(config["port_map"].keys())
     #input_port=ports[0]
     #output_port=ports[1]

     response = requests.get(URL+"v1/devices", headers=GET_HEADER)
     assert(response.status_code == 200)
     #print response.json()
     assert(len(response.json()['devices']) > 0)
     device = response.json()['devices'][0]
     device_id=device['id']
     print device_id
     #add l2_interface_gorup
     p2_payload="""
        {
          "type": "INDIRECT",
          "appCookie": "0x10002",
          "groupId": 65538,
          "buckets": [
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "OUTPUT",
                    "port": "2"
                  }
                ]
              }
            }
          ]
        }
     """
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=p2_payload)     
     assert(response.status_code == 201)
     
     #add flow
     flow_payload="""
     {
      "flows": [
        {
          "priority": 40000,
          "timeout": 0,
          "isPermanent": true,
          "tableId": 60,
          "deviceId": "_DEVICE_ID_",
          "treatment": {
            "instructions": [
              {
                "type": "GROUP",
                "groupId": 65538
              }
            ]
          },
          "selector": {
            "criteria": [
              {
                "type": "IN_PORT",
                "port": "1"
              }
            ]
          }
        }
      ]
     }
     """
     flow_payload=flow_payload.replace("_DEVICE_ID_", device_id)
     response = requests.post(URL+"v1/flows?appId=org.onosproject.drivers",  headers=POST_HEADER, data=flow_payload)     
     assert(response.status_code == 200)     
     flowid=response.json()["flows"][0]["flowId"]
     print flowid
     
     #get flows
     response = requests.get(URL+"v1/flows/"+device_id+"/"+flowid,  headers=GET_HEADER)
     assert(response.status_code == 200)
     assert(len(response.json()["flows"]) == 1)


     #delete flow
     response = requests.delete(URL+"v1/flows/"+device_id+"/"+flowid,  headers=GET_HEADER)       
     assert(response.status_code == 204)  
     #delete group
     response = requests.delete(URL+"v1/groups/"+device_id+"/0x10002",  headers=GET_HEADER)       
     assert(response.status_code == 204)     

