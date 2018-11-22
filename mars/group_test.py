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
from time import sleep

URL="http://" + config['controller_host'] + ":8181/mars/"
LOGIN=base64.b64encode(bytes('karaf:karaf'))
AUTH_TOKEN='BASIC ' + LOGIN
GET_HEADER={'Authorization': AUTH_TOKEN, 'Accept': 'application/json'}
POST_HEADER={'Authorization': AUTH_TOKEN, 'Content-Type': 'application/json', 'Accept':'application/json'}


class GroupTest_l2Interface(base_tests.SimpleDataPlane):
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
     #print device_id
     #add l2_interface_gorup
     group1_id=0x10001
     p1_payload="""
        {
          "type": "INDIRECT",
          "appCookie":"_GROUPIDCOOKIE_",
          "groupId":"_GROUPID_",
          "buckets": [
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "OUTPUT",
                    "port": "1"
                  }
                ]
              }
            }
          ]
        }
     """
     p1_payload=p1_payload.replace("_GROUPID_", str(group1_id))
     p1_payload=p1_payload.replace("_GROUPIDCOOKIE_", hex(group1_id))   

     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=p1_payload)
     assert(response.status_code == 201)
     response = requests.get(URL+"v1/groups/"+device_id+"/"+hex(group1_id),  headers=GET_HEADER)
     assert(response.status_code == 200)
     assert(len(response.json()["groups"]) == 1)
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(group1_id),  headers=GET_HEADER)
     assert(response.status_code == 204)
     response = requests.get(URL+"v1/groups/"+device_id+"/"+hex(group1_id),  headers=GET_HEADER)
     assert(response.json()["groups"][0]["state"]=="PENDING_DELETE")
          

class GroupTest_Flood(base_tests.SimpleDataPlane):
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
     #print device_id
     #add l2_interface_gorup
     group1_id=0x10001
     p1_payload="""
        {
          "type": "INDIRECT",
          "appCookie":"_GROUPIDCOOKIE_",
          "groupId":"_GROUPID_",
          "buckets": [
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "OUTPUT",
                    "port": "1"
                  }
                ]
              }
            }
          ]
        }
     """
     p1_payload=p1_payload.replace("_GROUPID_", str(group1_id))
     p1_payload=p1_payload.replace("_GROUPIDCOOKIE_", hex(group1_id))     
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=p1_payload)     
     assert(response.status_code == 201)

     
     #add l2_interface_gorup
     group2_id=0x10002
     p2_payload="""
        {
          "type": "INDIRECT",
          "appCookie": "_GROUPIDCOOKIE_",
          "groupId": "_GROUPID_",
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
     p2_payload=p2_payload.replace("_GROUPID_", str(group2_id))
     p2_payload=p2_payload.replace("_GROUPIDCOOKIE_", hex(group2_id))        
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=p2_payload)     
     assert(response.status_code == 201)

     #flood group
     flood_group=0x40010000
     flood_payload="""
        {
          "type": "ALL",
          "appCookie": "_GROUPIDCOOKIE_",
          "groupId": "_GROUPID_",
          "buckets": [
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "GROUP",
                    "groupId": "0x10001"
                  }
                ]
              },
              {
              "treatment": {
                "instructions": [
                  {
                    "type": "GROUP",
                    "groupId": "0x10002"
                  }                  
                ]
              }
            }
          ]
        }
     """
     flood_payload=flood_payload.replace("_GROUPID_", str(flood_group))
     flood_payload=flood_payload.replace("_GROUPIDCOOKIE_", hex(flood_group))        
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=flood_payload)     
     assert(response.status_code == 201)
     
     response = requests.get(URL+"v1/groups/"+device_id+"/"+hex(flood_group),  headers=GET_HEADER)
     assert(response.status_code == 200)
     assert(len(response.json()["groups"]) == 1)     
     
     #delete all groups
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(group1_id),  headers=GET_HEADER)
     assert(response.status_code == 204)     
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(group2_id),  headers=GET_HEADER)
     assert(response.status_code == 204)     
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(flood_group),  headers=GET_HEADER)
     assert(response.status_code == 204)
     response = requests.get(URL+"v1/groups/"+device_id+"/"+hex(flood_group),  headers=GET_HEADER)
     assert(response.json()["groups"][0]["state"]=="PENDING_DELETE")


class GroupTest_multicast(base_tests.SimpleDataPlane):
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
     #print device_id
     #add l2_interface_gorup
     group1_id=0x10001
     p1_payload="""
        {
          "type": "INDIRECT",
          "appCookie":"_GROUPIDCOOKIE_",
          "groupId":"_GROUPID_",
          "buckets": [
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "OUTPUT",
                    "port": "1"
                  }
                ]
              }
            }
          ]
        }
     """
     p1_payload=p1_payload.replace("_GROUPID_", str(group1_id))
     p1_payload=p1_payload.replace("_GROUPIDCOOKIE_", hex(group1_id))       
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=p1_payload)     
     assert(response.status_code == 201)

     
     #add l2_interface_gorup
     group2_id=0x10002
     p2_payload="""
        {
          "type": "INDIRECT",
          "appCookie": "_GROUPIDCOOKIE_",
          "groupId": "_GROUPID_",
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
     p2_payload=p2_payload.replace("_GROUPID_", str(group2_id))
     p2_payload=p2_payload.replace("_GROUPIDCOOKIE_", hex(group2_id))     
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=p2_payload)     
     assert(response.status_code == 201)

     #mcast group
     flood_group=0x30010000
     flood_payload="""
        {
          "type": "ALL",
          "appCookie": "_GROUPIDCOOKIE_",
          "groupId": "_GROUPID_",
          "buckets": [
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "GROUP",
                    "groupId": "0x10001"
                  }                 
                ]
              },
            {
              "treatment": {
                "instructions": [
                  {
                    "type": "GROUP",
                    "groupId": "0x10002"
                  }                  
                ]
              }              
            }
          ]
        }
     """
     flood_payload=flood_payload.replace("_GROUPID_", str(flood_group))
     flood_payload=flood_payload.replace("_GROUPIDCOOKIE_", hex(flood_group))     
     response = requests.post(URL+"v1/groups/"+device_id,  headers=POST_HEADER, data=flood_payload)     
     assert(response.status_code == 201)
     
     response = requests.get(URL+"v1/groups/"+device_id+"/"+hex(flood_group),  headers=GET_HEADER)
     assert(response.status_code == 200)
     assert(len(response.json()["groups"]) == 1)    
     
     #delete all groups
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(group1_id),  headers=GET_HEADER)
     assert(response.status_code == 204)     
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(group2_id),  headers=GET_HEADER)
     assert(response.status_code == 204)     
     response = requests.delete(URL+"v1/groups/"+device_id+"/"+hex(flood_group),  headers=GET_HEADER)
     assert(response.status_code == 204)  
     response = requests.get(URL+"v1/groups/"+device_id+"/"+hex(flood_group),  headers=GET_HEADER)
     assert(response.json()["groups"][0]["state"]=="PENDING_DELETE")     
