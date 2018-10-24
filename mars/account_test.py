"""
Get Test

Test each flow table can set entry, and packet rx correctly.
"""

import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
import requests

class AccountTest(base_tests.SimpleDataPlane):
   """
   Testin account login
   """
   def runTest(self):
     
     ports = sorted(config["port_map"].keys())
     input_port=ports[0]
     output_port=ports[1]
     url="http://"+config["controller_host"]+":8181/mars/useraccount/v1"
     response = requests.get(url)
     assert(response.status_code == 200)
     