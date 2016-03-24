import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr


class conformance_test(base_tests.SimpleDataPlane):
    """
    [CONFORMANCE TEST]
      Do CONFORMANCE TEST

    Inject  eth 1/1 Tag2
    Output  eth 1/2 Tag2

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20002 group=any,port=any,weight=0 output=2
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=301 eth_type=0x0800,in_port=1,vlan_vid=2 apply:output=2
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=301 eth_type=0x0800,in_port="+str(input_port)+",vlan_vid=2 apply:output="+str(output_port))

        input_pkt = simple_packet(
                '00 00 00 22 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 00 00 4e 04 d2 00 00 7f 06 b2 7b c0 a8 '
                '01 0a c0 a8 02 02 00 03 00 06 00 01 f7 fa 00 00 '
                '00 00 50 00 04 00 2f 5d 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = input_pkt

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
