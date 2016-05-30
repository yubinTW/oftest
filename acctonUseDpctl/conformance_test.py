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
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=301 eth_type=0x0800,in_port="+str(input_port)+",vlan_vid=2 apply:output="+str(output_port))

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        output_pkt = input_pkt

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
