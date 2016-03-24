import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr

"""
env:
    host1 -- port a, port b -- host2
    because only 3 net cards could be used to test
    separate trunk test to {combi_test1, combi_test2}
    after testing combi_test1, need to change module to another port as host2
"""
class combi_test1(base_tests.SimpleDataPlane):
    """
    [Test trunk]
        traffic between host1 and host2, should output from the same trunk member port

    Inject  eth 1/1 untag, SA 001094000002, DA 000001000001, SIP 202.101.224.68, DIP 192.85.1.2
    Output  eth 1/3

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0004 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1 write:group=0xF0000001

    sudo ./oft --verbose --default-timeout=6 -i 1@eth1 -i 3@eth2 -i 4@eth4 --disable-ipv6 --switch-ip=192.168.2.1 --host=192.168.2.20 --of-version=1.3 --port=6633 --test-dir=acctonUseDpctl --log-dir=log-dir trunk_group.combi_test1
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        host_port1 = test_ports[0]
        trunk_member1 = test_ports[1]
        trunk_member2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output="+str(trunk_member1)+" group=any,port=any,weight=0 output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member1)+" group=any,port=any,weight=0 pop_vlan,output="+str(trunk_member1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member2)+" group=any,port=any,weight=0 pop_vlan,output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(host_port1)+",vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(host_port1)+" write:group=0xF0000001")

        host1_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2')
        output_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2')

        self.dataplane.send(host_port1, str(host1_pkt))
        verify_packet(self, str(output_pkt), trunk_member2)


class combi_test2(base_tests.SimpleDataPlane):
    """
    [Test trunk]
        traffic between host1 and host2, should output from the same trunk member port

    Inject  eth 1/2 untag, SA000001000001, DA  001094000002, SIP 192.85.1.2, DIP 202.101.224.68
    Output  eth 1/3

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0004 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1 write:group=0xF0000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=2 write:group=0xF0000001

    sudo ./oft --verbose --default-timeout=6 -i 2@eth1 -i 3@eth2 -i 4@eth4 --disable-ipv6 --switch-ip=192.168.2.1 --host=192.168.2.20 --of-version=1.3 --port=6633 --test-dir=acctonUseDpctl --log-dir=log-dir trunk_group.combi_test2
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        host_port2 = test_ports[0]
        trunk_member1 = test_ports[1]
        trunk_member2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output="+str(trunk_member1)+" group=any,port=any,weight=0 output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member1)+" group=any,port=any,weight=0 pop_vlan,output="+str(trunk_member1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member2)+" group=any,port=any,weight=0 pop_vlan,output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(host_port2)+",vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(host_port2)+" write:group=0xF0000001")

        host2_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10')
        output_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10')

        self.dataplane.send(host_port2, str(host2_pkt))
        verify_packet(self, str(output_pkt), trunk_member2)


class output2member(base_tests.SimpleDataPlane):
    """
    [Test output to trunk member]
        check output to specified trunk member

    Inject  eth 1/1 untag, SA000001000001, DA  001094000002, SIP 192.85.1.2, DIP 202.101.224.68
    Output  eth 1/3

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0004 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1 write:group=0xa0003

    sudo ./oft --verbose --default-timeout=6 -i 1@eth1 -i 3@eth2 -i 4@eth4 --disable-ipv6 --switch-ip=192.168.2.1 --host=192.168.2.20 --of-version=1.3 --port=6633 --test-dir=acctonUseDpctl --log-dir=log-dir trunk_group.output2member
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        trunk_member1 = test_ports[1]
        trunk_member2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output="+str(trunk_member1)+" group=any,port=any,weight=0 output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member1)+" group=any,port=any,weight=0 pop_vlan,output="+str(trunk_member1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member2)+" group=any,port=any,weight=0 pop_vlan,output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+" write:group=0xa000"+str(trunk_member1))

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10')
        output_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), trunk_member1)


class two_trunk(base_tests.SimpleDataPlane):
    """
    [Test two trunk]
        test duplicated trunk member

    Inject  eth 1/1 tag 10, SA000001000001, DA  001094000002, SIP 192.85.1.2, DIP 202.101.224.68
    Output  eth 1/3

    Inject  eth 1/1 tag 11, SA000001000001, DA  001094000002, SIP 192.85.1.2, DIP 202.101.224.68
    Output  eth 1/4

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000002 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xb0003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xb0004 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x100a goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x100b goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1,vlan_vid=10 write:group=0xF0000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1,vlan_vid=11 write:group=0xF0000002

    sudo ./oft --verbose --default-timeout=6 -i 1@eth1 -i 3@eth2 -i 4@eth4 --disable-ipv6 --switch-ip=192.168.2.1 --host=192.168.2.20 --of-version=1.3 --port=6633 --test-dir=acctonUseDpctl --log-dir=log-dir trunk_group.two_trunk
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        trunk_member1 = test_ports[1]
        trunk_member2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output="+str(trunk_member1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=sel,group=0xF0000002 group=any,port=any,weight=0 output="+str(trunk_member1)+" group=any,port=any,weight=0 output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xa000"+str(trunk_member1)+" group=any,port=any,weight=0 output="+str(trunk_member1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xb000"+str(trunk_member1)+" group=any,port=any,weight=0 output="+str(trunk_member1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xb000"+str(trunk_member2)+" group=any,port=any,weight=0 output="+str(trunk_member2))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x100a goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x100b goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",vlan_vid=10 write:group=0xF0000001")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",vlan_vid=11 write:group=0xF0000002")

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10',
                                       vlan_vid=10,
                                       dl_vlan_enable=True)
        output_pkt = input_pkt

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), trunk_member1)

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10',
                                       vlan_vid=11,
                                       dl_vlan_enable=True)
        output_pkt = input_pkt

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), trunk_member2)



