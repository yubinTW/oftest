import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr

class vlan_pcp_mask(base_tests.SimpleDataPlane):
    """
    [Test match vlan pcp mask]
        test matched vlan pcp mask

    inject vlan_pcp=3 to port 3: no output
    inject vlan_pcp=6 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 vlan_vid=2,vlan_pcp=4/4,eth_type=0x0800 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",vlan_vid=2,vlan_pcp=4/4,eth_type=0x0800 write:group=0x2000"+str(output_port))

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       vlan_pcp=3,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       vlan_pcp=6,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class ip_dscp_mask(base_tests.SimpleDataPlane):
    """
    [Test match ip dscp mask]
        test matched ip dscp mask

    inject ip_dscp=84 to port 3: output from port 1
    inject ip_dscp=68 to port 3: no output
    inject ip_dscp=85 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 ip_dscp=84/84,eth_type=0x0800 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",ip_dscp=40/40,eth_type=0x0800 write:group=0x2000"+str(output_port))

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       ip_tos=136,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       ip_tos=168,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class tcp_src_mask(base_tests.SimpleDataPlane):
    """
    [Test match tcp src mask]
        test matched tcp src mask

    inject tcp_src=3 to port 3: no output
    inject tcp_src=12 to port 3: output from port 1
    inject tcp_src=13 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 tcp_src=15/12,eth_type=0x0800,ip_proto=6 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",tcp_src=15/12,eth_type=0x0800,ip_proto=6 write:group=0x2000"+str(output_port))

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_sport=3,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_sport=13,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class tcp_dst_mask(base_tests.SimpleDataPlane):
    """
    [Test match tcp dst mask]
        test matched tcp dst mask

    inject tcp_dst=6 to port 3: no output
    inject tcp_src=14 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 tcp_dst=10/10,eth_type=0x0800,ip_proto=6 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",tcp_dst=10/10,eth_type=0x0800,ip_proto=6 write:group=0x2000"+str(output_port))

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_dport=6,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_dport=14,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class udp_src_mask(base_tests.SimpleDataPlane):
    """
    [Test match udp src mask]
        test matched udp src mask

    inject udp_src=15231 to port 3: output from port 1
    inject udp_src=18132 to port 3: no output

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 udp_src=13183/13183,eth_type=0x0800,ip_proto=17 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",udp_src=13183/13183,eth_type=0x0800,ip_proto=17 write:group=0x2000"+str(output_port))

        input_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_sport=18132,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_sport=15231,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class udp_dst_mask(base_tests.SimpleDataPlane):
    """
    [Test match udp dst mask]
        test matched udp dst mask

    inject udp_dst=2421 to port 3: no output
    inject udp_dst=2941 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 udp_dst=2429/2429,eth_type=0x0800,ip_proto=17 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",udp_dst=2429/2429,eth_type=0x0800,ip_proto=17 write:group=0x2000"+str(output_port))

        input_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_dport=2421,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_dport=2941,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class sctp_src_mask(base_tests.SimpleDataPlane):
    """
    [Test match sctp src mask]
        test matched sctp src mask

    inject sctp_src=148 to port 3: output from port 1
    inject sctp_src=136 to port 3: no output

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 sctp_src=132/132,eth_type=0x0800,ip_proto=132 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",sctp_src=132/132,eth_type=0x0800,ip_proto=132 write:group=0x2000"+str(output_port))

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 88 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 94 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class sctp_dst_mask(base_tests.SimpleDataPlane):
    """
    [Test match sctp dst mask]
        test matched sctp dst mask

    inject sctp_dst=196 to port 3: no output
    inject sctp_dst=84 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 sctp_dst=68/196,eth_type=0x0800,ip_proto=132 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",sctp_dst=68/196,eth_type=0x0800,ip_proto=132 write:group=0x2000"+str(output_port))

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 88 00 c4 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 88 00 54 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class icmp_type_mask(base_tests.SimpleDataPlane):
    """
    [Test match icmp type mask]
        test matched icmp type mask

    inject src_port=29442 to port 3: output from port 1
    inject src_port=31234 to port 3: no output
    inject src_port=31490 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 icmp_type=115/115,eth_type=0x0800,ip_proto=1 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",icmp_type=115/115,eth_type=0x0800,ip_proto=1 write:group=0x2000"+str(output_port))

        input_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_type=83,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_type=119,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)


class icmp_code_mask(base_tests.SimpleDataPlane):
    """
    [Test match icmp code mask]
        test matched icmp code mask

    inject src_port=4221 to port 3: output from port 1
    inject src_port=4213 to port 3: no output
    inject src_port=4223 to port 3: output from port 1

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 icmp_code=125/125,eth_type=0x0800,ip_proto=1 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 in_port="+str(input_port)+",icmp_code=125/125,eth_type=0x0800,ip_proto=1 write:group=0x2000"+str(output_port))

        input_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_code=93,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_no_packet(self, str(input_pkt), output_port)

        input_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_code=253,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)
