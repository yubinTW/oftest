import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr


class encap_1mpls_vpls(base_tests.SimpleDataPlane):
    """
    [Encap 1 MPLS label: customer to provider]
    original output tag:2 => change to tag 5

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20002 group=any,port=any,weight=0 output=2
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x20002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000002

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x9C000001 group=any,port=any,weight=0 set_field=ofdpa_mpls_l2_port:0x30001,set_field=tunn_id:0x20001,group=0x91000001

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:0x10001,set_field=tunn_id:0x20001 goto:50

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 tunn_id=0x20001,eth_dst=00:00:00:11:33:55 write:group=0x9C000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=2,vlan_vid=2 write:set_field=vlan_vid=5
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000002")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x9C000001 group=any,port=any,weight=0 set_field=ofdpa_mpls_l2_port:0x30001,set_field=tunn_id:0x20001,group=0x91000001")

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:0x10001,set_field=tunn_id:0x20001 goto:50")
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 tunn_id=0x20001,eth_dst=00:00:00:11:33:55 write:group=0x9C000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port)+",vlan_vid=2 write:set_field=vlan_vid=5")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 05 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 03 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b2 47 c0 a8 01 64 c0 a8 02 02 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

class decap_1mpls_vpls(base_tests.SimpleDataPlane):
    """
    [Decap 1 MPLS label: provider to customer]
    original output tag:3 => change to tag 5

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20002 group=any,port=any,weight=0 output=2
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x20002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000002

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x9C000001 group=any,port=any,weight=0 set_field=ofdpa_mpls_l2_port:0x30001,set_field=tunn_id:0x20001,group=0x91000001

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:0x10001,set_field=tunn_id:0x20001 goto:50

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 tunn_id=0x20001,eth_dst=00:00:00:11:33:55 write:group=0x9C000001 goto:60

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 in_port=2,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:51,eth_type=0x8847 goto:23

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x9D000001 group=any,port=any,weight=0 set_field=ofdpa_mpls_l2_port:0x10001,set_field=tunn_id:0x20001,group=0x30001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 tunn_id=0x20001,eth_dst=00:00:00:11:22:33 write:group=0x9D000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=1,vlan_vid=3 write:set_field=vlan_vid=5
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x90000002")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x9C000001 group=any,port=any,weight=0 set_field=ofdpa_mpls_l2_port:0x30001,set_field=tunn_id:0x20001,group=0x91000001")

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:0x10001,set_field=tunn_id:0x20001 goto:50")
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 tunn_id=0x20001,eth_dst=00:00:00:11:33:55 write:group=0x9C000001 goto:60")

        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(output_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:51,eth_type=0x8847 goto:23")

        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x9D000001 group=any,port=any,weight=0 set_field=ofdpa_mpls_l2_port:0x10001,set_field=tunn_id:0x20001,group=0x3000"+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 tunn_id=0x20001,eth_dst=00:00:00:11:22:33 write:group=0x9D000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(input_port)+",vlan_vid=3 write:set_field=vlan_vid=5")

        input_pkt = simple_packet(
                '00 00 04 22 33 51 00 00 04 22 44 61 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 22 33 '
                '00 00 00 11 33 55 81 00 00 03 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b2 47 c0 a8 01 64 c0 a8 02 02 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 22 33 00 00 00 11 33 55 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(output_port, str(input_pkt))
        verify_packet(self, str(output_pkt), input_port)


class encap_2mpls_l3(base_tests.SimpleDataPlane):
    """
    [Encap two MPLS labels with L3]
      Encap two MPLS labels with L3 routing
      original output tag:2 => change to tag 5

    Inject  eth 1/3 Tag 2, SA000000112233, DA000000113355, SIP 192.168.1.10, DIP 192.168.2.2
    Output  eth 1/1 SA000004223355, DA000004224466, Tag2, Outer Label 0x903, EXP 7, TTL 250, Inner Label 0x901, EXP 7, TTL 250; IP the same as original

    ./dpctl tcp:192.168.1.1:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=1,vlan_vid=2 write:set_field=vlan_vid=5,set_field=vlan_pcp:3
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.3.2/255.255.255.0 write:group=0x92000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port)+",vlan_vid=2 write:set_field=vlan_vid=5,set_field=vlan_pcp:3")

        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 60 05 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_2mpls_l3(base_tests.SimpleDataPlane):
    """
    [Decap two MPLS labels with L3]
      Decap two MPLS labels with L3 routing
      original output tag:2 => change to tag 5

    Inject  eth 1/1 SA000004223355, DA000004224466, Tag2, Outer Label 0x903, EXP 7, TTL 250, Inner Label 0x901, SIP 192.168.3.2, DIP 192.168.2.10
    Output  eth 1/3 SA000006223355, DA000006224466, Tag2, SIP 192.168.3.2, DIP 192.168.2.10

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_vrf:1 goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000003 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=3,vlan_vid=2 write:set_field=vlan_vid=5
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_vrf:1 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:23")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.3.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000003 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port)+",vlan_vid=2 write:set_field=vlan_vid=5,set_field=vlan_pcp:2")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        output_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 40 05 '
                '08 00 45 00 00 4e 00 01 00 00 f9 06 38 4c c0 a8 '
                '05 0a c0 a8 03 02 04 d2 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 f0 2c 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class swap_ff_out_mpls(base_tests.SimpleDataPlane):
    """
    [Swap outermost MPLS label]
      Swap outermost MPLS label (LSR)

    Inject  eth 1/2 Tag 2, Outer label 0x901, TTL 250, InLabel 0xF, DA000004223355, SA000004224466

    -- working up --
    Output  eth 1/4 Tag 2, Outer label 0x9051, TTL 249, InLabel 0xF, SA000004223354, DA000004224464
    original output tag:2 => change to tag 10
    -- working down --
    Output  eth 1/1 Tag 2, Outer label 0x9051, TTL 249, InLabel 0xF, SA000004223351, DA000004224461
    original output tag:2 => change to tag 20

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x20001

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20004 group=any,port=any,weight=0 output=4
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000004 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:54,set_field=eth_dst=00:00:04:22:44:64,set_field=vlan_vid=2,group=0x20004

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ff,group=0xA6000001 group=any,port=4,weight=0 group=0x90000004 group=any,port=1,weight=0 group=0x90000001

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9051,group=0xA6000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901 apply:mpls_dec write:group=0x95000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 in_port=2,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=1,vlan_vid=2 write:set_field=vlan_vid=20,set_field=vlan_pcp:3
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=4,vlan_vid=2 write:set_field=vlan_vid=10,set_field=vlan_pcp:2
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port1 = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port1)+" group=any,port=any,weight=0 output="+str(output_port1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:51,set_field=eth_dst=00:00:04:22:44:61,set_field=vlan_vid=2,group=0x2000"+str(output_port1))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000004 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:54,set_field=eth_dst=00:00:04:22:44:64,set_field=vlan_vid=2,group=0x2000"+str(output_port2))

        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ff,group=0xA6000001 group=any,port="+str(output_port1)+",weight=0 group=0x90000001 group=any,port="+str(output_port2)+",weight=0 group=0x90000004")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x95000001 group=any,port=any,weight=0 set_field=mpls_label:0x9051,group=0xA6000001")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901 apply:mpls_dec write:group=0x95000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port1)+",vlan_vid=2 write:set_field=vlan_vid=10,set_field=vlan_pcp:2")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port2)+",vlan_vid=2 write:set_field=vlan_vid=20,set_field=vlan_pcp:3")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1e fa 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt1 = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 40 0a '
                '88 47 09 05 10 f9 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt1), output_port1)

        #if output_port link down
        apply_dpctl_mod(self, config, "port-mod port="+str(output_port1)+",conf=0x1,mask=0x1")
        time.sleep(5)
        self.dataplane.send(input_port, str(input_pkt))

        #recover output_port link status, before assert check
        apply_dpctl_mod(self, config, "port-mod port="+str(output_port1)+",conf=0x0,mask=0x1")
        time.sleep(1)
        #make sure port link up
        port_up = 0
        while port_up == 0:
            time.sleep(1)
            #apply_dpctl_mod(self, config, "port-mod port="+str(output_port)+",conf=0x0,mask=0x1")
            json_result = apply_dpctl_get_cmd(self, config, "port-desc")
            result=json_result["RECEIVED"][1]
            for p_desc in result["port"]:
                if p_desc["no"] == output_port1:
                    if p_desc["config"] != 0x01 : #up
                        port_up = 1
        #check if output_port2 receives packet
        output_pkt2 = simple_packet(
                '00 00 04 22 44 64 00 00 04 22 33 54 81 00 60 14 '
                '88 47 09 05 10 f9 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(output_pkt2), output_port2)

class encap_2mpls_vpws(base_tests.SimpleDataPlane):
    """
    [Encap two MPLS labels]
      Encap two MPLS labels

    Inject  eth 1/3 Tag 3, SA000000112233, DA000000113355
    Output  eth 1/1 Tag 2, Outer label 0x903, TTL 250, InLabel 0x901, TTL 250, SA000004223355, DA000004224466
    original output tag:2 => change to tag 10

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=1,vlan_vid=2 write:set_field=vlan_vid=10,set_field=vlan_pcp:2
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(output_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port)+",vlan_vid=2 write:set_field=vlan_vid=20,set_field=vlan_pcp:3")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 60 14 '
                '88 47 00 90 3e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

class decap_2mpls_vpws(base_tests.SimpleDataPlane):
    """
    [Pop, decap, and L2 forward]
      Pop outermost tunnel label and pop outer L2 header (L2 Switch VPWS )

    Inject  eth 1/1 Tag 2, Outer label 0x903, InLabel 0x901, SA000004223355, DA000004224466; InTag 5, InSA000000112233, InDA000000113355
    Output  eth 1/3 Tag 5, SA000000112233, DA000000113355
    original output tag:5 => change to tag 10

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=3,eth_dst=00:00:00:11:33:55 write:set_field=vlan_vid=10,set_field=vlan_pcp:2
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(input_port)+" goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port)+",eth_dst=00:00:00:11:33:55 write:set_field=vlan_vid=10,set_field=vlan_pcp:2")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 40 0a '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 56 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        #not specified DA: not change output tag
        output_pkt = simple_packet(
                '00 00 00 11 33 56 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class decap_2mpls_vpws_test2(base_tests.SimpleDataPlane):
    """
    [Pop, decap, and L2 forward]
      Pop outermost tunnel label and pop outer L2 header (L2 Switch VPWS )

    Inject  eth 1/1 Tag 2, Outer label 0x903, InLabel 0x901, SA000004223355, DA000004224466; InTag 5, InSA000000112233, InDA000000113355
    Output  eth 1/3 Tag 5, SA000000112233, DA000000113355
    original output tag:5 => change to tag 10

    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:192.168.1.1:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output=3,eth_dst=00:00:00:11:33:55/ff:ff:ff:ff:ff:00 write:set_field=vlan_vid=10,set_field=vlan_pcp:2
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(input_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001")
        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(input_port)+" goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=253,cmd=add,prio=501 ofdpa_actset_output="+str(output_port)+",eth_dst=00:00:00:11:33:55/ff:ff:ff:ff:ff:00 write:set_field=vlan_vid=10,set_field=vlan_pcp:2")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 40 0a '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 56 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 00 11 33 56 00 00 00 11 22 33 81 00 40 0a '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
