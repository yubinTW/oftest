import logging
import oftest.base_tests as base_tests
import time
from oftest import config
from oftest.testutils import *
#from util import *
from util import *

class p2p_encap(base_tests.SimpleDataPlane):
    """
    [test 1]
    Inject {Tag 2, DA000000113355, DIP 192.168.3.2} to port 1
    => output {Tag 2, DA000004224466, SA000004223355, MPLS label 0x903, 0x901} from port 2
    [test 2] shutdown port 2
    Inject {Tag 2, DA000000113355, DIP 192.168.3.2} to port 1
    => output {Tag 2, DA000004224467, SA000004223357, MPLS label 0x907, 0x901} from port 3

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20002 group=any,port=any,weight=0 output=2
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20002 goto:60
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x90000001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ff,group=0xA6000001 group=any,port=2,weight=0 group=0x93000001 group=any,port=3,weight=0 group=0x93000002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0xA6000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(output_port)+" goto:60")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 push_mpls=0x8847,set_field=mpls_label:0x903,group=0x90000001")

        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:57,set_field=eth_dst=00:00:04:22:44:67,set_field=vlan_vid=2,group=0x2000"+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000002 group=any,port=any,weight=0 set_field=mpls_label:0x907,push_mpls=0x8847,group=0x90000002")

        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ff,group=0xA6000001 group=any,port="+str(output_port)+",weight=0 group=0x93000001 group=any,port="+str(output_port2)+",weight=0 group=0x93000002")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0xA6000001")

        apply_dpctl_mod(self, config, "flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        """
        #shutdown output_port
        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        output_pkt = simple_packet(
                '00 00 04 22 44 67 00 00 04 22 33 57 81 00 00 02 '
                '88 47 00 90 7e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port2)
        """

class p2p_decap(base_tests.SimpleDataPlane):
    """
    [test]
    Inject {Tag 2, DA000004224466, SA000004223355, MPLS label 0x903, 0x901} to port 1
    => output {Tag 2, DA000000113355} from port 2

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x91000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ofdpa_push_l2hdr,push_vlan=0x8100,push_mpls=0x8847,ofdpa_push_cw,group=0x93000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=13,cmd=add,prio=113 tunn_id=0x10001,ofdpa_mpls_l2_port=100 write:group=0x91000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1003/0x1fff apply:set_field=ofdpa_mpls_l2_port:100,set_field=tunn_id:0x10001 goto:13
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:23
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x20001 goto:60
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
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x00008847 goto:23")
        apply_dpctl_mod(self, config, "flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24")
        apply_dpctl_mod(self, config, "flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1 apply:pop_mpls=0x8847,mpls_dec,ofdpa_pop_l2hdr,ofdpa_pop_cw,set_field=ofdpa_mpls_l2_port:0x20100,set_field=tunn_id:0x10001 write:group=0x2000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)




class mp2mp_encap(base_tests.SimpleDataPlane):
    """
    add MPLS 2 labels:
    Table 0 -> table 10 -> table 20 -> table 30 -> MPLS L3 VPN group -> MPLS FF group -> MPLS tunnel label 1 group -> MPLS intf group -> L2 intf group
    NOT add MPLS 2 labels:
    Table 0 -> table 10 -> table 60 -> L2 intf group

    [test 1]
    Inject {Tag 2, DA000000113355, DIP 192.168.3.2} to port 1
    => output {Tag 2, DA000004224466, SA000004223355, MPLS label 0x903, 0x901} from port 2
    [test 2] shutdown port 2
    Inject {Tag 2, DA000000113355, DIP 192.168.3.2} to port 1
    => output {Tag 2, DA000004224467, SA000004223357, MPLS label 0x907, 0x901} from port 3
    [test 3]
    Inject {Tag 2, DA000000113356, DIP 192.168.3.2} to port 1
    => output {Tag 2, DA000000113356, DIP 192.168.3.2} from port 2

    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20002 group=any,port=any,weight=0 output=2
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x20002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20003 group=any,port=any,weight=0 output=3
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:57,set_field=eth_dst=00:00:04:22:44:67,set_field=vlan_vid=2,group=0x20003
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x93000002 group=any,port=any,weight=0 set_field=mpls_label:0x907,push_mpls=0x8847,group=0x90000002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ff,group=0xA6000001 group=any,port=2,weight=0 group=0x93000001 group=any,port=3,weight=0 group=0x93000002
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0xA6000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0 write:group=0x92000001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:56 write:group=0x20001
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]
        output_port2 = test_ports[2]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0/0xffff0000 goto:10")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=2/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000001 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:55,set_field=eth_dst=00:00:04:22:44:66,set_field=vlan_vid=2,group=0x2000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000001 group=any,port=any,weight=0 set_field=mpls_label:0x903,push_mpls=0x8847,group=0x90000001")

        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port2)+" group=any,port=any,weight=0 output="+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x90000002 group=any,port=any,weight=0 set_field=eth_src=00:00:04:22:33:57,set_field=eth_dst=00:00:04:22:44:67,set_field=vlan_vid=2,group=0x2000"+str(output_port2))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x93000002 group=any,port=any,weight=0 set_field=mpls_label:0x907,push_mpls=0x8847,group=0x90000002")

        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ff,group=0xA6000001 group=any,port="+str(output_port)+",weight=0 group=0x93000001 group=any,port="+str(output_port2)+",weight=0 group=0x93000002")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x92000001 group=any,port=any,weight=0 set_field=mpls_label:0x901,set_field=mpls_tc:7,set_field=ofdpa_mpls_ttl:250,ttl_out,group=0xA6000001")
        apply_dpctl_mod(self, config, "flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.3.2/255.255.255.0 write:group=0x92000001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:11:33:56 write:group=0x2000"+str(output_port))

        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)

        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:56',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(input_pkt), output_port)

        """
        #shutdown output_port
        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        output_pkt = simple_packet(
                '00 00 04 22 44 67 00 00 04 22 33 57 81 00 00 02 '
                '88 47 00 90 7e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port2)
        """


class mp2mp_decap(base_tests.SimpleDataPlane):
    """
    [test]
    Inject {Tag 2, DA000004224466, SA000004223355, MPLS label 0x903, 0x901} to port 1
    => output {Tag 2, DA000000113355} from port 2

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20002 group=any,port=any,weight=0 output=2
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20000003 group=any,port=any,weight=0 set_field=eth_src=00:00:06:22:33:55,set_field=eth_dst=00:00:06:22:44:66,set_field=vlan_vid=2,group=0x20002
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x1fff apply:set_field=ofdpa_vrf:1 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 vlan_vid=2/0xfff,eth_dst=00:00:04:22:33:55,eth_type=0x8847 goto:23
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=23,cmd=add,prio=203 eth_type=0x8847,mpls_label=0x903 apply:pop_mpls=0x8847,mpls_dec goto:24
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=24,cmd=add,prio=204 eth_type=0x8847,mpls_label=0x901,mpls_bos=1,ofdpa_mpls_data_first_nibble=4 apply:mpls_dec,pop_mpls=0x0800,set_field=ofdpa_vrf:1 goto:30
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=30,cmd=add,prio=301 eth_type=0x0800,ip_dst=192.168.2.2/255.255.255.0,ofdpa_vrf=1 write:group=0x20000003 goto:60
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

        input_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        output_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 00 02 '
                '08 00 45 00 00 4e 00 01 00 00 f9 06 38 4c c0 a8 '
                '05 0a c0 a8 03 02 04 d2 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 f0 2c 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


