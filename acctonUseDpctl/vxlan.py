import logging
from oftest import config
import oftest.base_tests as base_tests
import time
import ofp
import oftest.parse as decode
from oftest.testutils import *
from util import *
from accton_util import *

"""
verify packet may be failed:
because that after encap VxLAN, the identifier of IPv4 header may be increased.
"""

class vxlan_a2n_ucast(base_tests.SimpleDataPlane):
    """
    [add match tunnel & ucast DA, output VTEP]

    Inject untag pkt with DA 000000224477 to port 1/3
    output from port 1/1 with vxlan

    !
    of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
    of-agent vni 1
    of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
    of-agent vtap 10103 ethernet 1/3
    of-agent vtap 10104 ethernet 1/4 vid 3
    of-agent vtp 10001 vni 1
    of-agent vtp 10103 vni 1
    of-agent vtp 10104 vni 1
    !
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 eth_dst=00:00:00:22:44:77,tunn_id=1 write:output=0x10001 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        network_port = test_ports[0]
        access_port = test_ports[1]
        access_port2 = test_ports[2]

        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")
            return

        #paramaters
        access_port_vid=0
        access_lport=0x10103
        vnid=1
        next_hop_id=1
        dst_mac="00:00:00:11:22:33"
        mcast_ipv4=None
        network_lport=0x10001
        network_port_vlan=2
        network_port_sip="192.168.3.1"
        network_port_dip="192.168.3.2"

        xml_before=get_edit_config(config["switch_ip"])
        #get datapath_id from feature message
        feature_reply=get_featureReplay(self)
        #of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id,
                                                  dst_mac=dst_mac,
                                                  phy_port=network_port,
                                                  vlan=network_port_vlan)
        logging.info("config NextHop %d, PHY %d, VLAN %d", next_hop_id, network_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent vni 1
        vni_config_xml=get_vni_config_xml(vni_id=vnid,
                                          mcast_ipv4=mcast_ipv4,
                                          next_hop_id=0)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        #of-agent vtap 10103 ethernet 1/3
        #of-agent vtp 10103 vni 1
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=access_lport, phy_port=access_port,
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtap 10104 ethernet 1/4 vid 3
        #of-agent vtp 10104 vni 1
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=0x10104, phy_port=access_port2,
                                        vlan=3, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", 0x10104, access_port2, 3, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
        #of-agent vtp 10001 vni 1
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id,
                                                lport=network_lport,
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id,
                                                vnid=vnid)
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(network_port)+" group=any,port=any,weight=0 output="+str(network_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 eth_dst=00:00:00:22:44:77,tunn_id=1 write:output=0x10001 goto:60")

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:22:44:77',
                                       eth_src='00:00:00:33:66:99',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.5.2',
                                       ip_ttl=64,
                                       dl_vlan_enable=False)
        output_pkt = simple_packet(
                '00 00 00 11 22 33 70 72 cf c7 cd c7 81 00 00 02 '
                '08 00 45 00 00 88 00 00 00 00 19 11 1a 12 c0 a8 '
                '03 01 c0 a8 03 02 00 00 12 b5 00 74 00 00 08 00 '
                '00 00 00 00 01 00 00 00 00 22 44 77 00 00 00 33 '
                '66 99 08 00 45 00 00 56 00 01 00 00 40 06 ef 44 '
                'c0 a8 05 0a c0 a8 05 02 04 d2 00 50 00 00 00 00 '
                '00 00 00 00 50 02 20 00 dd 13 00 00 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44')

        self.dataplane.send(access_port, str(input_pkt))
        verify_packet(self, str(output_pkt), network_port)

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:22:44:77',
                                       eth_src='00:00:00:33:44:55',
                                       ip_src='192.168.5.4',
                                       ip_dst='192.168.5.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)

        output_pkt = simple_packet(
                '00 00 00 11 22 33 70 72 cf c7 cd c7 81 00 00 02 '
                '08 00 45 00 00 84 00 01 00 00 19 11 1a 15 c0 a8 '
                '03 01 c0 a8 03 02 00 00 12 b5 00 70 00 00 08 00 '
                '00 00 00 00 01 00 00 00 00 22 44 77 00 00 00 33 '
                '44 55 08 00 45 00 00 52 00 01 00 00 40 06 ef 4e '
                'c0 a8 05 04 c0 a8 05 02 04 d2 00 50 00 00 00 00 '
                '00 00 00 00 50 02 20 00 65 a6 00 00 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44')
        self.dataplane.send(access_port2, str(input_pkt))
        verify_packet(self, str(output_pkt), network_port)


class vxlan_n2a_ucast(base_tests.SimpleDataPlane):
    """
    [add match tunnel & ucast DA, output VTAP]

    Inject tag 2 pkt with outer DA 000000000011, SIP 192.168.3.2, DIP 192.168.3.1, inner DA 000000113355 vxlan 1 to port 1/1
    output from port 1/4 with tag 3

    !
    of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
    of-agent vni 1
    of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
    of-agent vtap 10103 ethernet 1/3
    of-agent vtap 10104 ethernet 1/4 vid 3
    of-agent vtp 10001 vni 1
    of-agent vtp 10103 vni 1
    of-agent vtp 10104 vni 1
    !
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x0001fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 in_port=1,vlan_vid=2/0xfff,eth_dst=00:00:00:00:00:11,eth_type=0x00000800 goto:30
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 eth_dst=00:00:00:11:33:55,tunn_id=1 write:output=0x10104 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        network_port = test_ports[0]
        access_port = test_ports[1]
        access_port2 = test_ports[2]

        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")
            return

        #paramaters
        access_port_vid=0
        access_lport=0x10103
        vnid=1
        next_hop_id=1
        dst_mac="00:00:00:11:22:33"
        mcast_ipv4=None
        network_lport=0x10001
        network_port_vlan=2
        network_port_sip="192.168.3.1"
        network_port_dip="192.168.3.2"

        xml_before=get_edit_config(config["switch_ip"])
        #get datapath_id from feature message
        feature_reply=get_featureReplay(self)
        #of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id,
                                                  dst_mac=dst_mac,
                                                  phy_port=network_port,
                                                  vlan=network_port_vlan)
        logging.info("config NextHop %d, PHY %d, VLAN %d", next_hop_id, network_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent vni 1
        vni_config_xml=get_vni_config_xml(vni_id=vnid,
                                          mcast_ipv4=mcast_ipv4,
                                          next_hop_id=0)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        #of-agent vtap 10103 ethernet 1/3
        #of-agent vtp 10103 vni 1
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=access_lport, phy_port=access_port,
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtap 10104 ethernet 1/4 vid 3
        #of-agent vtp 10104 vni 1
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=0x10104, phy_port=access_port2,
                                        vlan=3, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", 0x10104, access_port2, 3, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
        #of-agent vtp 10001 vni 1
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id,
                                                lport=network_lport,
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id,
                                                vnid=vnid)
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(network_port)+",vlan_vid=0x1002/0x0001fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(network_port)+",vlan_vid=2/0xfff,eth_dst=00:00:00:00:00:11,eth_type=0x00000800 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 eth_dst=00:00:00:22:44:77,tunn_id=1 write:output=0x10104 goto:60")

        input_pkt = simple_packet(
                '00 00 00 00 00 11 00 00 00 00 00 33 81 00 00 02 '
                '08 00 45 00 00 72 00 01 00 00 40 11 f3 26 c0 a8 '
                '03 02 c0 a8 03 01 ff ff 12 b5 00 5e 0f 5d 08 00 '
                '00 00 00 00 01 00 00 00 00 22 44 77 00 00 00 00 '
                '00 33 08 00 45 00 00 40 00 01 00 00 40 01 69 48 '
                'c0 a8 c8 21 c0 a8 c8 01 08 00 5f 5d 00 01 00 01 '
                '31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 '
                '67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 '
                '77 78 79 7a ')

        output_pkt = simple_packet(
                '00 00 00 22 44 77 00 00 00 00 00 33 81 00 00 03 '
                '08 00 45 00 00 40 00 01 00 00 40 01 69 48 c0 a8 '
                'c8 21 c0 a8 c8 01 08 00 5f 5d 00 01 00 01 31 32 '
                '33 34 35 36 37 38 39 30 61 62 63 64 65 66 67 68 '
                '69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 '
                '79 7a')

        self.dataplane.send(network_port, str(input_pkt))
        verify_packet(self, str(output_pkt), access_port2)


class vxlan_a2n_mou(base_tests.SimpleDataPlane):
    """
    [add match tunnel & mcast DA, action group subtype 2]

    Inject untag pkt with DA 010000224477 to port 1/3
    output from port 1/1 with vxlan 2, outer DA 000000112233, outer vid 2

    !
    of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
    of-agent nexthop 2 destination 01005e002233 ethernet 1/2 vid 3
    of-agent vni 2 multicast 224.0.0.1 nexthop 2
    of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
    of-agent vtap 10103 ethernet 1/3
    of-agent vtp 10001 vni 2
    of-agent vtp 10103 vni 2
    !
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=all,group=0x80002801 group=any,port=any,weight=0 output=0x10001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 eth_dst=01:00:00:22:44:77,tunn_id=2 write:group=0x80002801 goto:60
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        network_port = test_ports[0]
        vni_port = test_ports[1]
        access_port = test_ports[2]

        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")
            return

        #paramaters
        access_port_vid=0
        access_lport=0x10103
        vnid=2
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:00:11:22:33"
        mcast_ipv4="224.0.0.1"
        dst_mac_mcast="01:00:5e:00:22:33"
        network_lport=0x10001
        vni_vlan=3
        network_port_vlan=2
        network_port_sip="192.168.3.1"
        network_port_dip="192.168.3.2"

        xml_before=get_edit_config(config["switch_ip"])
        #get datapath_id from feature message
        feature_reply=get_featureReplay(self)
        #of-agent nexthop 2 destination 01005e002233 ethernet 1/2 vid 3
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast,
                                                  dst_mac=dst_mac_mcast,
                                                  phy_port=vni_port,
                                                  vlan=vni_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id_mcast, dst_mac_mcast, vni_port, vni_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent nexthop 1 destination 00a0b0c01123 ethernet 1/1 vid 2
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id,
                                                  dst_mac=dst_mac,
                                                  phy_port=network_port,
                                                  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent vni 2 multicast 224.0.0.1 nexthop 2
        vni_config_xml=get_vni_config_xml(vni_id=vnid,
                                          mcast_ipv4=mcast_ipv4,
                                          next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        #of-agent vtap 10103 ethernet 1/3
        #of-agent vtp 10103 vni 2
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=access_lport, phy_port=access_port,
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
        #of-agent vtp 10001 vni 2
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id,
                                                lport=network_lport,
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id,
                                                vnid=vnid)
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(network_port)+" group=any,port=any,weight=0 output="+str(network_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(network_port)+" group=any,port=any,weight=0 output="+str(network_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x80002801 group=any,port=any,weight=0 output=0x10001")
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 eth_dst=01:00:00:22:44:77,tunn_id=2 write:group=0x80002801 goto:60")

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='01:00:00:22:44:77',
                                       eth_src='00:00:00:33:44:55',
                                       ip_src='192.168.5.1',
                                       ip_dst='192.168.5.2',
                                       ip_ttl=64,
                                       dl_vlan_enable=False)

        output_pkt = simple_packet(
                '00 00 00 11 22 33 70 72 cf c7 cd c7 81 00 00 02 '
                '08 00 45 00 00 88 00 01 00 00 19 11 1a 11 c0 a8 '
                '03 01 c0 a8 03 02 00 00 12 b5 00 74 00 00 08 00 '
                '00 00 00 00 02 00 01 00 00 22 44 77 00 00 00 33 '
                '44 55 08 00 45 00 00 56 00 01 00 00 40 06 ef 4d '
                'c0 a8 05 01 c0 a8 05 02 04 d2 00 50 00 00 00 00 '
                '00 00 00 00 50 02 20 00 dd 1c 00 00 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44')

        self.dataplane.send(access_port, str(input_pkt))
        verify_packet(self, str(output_pkt), network_port)


class vxlan_a2n_mom(base_tests.SimpleDataPlane):
    """
    [vxlan mcast over mcast]

    Inject  eth 1/3 untag, DA 010000224477
    Output  eth 1/1 Tag 3, vxlan 2, outer DA 01005e002233

    of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
    of-agent nexthop 2 destination 01005e000001 ethernet 1/1 vid 3
    of-agent vni 2 multicast 224.0.0.1 nexthop 2
    of-agent vtep 10001 source 192.168.2.1 destination 192.168.2.2 udp-src-port 65535 nexthop 1
    of-agent vtap 10103 ethernet 1/3
    of-agent vtp 10001 vni 2
    of-agent vtp 10103 vni 2
    !
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=all,group=0x80002C01 group=any,port=any,weight=0 output=0x10001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 eth_dst=01:00:5e:64:01:01,tunn_id=2 write:group=0x80002C01 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1003/0x1fff goto:20
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())

        input_port = test_ports[0]
        output_port = test_ports[1]

        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")
            return

        #paramaters
        access_port_vid=0
        access_phy_port=input_port
        access_lport=0x10103
        vnid=2
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:00:00:11:22:33"
        mcast_ipv4="224.0.0.1"
        dst_mac_mcast="01:00:5e:00:00:01"
        network_port_phy_port=output_port
        network_lport=0x10001
        vni_vlan=3
        network_port_vlan=2
        network_port_sip="192.168.3.1"
        network_port_dip="192.168.3.1"

        xml_before=get_edit_config(config["switch_ip"])
        #get datapath_id from feature message
        feature_reply=get_featureReplay(self)
        #of-agent nexthop 2 destination 01005e000001 ethernet 1/1 vid 3
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast,
                                                  dst_mac=dst_mac_mcast,
                                                  phy_port=network_port_phy_port,
                                                  vlan=vni_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id_mcast, dst_mac_mcast, network_port_phy_port, vni_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent nexthop 1 destination 000000112233 ethernet 1/1 vid 2
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id,
                                                  dst_mac=dst_mac,
                                                  phy_port=network_port_phy_port,
                                                  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_port_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent vni 2 multicast 224.0.0.1 nexthop 2
        vni_config_xml=get_vni_config_xml(vni_id=vnid,
                                          mcast_ipv4=mcast_ipv4,
                                          next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        #of-agent vtap 10103 ethernet 1/3
        #of-agent vtp 10103 vni 2
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=access_lport, phy_port=access_phy_port,
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_phy_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
        #of-agent vtp 10001 vni 2
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id,
                                                lport=network_lport,
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id,
                                                vnid=vnid)
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x80002C01 group=any,port=any,weight=0 output=0x10001")

        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 eth_dst=01:00:5e:64:01:01,tunn_id=2 write:group=0x80002C01 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(output_port)+",vlan_vid=0x1003/0x1fff goto:20")

        input_pkt = simple_packet(
                '01 00 5e 64 01 01 00 00 00 00 00 33 08 06 00 01 '
                '08 00 06 04 00 01 00 00 00 00 00 aa c0 a8 c8 21 '
                '00 00 00 00 00 bb c0 a8 c8 01 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        output_pkt = simple_packet(
                '01 00 5e 00 00 01 70 72 cf c7 cd c7 81 00 00 03 '
                '08 00 45 00 00 64 00 00 00 00 19 11 fd de c0 a8 '
                '03 01 e0 00 00 01 00 00 12 b5 00 50 00 00 08 00 '
                '00 00 00 00 02 00 01 00 5e 64 01 01 00 00 00 00 '
                '00 33 08 06 00 01 08 00 06 04 00 01 00 00 00 00 '
                '00 aa c0 a8 c8 21 00 00 00 00 00 bb c0 a8 c8 01 '
                '44 44 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class vxlan_dlf_n2a(base_tests.SimpleDataPlane):
    """
    of-agent nexthop 1 destination 00a0b0c01123 ethernet 1/1 vid 2
    of-agent nexthop 2 destination 01005e002233 ethernet 1/1 vid 3
    of-agent vni 100 multicast 224.0.0.1 nexthop 2
    of-agent vtep 10001 source 192.168.0.2 destination 1.1.1.1 udp-src-port 65535 nexthop 1
    of-agent vtap 10103 ethernet 1/2
    of-agent vtp 10001 vni 100
    of-agent vtp 10103 vni 100
    !
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=all,group=0x80064001 group=any,port=any,weight=0 output=0x10001 group=any,port=any,weight=0 output=0x10103
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 tunn_id=100 write:group=0x80064001 goto:60
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=2 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1002/0x0001fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1003/0x0001fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 eth_dst=70:72:CF:C7:CC:0B,eth_type=0x0800 goto:30
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=20,cmd=add,prio=201 eth_dst=01:00:5e:00:22:33/ff:ff:ff:80:00:00,eth_type=0x0800 goto:40
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        access_phy_port = test_ports[0] #1
        network_phy_port = test_ports[1] #2

        if config["switch_ip"] == None:
            logging.error("Doesn't configure switch IP")
            return

        #paramaters
        access_port_vid=0
        access_lport=0x10103
        vnid=100
        next_hop_id=1
        next_hop_id_mcast=2
        dst_mac="00:a0:b0:c0:11:23"
        mcast_ipv4="224.0.0.1"
        dst_mac_mcast="01:00:5e:00:22:33"
        network_lport=0x10001
        vni_vlan=3
        network_port_vlan=2
        network_port_sip="192.168.0.2"
        network_port_dip="1.1.1.1"

        xml_before=get_edit_config(config["switch_ip"])
        #get datapath_id from feature message
        feature_reply=get_featureReplay(self)
        #of-agent nexthop 2 destination 01005e002233 ethernet 1/1 vid 3
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id_mcast,
                                                  dst_mac=dst_mac_mcast,
                                                  phy_port=network_phy_port,
                                                  vlan=vni_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id_mcast, dst_mac_mcast, network_phy_port, vni_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent nexthop 1 destination 00a0b0c01123 ethernet 1/1 vid 2
        next_hop_conf_xml=get_next_hop_config_xml(next_hop_id=next_hop_id,
                                                  dst_mac=dst_mac,
                                                  phy_port=network_phy_port,
                                                  vlan=network_port_vlan)
        logging.info("config NextHop %d, DST_MAC %s, PHY %d, VLAN %d", next_hop_id, dst_mac, network_phy_port, network_port_vlan);
        assert(send_edit_config(config["switch_ip"], next_hop_conf_xml) == True)

        #of-agent vni 100 multicast 224.0.0.1 nexthop 2
        vni_config_xml=get_vni_config_xml(vni_id=vnid,
                                          mcast_ipv4=mcast_ipv4,
                                          next_hop_id=next_hop_id_mcast)
        logging.info("config VNI %lx", vnid);
        assert(send_edit_config(config["switch_ip"], vni_config_xml) == True)

        #of-agent vtap 10103 ethernet 1/3
        #of-agent vtp 10103 vni 100
        vtap_conf_xml=get_vtap_lport_config_xml(dp_id=feature_reply.datapath_id,
                                        lport=access_lport, phy_port=access_phy_port,
                                        vlan=access_port_vid, vnid=vnid)
        logging.info("config VTAP 0x%lx, PHY %d, VID %d, VNID %lx", access_lport, access_phy_port, access_port_vid, vnid);
        assert(send_edit_config(config["switch_ip"], vtap_conf_xml) == True)

        #of-agent vtep 10001 source 192.168.3.1 destination 192.168.3.2 udp-src-port 65535 nexthop 1
        #of-agent vtp 10001 vni 100
        vtep_conf_xml=get_vtep_lport_config_xml(dp_id=feature_reply.datapath_id,
                                                lport=network_lport,
                                                src_ip=network_port_sip, dst_ip=network_port_dip,
                                                next_hop_id=next_hop_id,
                                                vnid=vnid)
        logging.info("config VTEP 0x%lx, SRC_IP %s, DST_IP %s, NEXTHOP_ID %d", network_lport, network_port_sip, network_port_dip, next_hop_id);
        assert(send_edit_config(config["switch_ip"], vtep_conf_xml) == True)

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x2000"+str(network_phy_port)+" group=any,port=any,weight=0 output="+str(network_phy_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(network_phy_port)+" group=any,port=any,weight=0 output="+str(network_phy_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=all,group=0x80064001 group=any,port=any,weight=0 output=0x10001 group=any,port=any,weight=0 output=0x10103")
        apply_dpctl_mod(self, config, "flow-mod table=0,cmd=add,prio=1 in_port=0x10000/0xffff0000 goto:50")
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 tunn_id=100 write:group=0x80064001 goto:60")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(network_phy_port)+",vlan_vid=0x1002/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(network_phy_port)+",vlan_vid=0x1003/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 eth_dst=70:72:CF:C7:CC:0B,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 eth_dst=01:00:5e:00:22:33/ff:ff:ff:80:00:00,eth_type=0x0800 goto:40")

        input_pkt = simple_packet(
                '70 72 cf c7 cc 0b 00 00 00 00 00 33 81 00 00 02 '
                '08 00 45 00 00 72 00 01 00 00 40 11 b7 ce 01 01 '
                '01 01 c0 a8 00 02 00 00 12 b5 00 5e 82 59 08 00 '
                '00 00 00 00 64 00 00 00 00 11 33 55 00 00 00 00 '
                '00 11 08 00 45 00 00 40 00 01 00 00 40 01 69 48 '
                'c0 a8 c8 21 c0 a8 c8 01 08 00 5f 5d 00 01 00 01 '
                '31 32 33 34 35 36 37 38 39 30 61 62 63 64 65 66 '
                '67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 '
                '77 78 79 7a')
        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 00 00 11 08 00 45 00 '
                '00 40 00 01 00 00 40 01 69 48 c0 a8 c8 21 c0 a8 '
                'c8 01 08 00 5f 5d 00 01 00 01 31 32 33 34 35 36 '
                '37 38 39 30 61 62 63 64 65 66 67 68 69 6a 6b 6c '
                '6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a')

        self.dataplane.send(network_phy_port, str(input_pkt))
        verify_packet(self, str(output_pkt), access_phy_port)


