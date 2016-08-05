"""
MPLS Flow Test

Test each flow table can set entry, and packet rx correctly.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class encap_mpls(base_tests.SimpleDataPlane):
    #Encap a MPLS label
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        tunnel_id=0x10001
        mpls_l2_port=100
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id, False, 0, True, 0x20100, tunnel_id, True)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_intf_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 0, tunnel_id, mpls_l2_port, VLAN_TABLE_FLAG_MPLS_ALL, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 03 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b2 47 c0 a8 01 64 c0 a8 02 02 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_mpls(base_tests.SimpleDataPlane):
    #Decap a MPLS label
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        tunnel_id=0x10001
        mpls_l2_port=100
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, in_port, vlan_id, True, False)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id, False, 0, True, 0x20100, tunnel_id, True)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_intf_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [out_port], 0, tunnel_id, mpls_l2_port, VLAN_TABLE_FLAG_MPLS_ALL, True)
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 '
                '00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_2mpls(base_tests.SimpleDataPlane):
    #Encap 2 MPLS labels
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        tunnel_id=0x10001
        mpls_l2_port=100
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id, False, 0, True, 0x20100, tunnel_id, True)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_tunl_l1_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 0, tunnel_id, mpls_l2_port, VLAN_TABLE_FLAG_MPLS_ALL, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_3mpls(base_tests.SimpleDataPlane):
    #Encap 3 MPLS labels
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        tunnel_id=0x10001
        mpls_l2_port=100
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id, False, 0, True, 0x20100, tunnel_id, True)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 2 group
        mpls_tunl_l2_gid, mpls_tunl_l2_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL2, 1, mpls_intf_gid,
                         set_mpls_label=0x904, push_mpls_header=True)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_tunl_l2_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_tunl_l1_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 81 00 '
                '00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 '
                'c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_penultimate_mpls(base_tests.SimpleDataPlane):
    #Pop outermost tunnel label
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_PENULTIMATE_HOP_POP, 0x8847, mpls_intf_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1e fa 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 01 0f f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_2mpls(base_tests.SimpleDataPlane):
    #Pop 2 tunnel labels
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        tunnel_id=0x10001
        mpls_l2_port=100
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, in_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_tunl_l1_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [out_port], vlan_id, tunnel_id, mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)
        #add mpls 0 flow
        add_mpls0_flow(self.controller, 0x903, True)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id, False, 0, True, 0x20100, tunnel_id, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_penultimate_swap_mpls(base_tests.SimpleDataPlane):
    #Pop outermost tunnel label and swap inner MPLS label (MS-PW, LSR)
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        tunnel_id=0x10001
        mpls_l2_port=100
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_intf_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add mpls 0 flow
        add_mpls0_flow(self.controller, 0x903, True)
        #add MPLS swap group
        mpls_swap_gid, mpls_swap_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, 1, mpls_intf_gid, set_mpls_label=0x905)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_SWAP_LABEL, 0, mpls_swap_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 51 f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class swap_out_mpls(base_tests.SimpleDataPlane):
    #Swap outermost MPLS label (LSR)
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x67]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x57]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS swap group
        mpls_swap_gid, mpls_swap_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, 1, mpls_intf_gid, set_mpls_label=0x9051)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x901, 1, MPLS1_TABLE_FLAG_SWAP_LABEL, 0, mpls_swap_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, dst_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1e fa 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 67 00 00 04 22 33 57 81 00 00 02 '
                '88 47 09 05 10 f9 00 01 0b ff 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 05 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class swap_encap_mpls(base_tests.SimpleDataPlane):
    #Swap and encap a MPLS label
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x68]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x58]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS swap group
        mpls_swap_gid, mpls_swap_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, 1, mpls_intf_gid, set_mpls_label=0x9052)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x901, 1, MPLS1_TABLE_FLAG_SWAP_LABEL, 0, mpls_swap_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, dst_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 68 00 00 04 22 33 58 81 00 00 02 '
                '88 47 09 05 21 f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class swap_encap_2mpls(base_tests.SimpleDataPlane):
    #Swap and encap 2 MPLS labels
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x68]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x58]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 2 group
        mpls_tunl_l2_gid, mpls_tunl_l2_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL2, 1, mpls_intf_gid,
                         set_mpls_label=0x904, push_mpls_header=True)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_tunl_l2_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS swap group
        mpls_swap_gid, mpls_swap_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_SWAP_LABEL, 1, mpls_tunl_l1_gid, set_mpls_label=0x9052)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x901, 1, MPLS1_TABLE_FLAG_SWAP_LABEL, 0, mpls_swap_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, dst_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 68 00 00 04 22 33 58 81 00 00 02 '
                '88 47 00 90 40 f9 00 90 30 f9 09 05 21 f9 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 81 00 '
                '00 05 08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa '
                'c0 a8 02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 '
                '08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 '
                '18 19 00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_1mpls_of3(base_tests.SimpleDataPlane):
    #Decap outermost one MPLS of 3 MPLS labels
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x904, 1, MPLS1_TABLE_FLAG_PENULTIMATE_HOP_POP, 0x8847, mpls_intf_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 00 00 '
                '00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa '
                'c0 a8 02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 '
                '08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 '
                '18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e f9 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 00 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 02 01 '
                'c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 0a 0b '
                '0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_2mpls_of3(base_tests.SimpleDataPlane):
    #Decap outermost two MPLS of 3 MPLS labels
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add mpls0 flow
        add_mpls0_flow(self.controller, 0x904, True)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x903, 1, MPLS1_TABLE_FLAG_PENULTIMATE_HOP_POP, 0x8847, mpls_intf_gid, False, 0, False, 0, 0, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 00 00 '
                '00 00 00 00 00 11 33 55 00 00 00 11 22 33 00 00 '
                '00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa '
                'c0 a8 02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 '
                '08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 '
                '18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 1f f9 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 00 00 00 03 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_2mpls_ff(base_tests.SimpleDataPlane):
    #Encap two MPLS labels with fast failover group
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        tunnel_id=0x10001
        mpls_l2_port=100
        mpls_label=0x901
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x65]
        src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid1,
                set_mpls_label=0x9031, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac2, src_mac2, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid2,
                         set_mpls_label=0x9035, push_mpls_header=True)
        #add MPLS FF group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid1, mpls_tunl_l1_gid2], watch_port=[out_port1, out_port2])
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunnel_id, mpls_l2_port, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add mpls1 flow
        add_mpls1_flow(self.controller, mpls_label, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id1, False, 0, True, 0x20100, tunnel_id, True)

        #input packet
        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        pkt = str(input_pkt)
        self.dataplane.send(in_port, pkt)

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 09 03 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 44 65 00 00 04 22 33 55 81 00 00 02 '
                '88 47 09 03 5e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        verify_packet(self, str(output_pkt), out_port1)
        print 'ff1 done'
        #if output_port link down
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x1,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x1, mask=0x1)
        self.controller.message_send(request)

        time.sleep(5)
        self.dataplane.send(in_port, str(input_pkt))

        #recover output_port link status, before assert check
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x0,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x0, mask=0x1)
        self.controller.message_send(request)
        time.sleep(3)
        """
        #make sure port link up
        port_up = 0
        while port_up == 0:
            time.sleep(1)
            #apply_dpctl_mod(self, config, "port-mod port="+str(output_port)+",conf=0x0,mask=0x1")
            #json_result = apply_dpctl_get_cmd(self, config, "port-desc")
            stats = get_stats(self, ofp.message.port_desc_stats_request())
            for entry in stats:
                logging.info(entry.show())

            result=json_result["RECEIVED"][1]
            for p_desc in result["port"]:
                if p_desc["no"] == output_port:
                    if p_desc["config"] != 0x01 : #up
                        port_up = 1
        """
        #check if output_port2 receives packet
        verify_packet(self, str(output_pkt2), out_port2)


class decap_mpls_acl(base_tests.SimpleDataPlane):
    #Decap a MPLS label with ACL
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        tunn_id=0x10001
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, in_port, vlan_id, True, False)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x901, 1, MPLS1_TABLE_FLAG_L2_VPWS, 0x8847, group_id, False, 0, True, 0x20100, tunn_id, True)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, dst_mac, src_mac, vlan_id, 1, 0)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_intf_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=0x901)
        #add mpls l2 port flow
        add_mpls_l2_port_flow(self.controller, tunn_id, 100, mpls_vpn_gid, True)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 0, tunn_id, 100, VLAN_TABLE_FLAG_MPLS_ALL, True)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x8847, src_mac, vlan_id, 24, True)

        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add acl flow
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.tunnel_id(tunn_id))
        match.oxm_list.append(ofp.oxm.exp4ByteValue(exp_type=8, value=0x20100))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=60,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(group_id)]
                    )
            ],
            priority=601)
        #install flow
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 1f fa 00 00 00 00 00 00 00 11 33 55 '
                '00 00 00 11 22 33 81 00 00 05 08 00 45 00 00 2e '
                '04 d2 00 00 7f 00 b1 aa c0 a8 02 01 c0 a8 02 02 '
                '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f '
                '10 11 12 13 14 15 16 17 18 19 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b1 aa c0 a8 '
                '02 01 c0 a8 02 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 '
                '00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_mpls_l3(base_tests.SimpleDataPlane):
    #Encap a MPLS label
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_intf_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=mpls_label)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, mpls_vpn_gid, send_barrier=True)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 1f fa 45 00 00 4e 00 01 00 00 3f 06 '
                'f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 00 50 00 00 '
                '00 00 00 00 00 00 50 02 20 00 f0 2c 00 00 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_mpls_l3(base_tests.SimpleDataPlane):
    #Decap a MPLS label with L3 routing
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=12
        dst_mac=[0x00, 0x00, 0x00, 0x00, 0x01, 0x11]
        new_dst_mac=[0x00, 0x00, 0x06, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x06, 0x22, 0x33, 0x55]
        #add vlan flow
        add_one_vlan_table_flow(self.controller, in_port, vlan_id, 1, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, 10, True, False)
        #add l3 ucast group
        l3ucast_msg=add_l3_unicast_group(self.controller, out_port, 10, 1, new_src_mac, new_dst_mac)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x1234, 1, MPLS1_TABLE_FLAG_L3_VPN_ROUTE, 0x0800, 0, True, 1, False, 0, 0, True)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, l3ucast_msg.group_id, 1, True)
        #add term mac flow
        add_termination_flow(self.controller, 0, 0x8847, dst_mac, vlan_id, 24, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 00 00 01 11 00 00 00 11 22 33 81 00 00 0c '
                '88 47 01 23 41 3f 45 00 00 26 00 00 00 00 3f 00 '
                'f5 84 c0 a8 02 01 c0 a8 03 02 00 01 02 03 04 05 '
                '06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 '
                '16 17 18 19')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 00 0a '
                '08 00 45 00 00 26 00 00 00 00 3e 00 f6 84 c0 a8 '
                '02 01 c0 a8 03 02 00 01 02 03 04 05 06 07 08 09 '
                '0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_2mpls_l3(base_tests.SimpleDataPlane):
    #Encap two MPLS labels with L3 routing
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_tunl_l1_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=mpls_label)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, mpls_vpn_gid, send_barrier=True)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_2mpls_l3(base_tests.SimpleDataPlane):
    #Decap two MPLS labels with L3 routing
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        dst_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        new_dst_mac=[0x00, 0x00, 0x06, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x06, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add l3 ucast group
        l3ucast_msg=add_l3_unicast_group(self.controller, out_port, vlan_id, 1, new_src_mac, new_dst_mac)
        #add vlan flow
        add_one_vlan_table_flow(self.controller, in_port, vlan_id, 1, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, 0, 0x8847, dst_mac, vlan_id, 24, True)
        #add mpls0 flow
        add_mpls0_flow(self.controller, 0x903, True)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x901, 1, MPLS1_TABLE_FLAG_L3_VPN_ROUTE, 0x0800, 0, True, 1, False, 0, 0, True)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, l3ucast_msg.group_id, 1, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 66 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 00 02 '
                '08 00 45 00 00 4e 00 01 00 00 f9 06 38 4c c0 a8 '
                '05 0a c0 a8 03 02 04 d2 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 f0 2c 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_3mpls_l3(base_tests.SimpleDataPlane):
    #Encap 3 MPLS labels with L3 routing
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 2 group
        mpls_tunl_l2_gid, mpls_tunl_l2_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL2, 1, mpls_intf_gid,
                         set_mpls_label=0x904, push_mpls_header=True)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_tunl_l2_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_tunl_l1_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=mpls_label)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, mpls_vpn_gid, send_barrier=True)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 4e fa 00 90 3e fa 00 90 1f fa 45 00 '
                '00 4e 00 01 00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 '
                '03 02 04 d2 00 50 00 00 00 00 00 00 00 00 50 02 '
                '20 00 f0 2c 00 00 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_2mpls_l3v6(base_tests.SimpleDataPlane):
    #Encap two MPLS labels with L3 routing
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        v6_dst = '\x20\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03'
        v6_dst_mask = '\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'

        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x86dd, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_tunl_l1_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=mpls_label)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x86dd, v6_dst, v6_dst_mask, mpls_vpn_gid, send_barrier=True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '86 dd 60 00 00 00 00 08 11 7f 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 02 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 00 0d 00 07 00 08 '
                'bf 9f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 60 00 00 00 00 08 '
                '11 7e 20 14 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 02 20 14 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 01 00 0d 00 07 00 08 bf 9f 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00')
        verify_packet(self, str(parsed_pkt), out_port)


class decap_2mpls_l3v6(base_tests.SimpleDataPlane):
    #Decap two MPLS labels with L3 routing
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=2
        ofdpa_vrf=1
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        new_dst_mac=[0x00, 0x00, 0x06, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x06, 0x22, 0x33, 0x55]
        v6_dst = '\x20\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03'
        v6_dst_mask = '\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00'

        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add l3 ucast group
        l3_msg = add_l3_unicast_group(self.controller, out_port, vlan_id, 1, new_src_mac, new_dst_mac)
        #add vlan flow
        add_one_vlan_table_flow(self.controller, in_port, vlan_id, ofdpa_vrf, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, 0, 0x8847, dst_mac, vlan_id, 24, True)
        #add mpls 0 flow
        add_mpls0_flow(self.controller, 0x903, True)
        #add mpls1 flow
        add_mpls1_flow(self.controller, 0x901, 1, MPLS1_TABLE_FLAG_L3_VPN_ROUTE, 0x86dd, 0, True, ofdpa_vrf, False, 0, 0, True)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x86dd, v6_dst, v6_dst_mask, l3_msg.group_id, ofdpa_vrf, True)

        #input packet
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 00 00 33 81 00 00 02 '
                '88 47 00 90 30 40 00 90 11 40 60 00 00 00 00 2c '
                '3a 40 20 14 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 01 20 14 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 03 80 00 a6 ca 00 01 00 01 31 32 33 34 35 36 '
                '37 38 39 30 61 62 63 64 65 66 67 68 69 6a 6b 6c '
                '6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a ')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_packet(
                '00 00 06 22 44 66 00 00 06 22 33 55 81 00 00 02 '
                '86 dd 60 00 00 00 00 2c 3a 3f 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 01 20 14 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 03 80 00 a6 ca 00 01 '
                '00 01 31 32 33 34 35 36 37 38 39 30 61 62 63 64 '
                '65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 '
                '75 76 77 78 79 7a')
        verify_packet(self, str(parsed_pkt), out_port)


class encap_2mpls_l3_mp2mp(base_tests.SimpleDataPlane):
    #add MPLS 2 labels: Table 0 -> table 10 -> table 20 -> table 30 -> MPLS L3 VPN group -> MPLS FF group -> MPLS tunnel label 1 group -> MPLS intf group -> L2 intf group
    #NOT add MPLS 2 labels: Table 0 -> table 10 -> table 60 -> L2 intf group
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]

        vlan_id=2
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        dst_mac2=[0x00, 0x00, 0x00, 0x11, 0x33, 0x56]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        new_dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x67]
        new_src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x57]
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg2=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg2=add_mpls_intf_group(self.controller, group_id2, new_dst_mac2, new_src_mac2, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid2,
                         set_mpls_label=0x907, push_mpls_header=True)

        #add mpls ff group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid, mpls_tunl_l1_gid2], watch_port=[out_port, out_port2])
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=0x901)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, mpls_vpn_gid, send_barrier=True)
        #add acl flow
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac2))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=60,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(group_id)]
                    )
            ],
            priority=601)
        #install flow
        self.controller.message_send(request)

        #input packet
        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:56',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(input_pkt), out_port)
        print 'normal done'
        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(in_port, str(input_pkt))
        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        verify_packet(self, str(output_pkt), out_port)
        print 'ff1 done'
        #if output_port link down
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port)+",conf=0x1,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port, config=0x1, mask=0x1)
        self.controller.message_send(request)

        time.sleep(5)
        self.dataplane.send(in_port, str(input_pkt))

        #recover output_port link status, before assert check
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port)+",conf=0x0,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port, config=0x0, mask=0x1)
        self.controller.message_send(request)
        time.sleep(5)

        output_pkt2 = simple_packet(
                '00 00 04 22 44 67 00 00 04 22 33 57 81 00 00 02 '
                '88 47 00 90 7e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        verify_packet(self, str(output_pkt2), out_port2)


class encap_2mpls_l3_mp2mp_vrf(base_tests.SimpleDataPlane):
    #add MPLS 2 labels: Table 0 -> table 10 -> table 20 -> table 30 -> MPLS L3 VPN group -> MPLS FF group -> MPLS tunnel label 1 group -> MPLS intf group -> L2 intf group
    #NOT add MPLS 2 labels: Table 0 -> table 10 -> table 60 -> L2 intf group
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]

        vlan_id=2
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        dst_mac2=[0x00, 0x00, 0x00, 0x11, 0x33, 0x56]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        new_dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x67]
        new_src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x57]
        ofdpa_vrf=1
        #add vlan flow
        add_one_vlan_table_flow(self.controller, in_port, vlan_id, ofdpa_vrf, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg2=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg2=add_mpls_intf_group(self.controller, group_id2, new_dst_mac2, new_src_mac2, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid2,
                         set_mpls_label=0x907, push_mpls_header=True)

        #add mpls ff group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid, mpls_tunl_l1_gid2], watch_port=[out_port, out_port2])
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=0x901)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, mpls_vpn_gid, ofdpa_vrf, True)
        #add acl flow
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac2))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=60,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(group_id)]
                    )
            ],
            priority=601)
        #install flow
        self.controller.message_send(request)

        #input packet
        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:56',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(input_pkt), out_port)
        print 'normal done'
        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        self.dataplane.send(in_port, str(input_pkt))
        output_pkt = simple_packet(
                '00 00 04 22 44 66 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 90 3e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        verify_packet(self, str(output_pkt), out_port)
        print 'ff1 done'
        #if output_port link down
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port)+",conf=0x1,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port, config=0x1, mask=0x1)
        self.controller.message_send(request)

        time.sleep(5)
        self.dataplane.send(in_port, str(input_pkt))

        #recover output_port link status, before assert check
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port)+",conf=0x0,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port, config=0x0, mask=0x1)
        self.controller.message_send(request)
        time.sleep(5)

        output_pkt2 = simple_packet(
                '00 00 04 22 44 67 00 00 04 22 33 57 81 00 00 02 '
                '88 47 00 90 7e fa 00 90 1f fa 45 00 00 4e 00 01 '
                '00 00 3f 06 f2 4c c0 a8 05 0a c0 a8 03 02 04 d2 '
                '00 50 00 00 00 00 00 00 00 00 50 02 20 00 f0 2c '
                '00 00 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44')
        verify_packet(self, str(output_pkt2), out_port2)


class encap_2mpls_l3_mp2mp_vrf_diff(base_tests.SimpleDataPlane):
    #add MPLS 2 labels: Table 0 -> table 10 -> table 20 -> table 30 -> MPLS L3 VPN group -> MPLS FF group -> MPLS tunnel label 1 group -> MPLS intf group -> L2 intf group
    #NOT add MPLS 2 labels: Table 0 -> table 10 -> table 60 -> L2 intf group
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]

        vlan_id=2
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        dst_mac2=[0x00, 0x00, 0x00, 0x11, 0x33, 0x56]
        new_dst_mac=[0x00, 0x00, 0x04, 0x22, 0x44, 0x66]
        new_src_mac=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        new_dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x67]
        new_src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x57]
        ofdpa_vrf=1
        ofdpa_vrf2=2
        #add vlan flow
        add_one_vlan_table_flow(self.controller, in_port, vlan_id, ofdpa_vrf, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id, 30, True)
        #add l2 intf group
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id, new_dst_mac, new_src_mac, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid,
                         set_mpls_label=0x903, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg2=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg2=add_mpls_intf_group(self.controller, group_id2, new_dst_mac2, new_src_mac2, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid2,
                         set_mpls_label=0x907, push_mpls_header=True)

        #add mpls ff group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid, mpls_tunl_l1_gid2], watch_port=[out_port, out_port2])
        #add MPLS L3 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L3_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, cpy_ttl_outward=True, set_mpls_label=0x901)
        #add ucast route flow
        add_unicast_routing_flow(self.controller, 0x800, 0xc0a80302, 0xffffff00, mpls_vpn_gid, ofdpa_vrf2, True)
        #add acl flow
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac2))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=60,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(group_id)]
                    )
            ],
            priority=601)
        #install flow
        self.controller.message_send(request)

        input_pkt = simple_tcp_packet(pktlen=96,
                                       eth_dst='00:00:00:11:33:56',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(input_pkt), out_port)

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

        self.dataplane.send(in_port, str(input_pkt))
        verify_no_packet(self, str(output_pkt), out_port)


##################################################
# MPLS VPLS
##################################################

class encap_2mpls_vpls_p2p_ff(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to FF provider
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        tunnel_id=0x20001
        provider_mpls_l2_port=0x30001
        customer_mpls_l2_port=0x10001
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x65]
        src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac2, src_mac2, vlan_id, 3, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 3, mpls_intf_gid2,
                         set_mpls_label=0x935, push_mpls_header=True)
        #add MPLS FF group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid1, mpls_tunl_l1_gid2], watch_port=[out_port1, out_port2])
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add VPLS provider port
        provider_gid, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port, 0x9C000001)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, customer_mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, provider_gid, True, True)

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 44 65 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 93 5e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        print 'ff1 done'
        #if output_port link down
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x1,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x1, mask=0x1)
        self.controller.message_send(request)

        time.sleep(5)
        self.dataplane.send(in_port, str(input_pkt))

        #recover output_port link status, before assert check
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x0,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x0, mask=0x1)
        self.controller.message_send(request)
        time.sleep(3)
        #check if output_port2 receives packet
        verify_packet(self, str(output_pkt2), out_port2)


class decap_2mpls_vpls_p2p(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: provider to customer
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        inport_vlan_id=3
        tunnel_id=0x20001
        provider_mpls_l2_port=0x30001
        customer_mpls_l2_port=0x10001
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x65]
        src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, True)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, True)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac2, src_mac2, vlan_id, 3, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 3, mpls_intf_gid2,
                         set_mpls_label=0x935, push_mpls_header=True)
        #add MPLS FF group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid1, mpls_tunl_l1_gid2], watch_port=[out_port1, out_port2])
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add VPLS provider port
        provider_gid, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port, 0x9C000001)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], inport_vlan_id, tunnel_id, customer_mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, provider_gid, True, True)

        #add normal vlan flow
        add_vlan_table_flow(self.controller, [out_port1], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        add_vlan_table_flow(self.controller, [out_port2], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add term mac flow
        add_termination_flow(self.controller, out_port1, 0x8847, src_mac1, vlan_id, 23, True)
        add_termination_flow(self.controller, out_port2, 0x8847, src_mac2, vlan_id, 23, True)
        #add mpls0 flow
        add_mpls0_flow(self.controller, 0x931, True)
        add_mpls0_flow(self.controller, 0x935, True)
        #add l2 intf group
        group_id3, msg=add_one_l2_interface_group(self.controller, in_port, inport_vlan_id, True, True)
        #add VPLS customer port
        customer_gid, provider_msg=add_mpls_vpls_port_group(self.controller, group_id3, tunnel_id, customer_mpls_l2_port, 0x9D000001)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, src_mac, tunnel_id, customer_gid, True, True)

        input_pkt = simple_packet(
                '00 00 00 11 22 33 00 00 00 11 33 55 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 33 51 00 00 04 22 44 61 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 22 33 00 00 00 11 33 55 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 33 55 00 00 04 22 44 65 81 00 00 02 '
                '88 47 00 93 5e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 22 33 00 00 00 11 33 55 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(out_port1, str(output_pkt))
        verify_packet(self, str(input_pkt), in_port)
        print 'send 1st done'
        self.dataplane.send(out_port2, str(output_pkt2))
        verify_packet(self, str(input_pkt), in_port)


class encap_2mpls_vpls_p2p_normal(base_tests.SimpleDataPlane):
    #NOT care output vlan with input
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        inport_vlan_id=3
        tunnel_id=0x20001
        customer_mpls_l2_port1=0x10001
        customer_mpls_l2_port2=0x10002
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, True)
        #add VPLS customer port
        customer_gid, provider_msg=add_mpls_vpls_port_group(self.controller, group_id1, tunnel_id, customer_mpls_l2_port2, 0x9D000001)

        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], inport_vlan_id, tunnel_id, customer_mpls_l2_port1, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, customer_gid, True, True)

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(input_pkt), out_port1)


class encap_2mpls_vpls_p2m_same(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to multiple provider with same output
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        tunnel_id=0x20001
        provider_mpls_l2_port1=0x30001
        provider_mpls_l2_port2=0x30002
        customer_mpls_l2_port=0x10001
        mpls_label=0x901
        dst_mac=[0x01, 0x00, 0x5e, 0x11, 0x33, 0x55]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 1, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 1, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_tunl_l1_gid1,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid2,
                         set_mpls_label=0x931, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid2, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 2, mpls_tunl_l1_gid2,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)

        #add VPLS provider port
        provider_gid1, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port1, 0x9C000001)
        provider_gid2, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid2, tunnel_id, provider_mpls_l2_port2, 0x9C000002)
        #add vpls mcast group
        mcast_gid, mcast_msg=add_mpls_vpls_mcast_group(self.controller, [provider_gid1, provider_gid2], 0x9f000001)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, customer_mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, mcast_gid, True, True)

        input_pkt = simple_packet(
                '01 00 5e 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 01 00 '
                '5e 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        verify_packet(self, str(output_pkt), out_port2)


class encap_2mpls_vpls_p2m_diff(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to multiple provider with different mpls
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        tunnel_id=0x20001
        provider_mpls_l2_port1=0x30001
        provider_mpls_l2_port2=0x30002
        customer_mpls_l2_port=0x10001
        dst_mac=[0x01, 0x00, 0x5e, 0x11, 0x33, 0x55]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x65]
        src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 2, mpls_tunl_l1_gid1,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=0x901)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac2, src_mac2, vlan_id, 3, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 3, mpls_intf_gid2,
                         set_mpls_label=0x935, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid2, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 3, mpls_tunl_l1_gid2,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=0x903)

        #add VPLS provider port
        provider_gid1, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port1, 0x9C000001)
        provider_gid2, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid2, tunnel_id, provider_mpls_l2_port2, 0x9C000002)
        #add vpls mcast group
        mcast_gid, mcast_msg=add_mpls_vpls_mcast_group(self.controller, [provider_gid1, provider_gid2], 0x9f000001)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, customer_mpls_l2_port, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, mcast_gid, True, True)

        input_pkt = simple_packet(
                '01 00 5e 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 01 00 '
                '5e 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 44 65 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 93 5e fa 00 90 3f fa 00 00 00 00 01 00 '
                '5e 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        verify_packet(self, str(output_pkt2), out_port2)


class encap_2mpls_vpls_p2m_cp(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to provider and customer
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        tunnel_id=0x20001
        provider_mpls_l2_port1=0x30001
        customer_mpls_l2_port1=0x10001
        customer_mpls_l2_port2=0x10002
        dst_mac=[0x01, 0x00, 0x5e, 0x11, 0x33, 0x55]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 2, mpls_tunl_l1_gid1,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=0x901)
        #add VPLS provider port
        provider_gid1, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port1, 0x9C000001)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, True)
        #add VPLS customer port
        customer_gid, provider_msg=add_mpls_vpls_port_group(self.controller, group_id2, tunnel_id, customer_mpls_l2_port2, 0x9D000001)

        #add vpls mcast group
        mcast_gid, mcast_msg=add_mpls_vpls_mcast_group(self.controller, [provider_gid1, customer_gid], 0x9f000001)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, customer_mpls_l2_port1, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, mcast_gid, True, True)

        input_pkt = simple_packet(
                '01 00 5e 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 01 00 '
                '5e 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        verify_packet(self, str(input_pkt), out_port2)


class encap_2mpls_vpls_p2m_dlf(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to provider and customer
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        tunnel_id=0x20001
        provider_mpls_l2_port1=0x30001
        customer_mpls_l2_port1=0x10001
        customer_mpls_l2_port2=0x10002
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 2, mpls_tunl_l1_gid1,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=0x901)
        #add VPLS provider port
        provider_gid1, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port1, 0x9C000001)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, True)
        #add VPLS customer port
        customer_gid, provider_msg=add_mpls_vpls_port_group(self.controller, group_id2, tunnel_id, customer_mpls_l2_port2, 0x9D000001)

        #add vpls unknown mcast group
        mcast_gid, mcast_msg=add_mpls_vpls_mcast_group(self.controller, [provider_gid1, customer_gid], 0x9E020001)
        #add vlan flow
        add_vlan_table_flow_mpls(self.controller, [in_port], 3, tunnel_id, customer_mpls_l2_port1, VLAN_TABLE_FLAG_MPLS_TAG, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, None, tunnel_id, mcast_gid, True, True)

        input_pkt = simple_packet(
                '01 00 5e 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 01 00 '
                '5e 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        verify_packet(self, str(input_pkt), out_port2)

        input_pkt = simple_packet(
                '00 00 00 11 22 33 00 00 00 11 33 55 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 22 33 00 00 00 11 33 55 81 00 00 03 08 00 '
                '45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        verify_packet(self, str(input_pkt), out_port2)


class encap_2mpls_vpls_p2p_ff_pop_outer_vlan(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to FF provider
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        inport_vlan_id=3
        ovid=6
        tunnel_id=0x20001
        provider_mpls_l2_port=0x30001
        customer_mpls_l2_port=0x10001
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x65]
        src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac2, src_mac2, vlan_id, 3, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 3, mpls_intf_gid2,
                         set_mpls_label=0x935, push_mpls_header=True)
        #add MPLS FF group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid1, mpls_tunl_l1_gid2], watch_port=[out_port1, out_port2])
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add VPLS provider port
        provider_gid, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port, 0x9C000001)
        #add vlan flow
        add_vlan_table_flow_xlate(self.controller, [in_port], ovid, 0, ovid, VLAN_TABLE_FLAG_XLATE_DOUBLE_TO_SINGLE, True)
        #add vlan1 flow
        add_vlan1_table_flow(self.controller, [in_port], inport_vlan_id, ovid, 0, False, 0, customer_mpls_l2_port, tunnel_id, VLAN1_TABLE_FLAG_MPLS, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, provider_gid, True, True)

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 06 '
                '81 00 00 03 08 00 45 00 00 2a 04 d2 00 00 7f 00 '
                'b2 4b c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2a 04 d2 00 00 7f 00 b2 4b c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 44 65 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 93 5e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 03 08 00 '
                '45 00 00 2a 04 d2 00 00 7f 00 b2 4b c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        print 'ff1 done'
        #if output_port link down
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x1,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x1, mask=0x1)
        self.controller.message_send(request)

        time.sleep(5)
        self.dataplane.send(in_port, str(input_pkt))

        #recover output_port link status, before assert check
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x0,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x0, mask=0x1)
        self.controller.message_send(request)
        time.sleep(3)
        #check if output_port2 receives packet
        verify_packet(self, str(output_pkt2), out_port2)


class encap_2mpls_vpls_p2p_ff_pop_outer_vlan_change_inner(base_tests.SimpleDataPlane):
    #Encap two MPLS labels: customer to FF provider
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port1=config["port_map"].keys()[1]
        out_port2=config["port_map"].keys()[2]
        vlan_id=2
        inport_vlan_id=3
        ovid=6
        tunnel_id=0x20001
        provider_mpls_l2_port=0x30001
        customer_mpls_l2_port=0x10001
        mpls_label=0x901
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        dst_mac1=[0x00, 0x00, 0x04, 0x22, 0x44, 0x61]
        src_mac1=[0x00, 0x00, 0x04, 0x22, 0x33, 0x51]
        dst_mac2=[0x00, 0x00, 0x04, 0x22, 0x44, 0x65]
        src_mac2=[0x00, 0x00, 0x04, 0x22, 0x33, 0x55]
        #add l2 intf group
        group_id1, msg=add_one_l2_interface_group(self.controller, out_port1, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid1, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id1, dst_mac1, src_mac1, vlan_id, 2, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid1, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 2, mpls_intf_gid1,
                set_mpls_label=0x931, push_mpls_header=True)

        #add l2 intf group
        group_id2, msg=add_one_l2_interface_group(self.controller, out_port2, vlan_id, True, False)
        #add mpls intf group
        mpls_intf_gid2, mpls_intf_msg=add_mpls_intf_group(self.controller, group_id2, dst_mac2, src_mac2, vlan_id, 3, 0)
        #add MPLS Tunnel Label 1 group
        mpls_tunl_l1_gid2, mpls_tunl_l1_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_TUNNEL_LABEL1, 3, mpls_intf_gid2,
                         set_mpls_label=0x935, push_mpls_header=True)
        #add MPLS FF group
        mpls_ff_gid, mpls_ff_msg=add_mpls_forwarding_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_FAST_FAILOVER_GROUP, 1,
                [mpls_tunl_l1_gid1, mpls_tunl_l1_gid2], watch_port=[out_port1, out_port2])
        #add MPLS L2 VPN Label group
        mpls_vpn_gid, mpls_vpn_msg=add_mpls_label_group(self.controller, OFDPA_MPLS_GROUP_SUBTYPE_L2_VPN_LABEL, 1, mpls_ff_gid,
          set_tc=7, set_ttl=250, push_l2_header=True, push_vlan=True, push_mpls_header=True, push_cw=True, set_mpls_label=mpls_label)
        #add VPLS provider port
        provider_gid, provider_msg=add_mpls_vpls_port_group(self.controller, mpls_vpn_gid, tunnel_id, provider_mpls_l2_port, 0x9C000001)
        #add vlan flow
        add_vlan_table_flow_xlate(self.controller, [in_port], inport_vlan_id, 0, ovid, VLAN_TABLE_FLAG_XLATE_DOUBLE_TO_SINGLE, True)
        #add vlan1 flow
        add_vlan1_table_flow(self.controller, [in_port], inport_vlan_id, ovid, 4, False, 0, customer_mpls_l2_port, tunnel_id, VLAN1_TABLE_FLAG_MPLS, True)
        #add bridge flow
        add_overlay_bridge_flow(self.controller, dst_mac, tunnel_id, provider_gid, True, True)

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 06 '
                '81 00 00 03 08 00 45 00 00 2a 04 d2 00 00 7f 00 '
                'b2 4b c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00')

        output_pkt = simple_packet(
                '00 00 04 22 44 61 00 00 04 22 33 51 81 00 00 02 '
                '88 47 00 93 1e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 04 08 00 '
                '45 00 00 2a 04 d2 00 00 7f 00 b2 4b c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt2 = simple_packet(
                '00 00 04 22 44 65 00 00 04 22 33 55 81 00 00 02 '
                '88 47 00 93 5e fa 00 90 1f fa 00 00 00 00 00 00 '
                '00 11 33 55 00 00 00 11 22 33 81 00 00 04 08 00 '
                '45 00 00 2a 04 d2 00 00 7f 00 b2 4b c0 a8 01 64 '
                'c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(in_port, str(input_pkt))
        verify_packet(self, str(output_pkt), out_port1)
        print 'ff1 done'
        #if output_port link down
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x1,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x1, mask=0x1)
        self.controller.message_send(request)

        time.sleep(5)
        self.dataplane.send(in_port, str(input_pkt))

        #recover output_port link status, before assert check
        #apply_dpctl_mod(self, config, "port-mod port="+str(out_port1)+",conf=0x0,mask=0x1")
        request = ofp.message.port_mod(port_no=out_port1, config=0x0, mask=0x1)
        self.controller.message_send(request)
        time.sleep(3)
        #check if output_port2 receives packet
        verify_packet(self, str(output_pkt2), out_port2)

