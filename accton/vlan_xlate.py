"""
VLAN Translate Flow Test

Test each flow table can set entry, and packet rx correctly.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class single_swap(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=3
        new_vlan=5
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
        #add vlan flow
        add_vlan_table_flow_xlate(self.controller, [in_port], vlan_id=vlan_id, set_vid=new_vlan, flag=VLAN_TABLE_FLAG_XLATE_SINGLE, send_barrier=True)
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, new_vlan, True, False)
        #add termination flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #add reverse flow
        #group_id, msg=add_one_l2_interface_group(self.controller, in_port, vlan_id, True, False)
        #add_bridge_flow(self.controller, src_mac, in_port, group_id, True)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=5,
                                       dl_vlan_enable=True)
        verify_packet(self, str(parsed_pkt), out_port)


class single_to_double(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=3
        outer_vlan=5
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
        #add vlan flow
        add_vlan_table_flow_xlate(self.controller, [in_port], vlan_id=vlan_id, set_vid=outer_vlan, flag=VLAN_TABLE_FLAG_XLATE_SINGLE_TO_DOUBLE, send_barrier=False)
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, outer_vlan, True, False)
        #add termination flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=3)
        verify_packet(self, str(parsed_pkt), out_port)


class double_to_single(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=3
        ovid=5
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
        #add vlan flow
        add_vlan_table_flow_xlate(self.controller, [in_port], vlan_id=ovid, set_ovid=ovid, flag=VLAN_TABLE_FLAG_XLATE_DOUBLE_TO_SINGLE, send_barrier=True)
        #add vlan1 flow
        add_vlan1_table_flow(self.controller, [in_port], vlan_id=vlan_id, ovid=ovid, flag=VLAN1_TABLE_FLAG_BYPASS, send_barrier=True)
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add termination flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=3)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       dl_vlan_enable=True,
                                       vlan_vid=3)
        verify_packet(self, str(parsed_pkt), out_port)


class double_to_single_swap(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=3
        ovid=5
        new_vid=6
        dst_mac=[0x00, 0x00, 0x00, 0x11, 0x33, 0x55]
        src_mac=[0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
        #add vlan flow
        add_vlan_table_flow_xlate(self.controller, [in_port], vlan_id=ovid, set_ovid=ovid, flag=VLAN_TABLE_FLAG_XLATE_DOUBLE_TO_SINGLE, send_barrier=True)
        #add vlan1 flow
        add_vlan1_table_flow(self.controller, [in_port], vlan_id=vlan_id, ovid=ovid, set_vid=new_vid, flag=VLAN1_TABLE_FLAG_ASSIGN, send_barrier=True)
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, new_vid, True, False)
        #add termination flow
        add_termination_flow(self.controller, in_port, 0x800, dst_mac, vlan_id)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=3)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       dl_vlan_enable=True,
                                       vlan_vid=6)
        verify_packet(self, str(parsed_pkt), out_port)


class egress_vlan_swap(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=200
        new_vid=3
        dst_mac=[0x00, 0x00, 0x00, 0x00, 0x02, 0x00]
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add egress vlan flow
        add_egress_vlan_flow(self.controller, out_port, vlan_id, new_vid, EGRESS_VLAN_TABLE_FLAG_SWAP)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=200,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)
        verify_packet(self, str(parsed_pkt), out_port)


class egress_vlan_single2double(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=200
        outer_vid=5
        dst_mac=[0x00, 0x00, 0x00, 0x00, 0x02, 0x00]
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, vlan_id, True, False)
        #add vlan flow
        add_vlan_table_flow(self.controller, [in_port], vlan_id, VLAN_TABLE_FLAG_ONLY_TAG, True)
        #add egress vlan flow
        add_egress_vlan_flow(self.controller, out_port, vlan_id, outer_vid, EGRESS_VLAN_TABLE_FLAG_SINGLE_TO_DOUBLE)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=200,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        verify_packet(self, str(parsed_pkt), out_port)


class egress_vlan_double2single(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=200
        ovid=5
        dst_mac=[0x00, 0x00, 0x00, 0x00, 0x02, 0x00]
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, ovid, True, False)
        #add vlan flow
        add_vlan_table_flow_allow_all_vlan(self.controller, in_port, True)
        #add egress vlan flow
        add_egress_vlan_flow(self.controller, out_port, vlan_id, ovid, EGRESS_VLAN_TABLE_FLAG_DOUBLE_TO_SINGLE)
        #add egress vlan1 flow
        add_egress_vlan1_flow(self.controller, out_port, vlan_id, ovid, 0, flag=EGRESS_VLAN1_TABLE_FLAG_DOUBLE_TO_SINGLE)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=200,
                                       dl_vlan_enable=True)
        verify_packet(self, str(parsed_pkt), out_port)


class egress_vlan_double2single_swap(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=200
        ovid=5
        set_vid=3
        dst_mac=[0x00, 0x00, 0x00, 0x00, 0x02, 0x00]
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, ovid, True, False)
        #add vlan flow
        add_vlan_table_flow_allow_all_vlan(self.controller, in_port, True)
        #add egress vlan flow
        add_egress_vlan_flow(self.controller, out_port, vlan_id, ovid, EGRESS_VLAN_TABLE_FLAG_DOUBLE_TO_SINGLE)
        #add egress vlan1 flow
        add_egress_vlan1_flow(self.controller, out_port, vlan_id, ovid, set_vid, EGRESS_VLAN1_TABLE_FLAG_DOUBLE_TO_SINGLE_SWAP)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)
        verify_packet(self, str(parsed_pkt), out_port)


class egress_vlan_swap_outer(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        vlan_id=200
        ovid=5
        set_vid=3
        dst_mac=[0x00, 0x00, 0x00, 0x00, 0x02, 0x00]
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, ovid, True, False)
        #add vlan flow
        add_vlan_table_flow_allow_all_vlan(self.controller, in_port, True)
        #add egress vlan flow
        add_egress_vlan_flow(self.controller, out_port, vlan_id, ovid, EGRESS_VLAN_TABLE_FLAG_DOUBLE_TO_SINGLE)
        #add egress vlan1 flow
        add_egress_vlan1_flow(self.controller, out_port, vlan_id, ovid, set_vid, EGRESS_VLAN1_TABLE_FLAG_SWAP_OUTER_VLAN)
        #add acl
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        match.oxm_list.append(ofp.oxm.eth_dst(dst_mac))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input packet
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=3,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        verify_packet(self, str(parsed_pkt), out_port)


