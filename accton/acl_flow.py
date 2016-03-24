import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *


class NoVlanOnlyAclOutputPort(base_tests.SimpleDataPlane):
    """
    In OFDPA, ACL can save the packet it was dropped vlan table
    """
    def runTest(self):
        ports = sorted(config["port_map"].keys())
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
        input_port=ports[0]
        output_port=ports[1]
        vlan_id = 10
        dmac = [0x00, 0x12, 0x34, 0x56, 0x78, 0x9a]
        gid, req_msg = add_one_l2_interface_group(self.controller, port=output_port, vlan_id=vlan_id, is_tagged=True, send_barrier=False)
        #add ACL flow to output port
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(input_port))
        match.oxm_list.append(ofp.oxm.eth_dst(dmac))
        match.oxm_list.append(ofp.oxm.vlan_vid(0x1000+vlan_id))
        request = ofp.message.flow_add(
            table_id=60,
            cookie=42,
            match=match,
            instructions=[
                ofp.instruction.write_actions(
                    actions=[
                        ofp.action.group(gid)]
                    )
            ],
            priority=1)
        #install flow
        self.controller.message_send(request)        

        dmac_str = convertMACtoStr(dmac)
        #send packet
        parsed_pkt = simple_tcp_packet(eth_dst=dmac_str, vlan_vid=vlan_id, dl_vlan_enable=True)
        self.dataplane.send(input_port, str(parsed_pkt))
        #verify packet
        verify_packet(self, str(parsed_pkt), output_port)        


class VlanPcpMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 vlan_vid=2,vlan_pcp=4/4,eth_type=0x0800 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.vlan_vid(out_vlan))
        match.oxm_list.append(ofp.oxm.vlan_pcp_masked(4, 4))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (vlan_pcp = 3)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       vlan_pcp=3,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (vlan_pcp = 6)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       vlan_pcp=6,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class IpDscpMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 ip_dscp=84/84,eth_type=0x0800 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_dscp_masked(40, 40))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (ip_dscp = 34)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       ip_tos=136,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (ip_dscp = 42)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       ip_tos=168,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class TcpSrcMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 tcp_src=15/12,eth_type=0x0800,ip_proto=6 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(6))
        match.oxm_list.append(ofp.oxm.tcp_src_masked(15, 12))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (tcp_src = 68)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_sport=3,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (tcp_src = 92)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_sport=13,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class TcpDstMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 tcp_dst=10/10,eth_type=0x0800,ip_proto=6 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(6))
        match.oxm_list.append(ofp.oxm.tcp_dst_masked(10, 10))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (tcp_dst = 68)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_dport=6,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (tcp_dst = 92)
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       tcp_dport=14,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class UdpSrcMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 udp_src=13183/13183,eth_type=0x0800,ip_proto=17 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(17))
        match.oxm_list.append(ofp.oxm.udp_src_masked(13183, 13183))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (udp_src = 18132)
        parsed_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_sport=18132,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (udp_src = 15231)
        parsed_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_sport=15231,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class UdpDstMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 udp_dst=2429/2429,eth_type=0x0800,ip_proto=17 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(17))
        match.oxm_list.append(ofp.oxm.udp_dst_masked(2429, 2429))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (udp_dst = 2421)
        parsed_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_dport=2421,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (udp_dst = 2941)
        parsed_pkt = simple_udp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       udp_dport=2941,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class SctpSrcMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 sctp_src=132/132,eth_type=0x0800,ip_proto=132 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(132))
        match.oxm_list.append(ofp.oxm.sctp_src_masked(132, 132))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (sctp_src = 136)
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 88 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (sctp_src = 148)
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 94 00 50 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class SctpDstMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 sctp_dst=68/196,eth_type=0x0800,ip_proto=132 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(132))
        match.oxm_list.append(ofp.oxm.sctp_dst_masked(68, 196))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (sctp_dst = 196)
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 88 00 c4 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (sctp_dst = 84)
        parsed_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 02 '
                '08 00 45 a8 00 52 00 01 00 00 40 84 ef a0 c0 a8 '
                '05 0a c0 a8 04 02 00 88 00 54 00 00 00 00 00 00 '
                '00 00 50 02 20 00 66 a0 00 00 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 '
                '44 44 44 44')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class IcmpTypeMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 icmp_type=115/115,eth_type=0x0800,ip_proto=1 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(1))
        match.oxm_list.append(ofp.oxm.icmpv4_type_masked(115, 115))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (icmp_type = 83)
        parsed_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_type=83,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (icmp_type = 119)
        parsed_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_type=119,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)


class IcmpCodeMask(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x20001 group=any,port=any,weight=0 output=1
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]
        out_vlan=2
        group_id, msg = add_one_l2_interface_group(self.controller, out_port, out_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1002/0x1fff goto:20
        msg2= add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 icmp_code=125/125,eth_type=0x0800,ip_proto=1 write:group=0x20001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.ip_proto(1))
        match.oxm_list.append(ofp.oxm.icmpv4_code_masked(125, 125))
        match.oxm_list.append(ofp.oxm.eth_type(0x800))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=601,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input non-matched packet (icmp_code = 93)
        parsed_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_code=93,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_no_packet(self, str(parsed_pkt), out_port)

        #input matched packet (icmp_code = 253)
        parsed_pkt = simple_icmp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2',
                                       icmp_code=253,
                                       vlan_vid=2,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, str(parsed_pkt), out_port)
