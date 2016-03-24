"""
Flow Test

Test each flow table can set entry, and packet rx correctly.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
from oftest.testutils import *
from accton_util import *

class qinq(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)   
        
        in_port = config["port_map"].keys()[0]
        out_port=config["port_map"].keys()[1]        
        out_vlan=10
        add_vlan_table_flow_pvid(self.controller, in_port, None, out_vlan, False)
        add_vlan_table_flow_pvid(self.controller, in_port, 1,out_vlan, False)        
        group_id, msg=add_one_l2_interface_group(self.controller, out_port, out_vlan,  True, False)
        #add acl 
        match = ofp.match()
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
     
        #input untag packet

        parsed_pkt = simple_tcp_packet(pktlen=100)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
    
        parsed_pkt = simple_tcp_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=10)
        verify_packet(self, str(parsed_pkt), out_port)

        #input tag packet
        parsed_pkt = simple_tcp_packet(pktlen=104, dl_vlan_enable=True, vlan_vid=1)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
    
        parsed_pkt = simple_tcp_packet_two_vlan(pktlen=108, out_dl_vlan_enable=True, out_vlan_vid=10,
                                                in_dl_vlan_enable=True, in_vlan_vid=1)
        verify_packet(self, str(parsed_pkt), out_port)


class trunk_combi1(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #if "1@eth1 -i 3@eth2 -i 4@eth4", output should be port 4

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0004 group=any,port=any,weight=0 output=4
        in_port = config["port_map"].keys()[0]
        trunk_port1=config["port_map"].keys()[1]
        trunk_port2=config["port_map"].keys()[2]
        out_vlan=10
        group_id, msg = add_one_l2_interface_group(self.controller, trunk_port1, out_vlan, False, False)
        group_id, msg = add_one_l2_interface_group(self.controller, trunk_port2, out_vlan, False, False)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
        truk_member_list = []
        truk_member_list.append(trunk_port1)
        truk_member_list.append(trunk_port2)
        msg2 = add_trunk_group(self.controller, truk_member_list, 1)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
        msg3 = add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_UNTAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1 write:group=0xF0000001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg2.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input untag packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:33:55',
                                       eth_src='00:00:00:11:22:33',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.4.2')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        verify_packet(self, str(parsed_pkt), trunk_port2)
        verify_no_other_packets(self)


class trunk_combi2(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #if "2@eth1 -i 3@eth2 -i 4@eth4", output should be port 4

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0004 group=any,port=any,weight=0 output=4
        in_port = config["port_map"].keys()[0]
        trunk_port1=config["port_map"].keys()[1]
        trunk_port2=config["port_map"].keys()[2]
        out_vlan=10
        group_id, msg = add_one_l2_interface_group(self.controller, trunk_port1, out_vlan, False, False)
        group_id, msg = add_one_l2_interface_group(self.controller, trunk_port2, out_vlan, False, False)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
        truk_member_list = []
        truk_member_list.append(trunk_port1)
        truk_member_list.append(trunk_port2)
        msg2 = add_trunk_group(self.controller, truk_member_list, 1)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
        msg3 = add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_UNTAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=2 write:group=0xF0000001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg2.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input untag packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        verify_packet(self, str(parsed_pkt), trunk_port2)
        verify_no_other_packets(self)


class trunk_member_out(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0004 group=any,port=any,weight=0 output=4
        in_port = config["port_map"].keys()[0]
        trunk_port1=config["port_map"].keys()[1]
        trunk_port2=config["port_map"].keys()[2]
        out_vlan=10
        group_id, msg1 = add_one_l2_interface_group(self.controller, trunk_port1, out_vlan, False, False)
        group_id, msg2 = add_one_l2_interface_group(self.controller, trunk_port2, out_vlan, False, False)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
        truk_member_list = []
        truk_member_list.append(trunk_port1)
        truk_member_list.append(trunk_port2)
        msg3 = add_trunk_group(self.controller, truk_member_list, 1)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=2,vlan_vid=0x1000/0xfff apply:set_field=vlan_vid=10 goto:20
        msg4 = add_one_vlan_table_flow(self.controller, in_port, out_vlan, flag=VLAN_TABLE_FLAG_ONLY_UNTAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=2 write:group=0xa0004
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg2.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input untag packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10')
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)

        verify_packet(self, str(parsed_pkt), trunk_port2)
        verify_no_other_packets(self)

class trunk_duplicate_member(base_tests.SimpleDataPlane):
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xa0003 group=any,port=any,weight=0 output=3
        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xb0003 group=any,port=any,weight=0 output=3
        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xb0004 group=any,port=any,weight=0 output=4
        in_port = config["port_map"].keys()[0]
        trunk_port1=config["port_map"].keys()[1]
        trunk_port2=config["port_map"].keys()[2]
        t1_vlan=10
        t2_vlan=11
        group_id, msg1 = add_one_l2_interface_group(self.controller, trunk_port1, t1_vlan, True, False)
        group_id, msg2 = add_one_l2_interface_group(self.controller, trunk_port1, t2_vlan, True, False)
        group_id, msg3 = add_one_l2_interface_group(self.controller, trunk_port2, t2_vlan, True, False)

        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000001 group=any,port=any,weight=0 output=3
        #./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=sel,group=0xF0000002 group=any,port=any,weight=0 output=3 group=any,port=any,weight=0 output=4
        t1_member_list = []
        t1_member_list.append(trunk_port1)
        msg4 = add_trunk_group(self.controller, t1_member_list, 1)
        t2_member_list = []
        t2_member_list.append(trunk_port1)
        t2_member_list.append(trunk_port2)
        msg5 = add_trunk_group(self.controller, t2_member_list, 2)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x100a goto:20
        #./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=1,vlan_vid=0x100b goto:20
        msg6 = add_one_vlan_table_flow(self.controller, in_port, t1_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)
        msg7 = add_one_vlan_table_flow(self.controller, in_port, t2_vlan, flag=VLAN_TABLE_FLAG_ONLY_TAG)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1,vlan_vid=10 write:group=0xF0000001
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.vlan_vid(t1_vlan))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg4.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 in_port=1,vlan_vid=11 write:group=0xF0000002
        match = ofp.match()
        match.oxm_list.append(ofp.oxm.in_port(in_port))
        match.oxm_list.append(ofp.oxm.vlan_vid(t2_vlan))
        request = ofp.message.flow_add(
                table_id=60,
                cookie=42,
                match=match,
                instructions=[
                    ofp.instruction.write_actions(
                        actions=[
                            ofp.action.group(msg5.group_id)])
                    ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)

        #input tag10 packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10',
                                       vlan_vid=10,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, trunk_port1)
        verify_no_other_packets(self)

        #input tag11 packet
        parsed_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:11:22:33',
                                       eth_src='00:00:00:11:33:55',
                                       ip_src='192.168.4.2',
                                       ip_dst='192.168.5.10',
                                       vlan_vid=11,
                                       dl_vlan_enable=True)
        pkt = str(parsed_pkt)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, trunk_port2)
        verify_no_other_packets(self)
