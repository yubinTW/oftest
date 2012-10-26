"""These tests fall under Conformance Test-Suite (OF-SWITCH-1.0.0 TestCases).
    Refer Documentation -- Detailed testing methodology 
    <Some of test-cases are directly taken from oftest> """

"Test Suite 6 --> Flow Matches"


import logging

import unittest
import random

import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.parse as parse
import oftest.base_tests as base_tests
import time

from oftest.testutils import *
from time import sleep
from FuncUtils import *

    

class AllWildcardMatch(base_tests.SimpleDataPlane):

    """Verify for an all wildcarded flow all the injected packets would match that flow"""

    def runTest(self):
        
        logging.info("Running All Wildcard Match test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting an all wildcarded flow and sending packets with various match fields")
        logging.info("Expecting all sent packets to match")

        #Insert an All Wildcarded flow.
        Wildcard_All(self,of_ports)

        #check for different  match fields and verify packet implements the action specified in the flow
        pkt1 = simple_tcp_packet(dl_src="00:01:01:01:01:01");
        self.dataplane.send(of_ports[0], str(pkt1))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt1,[yes_ports],no_ports,self)

        pkt2 = simple_tcp_packet(dl_dst="00:01:01:01:01:01");    
        self.dataplane.send(of_ports[0], str(pkt2))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt2,[yes_ports],no_ports,self)
        
        pkt3 = simple_tcp_packet(ip_src="192.168.2.1");
        self.dataplane.send(of_ports[0], str(pkt3))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt3,[yes_ports],no_ports,self)

        pkt4 = simple_tcp_packet(ip_dst="192.168.2.2");
        self.dataplane.send(of_ports[0], str(pkt4))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt4,[yes_ports],no_ports,self)

        pkt5 = simple_tcp_packet(ip_tos=2);
        self.dataplane.send(of_ports[0], str(pkt5))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt5,[yes_ports],no_ports,self)

        pkt6 = simple_tcp_packet(tcp_sport=8080);
        self.dataplane.send(of_ports[0], str(pkt6))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt6,[yes_ports],no_ports,self)
                  
        pkt7 = simple_tcp_packet(tcp_dport=8081);
        self.dataplane.send(of_ports[0], str(pkt7))
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt7,[yes_ports],no_ports,self)



class EthernetSrcAddress(base_tests.SimpleDataPlane):
    
    """Verify match on single header field -- Ethernet Src Address """
    
    def runTest(self):

        logging.info("Running Ethernet Src Address test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Ethernet Source Address ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        #Insert a Match On Ethernet Src Address flow
        (pkt,match) = Match_Ethernet_Src_Address(self,of_ports)   

        #Sending packet matching the flow, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(dl_src='00:01:01:01:01:02');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")

class EthernetDstAddress(base_tests.SimpleDataPlane):
    
    """Verify match on single Header Field Field -- Ethernet Dst Address """

    def runTest(self):

        logging.info("Running Ethernet Dst Address test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
        
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Ethernet Destination Address ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")
        
        #Insert a Match on Destination Address flow   
        (pkt,match) = Match_Ethernet_Dst_Address(self,of_ports)
        
        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send Non-matching packet
        pkt2 = simple_tcp_packet(dl_dst='00:01:01:01:01:02');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #Verify PacketIn event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")


class EthernetType(base_tests.SimpleDataPlane):
    
    """Verify match on single header field -- Ethernet Type """
    
    def runTest(self):

        logging.info("Running Ethernet Type test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Ethernet Type ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        #Insert a Match on Ethernet Type flow
        (pkt,match) = Match_Ethernet_Type(self,of_ports)   

        #Sending packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , 
        pkt2 = simple_eth_packet(dl_type=0x0806);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #verify Packetin event gets triggered.
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")

            
class IngressPort(base_tests.SimpleDataPlane):
    
    """Verify match on single Header Field Field -- In_port """

    def runTest(self):

        logging.info("Running Ingress Port test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Ingress Port ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")
        
        #Insert a Match on Ingress Port FLow
        (pkt,match) = Wildcard_All_Except_Ingress(self,of_ports,priority=0)
        
        #Send Packet matching the flow i.e on in_port specified in the flow
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Send Non-Matching Packet 
        self.dataplane.send(of_ports[1],str(pkt))

        #Verify PacketIn event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")

class VlanId(base_tests.SimpleDataPlane):

    """Verify match on single Header Field Field -- Vlan Id """

    def runTest(self):

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on VLAN ID ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")
    
        #Create a flow with match on Vlan Id
        (pkt,match) = Match_Vlan_Id(self,of_ports)

        #Send tagged packet matching the flow i.e packet with same vlan id as in flow
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send Non-matching packet, i.e packet with different Vlan Id
        pkt2 = simple_tcp_packet(dl_vlan_enable=True,dl_vlan=4);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        #Verify PacketIn event gets triggered
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")

class VlanPCP(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- Vlan Priority"""

    def runTest(self):

        logging.info("Running VlanPCP1 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        logging.info("Inserting a flow with match on VLAN Priority ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        #Create a flow matching on VLAN Priority
        (pkt,match) = Match_Vlan_Pcp(self,of_ports)

        #Send tagged Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Send tagged packet with same vlan_id but different vlan priority
        pkt2 = simple_tcp_packet(dl_vlan_enable=True,dl_vlan=1,dl_vlan_pcp=20);
        self.dataplane.send(in_port, str(pkt))
       
class MultipleHeaderFieldL2(base_tests.SimpleDataPlane):
    
    """Verify match on multiple header field -- Ethernet Type, Ethernet Source Address, Ethernet Destination Address """
    
    def runTest(self):

        logging.info("Running Multiple Header Field L2 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Multiple Header Field L2 ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = Match_Mul_L2(self,of_ports)   

        #Send eth packet matching the dl_type field, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_eth_packet(dl_type=0x0806,dl_src='00:01:01:01:01:02',dl_dst='00:01:01:01:01:01');
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")

class IpTos(base_tests.SimpleDataPlane):

    """"Verify match on single Header Field Field -- Type of service"""

    def runTest(self):

        logging.info("Running Ip_Tos test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        logging.info("Inserting a flow with match on Ip_Tos ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        #Create a flow matching on VLAN Priority
        (pkt,match) = Match_Ip_Tos(self,of_ports)

        #Send Packet matching the flow 
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)
        
        #Create a non-matching packet , verify packet_in get generated
        pkt2 = simple_tcp_packet(ip_tos=20);
        self.dataplane.send(of_ports[0], str(pkt2))
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")


class TcpSourcePort(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field -- Tcp Source Port,  """
    
    def runTest(self):

        logging.info("Running Tcp Source Port test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Tcp Tcp Source Port ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = Match_Tcp_Src(self,of_ports)   

        #Sending packet matching the tcp_sport, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=540);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")

class TcpDstPort(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field -- Tcp Destination Port """
    
    def runTest(self):

        logging.info("Running Tcp Destination Port test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Tcp Destination Port ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = Match_Tcp_Dst(self,of_ports)   

        #Sending packet matching the tcp_dport, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_dport=541);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=10)
        self.assertTrue(response is not None, "PacketIn not received")


class ExactMatch(base_tests.SimpleDataPlane):
    
    """Verify match on Single header field -- Exact Match  """
    
    def runTest(self):

        logging.info("Running Tcp Exact Match test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match for Exact Match ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = Exact_Match(self,of_ports)   

        #Sending packet matching all the fields of a tcp_packet, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=540);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")


class MultipleHeaderFieldL4(base_tests.SimpleDataPlane):
    
    """Verify match on multiple header field -- Tcp Source Port, Tcp Destination Port  """
    
    def runTest(self):

        logging.info("Running Multiple Header Field L4 test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with match on Multiple Header Field L4 ")
        logging.info("Sending matching and non-matching packets")
        logging.info("Verifying matching packets implements the action specified in the flow")

        (pkt,match) = Match_Mul_L4(self,of_ports)   

        #Sending packet matching the tcp_sport and tcp_dport field, verify it implements the action
        self.dataplane.send(of_ports[0], str(pkt))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)

        #Sending non matching packet , verify Packetin event gets triggered.
        pkt2 = simple_tcp_packet(tcp_sport=540,tcp_dport=541);
        self.dataplane.send(of_ports[0], str(pkt2))
        
        (response, raw) = self.controller.poll(ofp.OFPT_PACKET_IN,timeout=4)
        self.assertTrue(response is not None, "PacketIn not received")



class ExactMatchHigh(base_tests.SimpleDataPlane):
    
    """Verify that Exact Match has highest priority """
    
    def runTest(self):

        logging.info("Running Exact Match High Priority test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting a flow with Exact Match (low priority)")
        logging.info("Inserting a overlapping wildcarded flow (higher priority)")
        logging.info("Sending packets matching both the flows ")
        logging.info("Verifying matching packets implements the action specified in the exact match flow")

        #Insert two Overlapping Flows : Exact Match and Wildcard All.
        (pkt,match) = Exact_Match_With_Prio(self,of_ports,priority=10) 
        (pkt2,match2) = Wildcard_All(self,of_ports,priority=20);  
        
        #Sending packet matching the both the flows , verify it implements the action specified in Exact Match Flow
        self.dataplane.send(of_ports[0], str(pkt2))

        #Verify packet implements the action specified in the flow
        egress_port=of_ports[2]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = egress_port
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)


class WildcardMatchHigh(base_tests.SimpleDataPlane):
    
    """Verify that Wildcard Match with highest priority overrides the low priority WildcardMatch """
    
    def runTest(self):

        logging.info("Running Wildcard Match High Priority test")

        of_ports = config["port_map"].keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    
        #Clear Switch State
        rc = delete_all_flows(self.controller)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        logging.info("Inserting two wildcarded flows with priorities ")
        logging.info("Sending packets matching the flows")
        logging.info("Verifying matching packets implements the action specified in the flow with higher priority")

        (pkt,match) = Wildcard_All(self,of_ports,priority=20) 
        (pkt1,match1) =  Wildcard_All_Except_Ingress1(self,of_ports,priority=10)  

        #Sending packet matching both the flows , verify it implements the action specified by Higher Priority flow
        self.dataplane.send(of_ports[0], str(pkt1))

        egress_port=of_ports[1]
        no_ports=set(of_ports).difference([egress_port])
        yes_ports = of_ports[1]
        receive_pkt_check(self.dataplane,pkt,[yes_ports],no_ports,self)