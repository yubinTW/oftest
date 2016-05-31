import logging
import oftest.base_tests as base_tests
from oftest import config
from oftest.testutils import *
from util import *
from accton_util import convertIP4toStr as toIpV4Str
from accton_util import convertMACtoStr as toMacStr


class single_tag_to_double_tag(base_tests.SimpleDataPlane):
    """																					 
	[Single tag to double tag]																				
		Add a specified outer tag to incoming tagged packet																			
																					
	Inject	eth 1/3	Tag 3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Outter Tag 5, inner Tag 3, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:push_vlan=0x8100,set_field=vlan_vid=5 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x50001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60																				
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:push_vlan=0x8100,set_field=vlan_vid=5 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x5000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x5000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(input_port)+" group=any,port=any,weight=0 pop_vlan,output="+str(input_port))
        apply_dpctl_mod(self, config, " flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x3000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '81 00 00 03 08 00 45 00 00 2e 04 d2 00 00 7f 00 '
                'b2 47 c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00')
        
        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
        
        
        

class double_tag_to_single_tag(base_tests.SimpleDataPlane):
    """																					 
	[Double tag to single tag]																				
		Pop outter tag of incoming double tagged packet																			
																					
	Inject	eth 1/3	Outer 0x8100 + 6, Inner 0x8100 +3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Tag 3, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=11,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x30001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x60003 goto:60																				
																				
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11")
        apply_dpctl_mod(self, config, "flow-mod table=11,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")        
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x3000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x6000"+str(input_port)+" group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x6000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 06 '
                '81 00 00 03 08 00 45 00 00 2a 04 d2 00 00 7f 00 '
                'b2 4b c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2a 04 d2 00 00 7f 00 b2 4b c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
                
        


class double2single_vlan_translate(base_tests.SimpleDataPlane):
    """																					 
	[Double tag to single tag and modify inner tag]																				
		Pop outter tag of incoming double tagged packet and modify inner tag																			
																					
	Inject	eth 1/3	Outer 0x8100 + 6, Inner 0x8100 +3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Tag 4, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=11,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 apply:set_field=vlan_vid=4 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x40001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x40001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x60003 goto:60																				
															
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1006/0x1fff apply:pop_vlan,set_field=ofdpa_ovid:6 goto:11")
        apply_dpctl_mod(self, config, "flow-mod table=11,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff,ofdpa_ovid=0x1006 apply:set_field=vlan_vid=4 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=6/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")        
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x4000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x4000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x60003 group=any,port=any,weight=0 output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=6,eth_dst=00:00:00:11:22:33 write:group=0x6000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 06 '
                '81 00 00 03 08 00 45 00 00 2a 04 d2 00 00 7f 00 '
                'b2 4b c0 a8 01 64 c0 a8 02 02 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 04 '
                '08 00 45 00 00 2a 04 d2 00 00 7f 00 b2 4b c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)   



class vlan_translate(base_tests.SimpleDataPlane):
    """																					 
	[VLAN tanslate]																				
		Swap incoming tagged packet to a specified VLAN tag																			
																					
	Inject	eth 1/3	Tag 3, SA000000112233, DA000000113355, V4																		
	Output	eth 1/1	Tag 5, others not change																		
																					
	dpctl tcp:192.168.1.1:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1003/0x1fff apply:set_field=vlan_vid=5 goto:20																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=20,cmd=add,prio=201 in_port=3,vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port=3 write:group=0x50001																				
	dpctl tcp:192.168.1.1:6633 group-mod cmd=add,type=ind,group=0x30003 group=any,port=any,weight=0 pop_vlan,output=3																				
	dpctl tcp:192.168.1.1:6633 flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x30003 goto:60																				
																		
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)    
		
        test_ports = sorted(config["port_map"].keys())	
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1003/0x1fff apply:set_field=vlan_vid=5 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=20,cmd=add,prio=201 in_port="+str(input_port)+",vlan_vid=3/0xfff,eth_dst=00:00:00:11:33:55,eth_type=0x0800 goto:30")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x5000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_type=0x0800,in_port="+str(input_port)+" write:group=0x5000"+str(output_port))
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x3000"+str(input_port)+" group=any,port=any,weight=0 pop_vlan,output="+str(input_port))
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 vlan_vid=3,eth_dst=00:00:00:11:22:33 write:group=0x3000"+str(input_port)+" goto:60")

        input_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 03 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        output_pkt = simple_packet(
                '00 00 00 11 33 55 00 00 00 11 22 33 81 00 00 05 '
                '08 00 45 00 00 2e 04 d2 00 00 7f 00 b2 47 c0 a8 '
                '01 64 c0 a8 02 02 00 00 00 00 00 00 00 00 00 00 '
                '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)        


class egress_vlan_swap(base_tests.SimpleDataPlane):
    """
    [egress vlan swap]
        xlate packet's tag

    Inject  eth 1/3 Tag 200, SA000000000201, DA000000000200
    Output  eth 1/1 Tag 3, SA 000000000201, DA 000000000200

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xc80001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0xc80001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output=1,vlan_vid=200 apply:set_field=vlan_vid=3

    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xc8000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x10c8/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0xc8000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output="+str(output_port)+",vlan_vid=200 apply:set_field=vlan_vid=3")

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=200,
                                       dl_vlan_enable=True)
        output_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class egress_vlan_single2double(base_tests.SimpleDataPlane):
    """
    [egress vlan single to double]
        add outer tag

    Inject  eth 1/3 Tag 200, SA000000000201, DA000000000200
    Output  eth 1/1 outer tag 5, inner tag 200, SA 000000000201, DA 000000000200

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xc80001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x10c8/0x1fff goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0xc80001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output=1,vlan_vid=200 apply:push_vlan=0x8100,set_field=vlan_vid=5

    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xc8000"+str(output_port)+" group=any,port=any,weight=0 pop_vlan,output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x10c8/0x1fff goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0xc8000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output="+str(output_port)+",vlan_vid=200 apply:push_vlan=0x8100,set_field=vlan_vid=5")

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=200,
                                       dl_vlan_enable=True)
        output_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class egress_vlan_double2single(base_tests.SimpleDataPlane):
    """
    [egress vlan double to single]
        pop outer tag

    Inject  eth 1/3 outer tag 5, inner tag 200, SA000000000201, DA000000000200
    Output  eth 1/1 tag 200, SA 000000000201, DA 000000000200

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1000/0x1000 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0x50001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output=1,vlan_vid=200 apply:pop_vlan,set_field=ofdpa_ovid:5 goto:211
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=211,cmd=add,prio=211 ofdpa_actset_output=1,ofdpa_ovid=5,vlan_vid=200 apply:pop_vlan

    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x5000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0x1000 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0x5000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output="+str(output_port)+",vlan_vid=200 apply:pop_vlan,set_field=ofdpa_ovid:5 goto:211")
        apply_dpctl_mod(self, config, "flow-mod table=211,cmd=add,prio=211 ofdpa_actset_output="+str(output_port)+",ofdpa_ovid=5,vlan_vid=200 apply:pop_vlan")

        input_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        output_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=200,
                                       dl_vlan_enable=True)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class egress_vlan_double2single_swap(base_tests.SimpleDataPlane):
    """
    [egress vlan double to single and swap]
        pop outer tag and swap inner tag

    Inject  eth 1/3 outer tag 5, inner tag 200, SA000000000201, DA000000000200
    Output  eth 1/1 tag 3, SA 000000000201, DA 000000000200

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1000/0x1000 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0x50001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output=1,vlan_vid=200 apply:pop_vlan,set_field=ofdpa_ovid:5 goto:211
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=211,cmd=add,prio=211 ofdpa_actset_output=1,ofdpa_ovid=5,vlan_vid=200 apply:set_field=vlan_vid=3

    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x5000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0x1000 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0x5000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output="+str(output_port)+",vlan_vid=200 apply:pop_vlan,set_field=ofdpa_ovid:5 goto:211")
        apply_dpctl_mod(self, config, "flow-mod table=211,cmd=add,prio=211 ofdpa_actset_output="+str(output_port)+",ofdpa_ovid=5,vlan_vid=200 apply:set_field=vlan_vid=3")

        input_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        output_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=3,
                                       dl_vlan_enable=True)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class egress_vlan_swap_outer(base_tests.SimpleDataPlane):
    """
    [egress vlan swap outer]
        swap outer tag

    Inject  eth 1/3 outer tag 5, inner tag 200, SA 000000000201, DA 000000000200
    Output  eth 1/1 outer tag 3, inner tag 200, SA 000000000201, DA 000000000200

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0x50001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1000/0x1000 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0x50001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output=1,vlan_vid=200 apply:pop_vlan,set_field=ofdpa_ovid:5 goto:211
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=211,cmd=add,prio=211 ofdpa_actset_output=1,ofdpa_ovid=5,vlan_vid=200 apply:push_vlan=0x8100,set_field=vlan_vid=3

    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0x5000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0x1000 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=60,cmd=add,prio=601 eth_dst=00:00:00:00:02:00,eth_type=0x800 write:group=0x5000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output="+str(output_port)+",vlan_vid=200 apply:pop_vlan,set_field=ofdpa_ovid:5 goto:211")
        apply_dpctl_mod(self, config, "flow-mod table=211,cmd=add,prio=211 ofdpa_actset_output="+str(output_port)+",ofdpa_ovid=5,vlan_vid=200 apply:push_vlan=0x8100,set_field=vlan_vid=3")

        input_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)
        output_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=3,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=200)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)


class egress_vlan_add_and_swap_inner(base_tests.SimpleDataPlane):
    """
    [egress vlan add and swap inner]
        add outer tag and swap inner tag

    Inject  eth 1/3 tag 5, SA 000000000201, DA 000000000200
    Output  eth 1/1 outer tag 5, inner tag 3, SA 000000000201, DA 000000000200

    ./dpctl tcp:0.0.0.0:6633 group-mod cmd=add,type=ind,group=0xb0000001 group=any,port=any,weight=0 output=1
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=10,cmd=add,prio=101 in_port=3,vlan_vid=0x1000/0x1000 goto:20
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=50,cmd=add,prio=501 eth_dst=00:00:00:00:02:00,vlan_vid=5 write:group=0xb0000001
    ./dpctl tcp:0.0.0.0:6633 flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output=1,vlan_vid=5 apply:set_field=vlan_vid=3,push_vlan=0x8100,,set_field=vlan_vid=5
    """
    def runTest(self):
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)

        test_ports = sorted(config["port_map"].keys())
        input_port = test_ports[0]
        output_port = test_ports[1]

        apply_dpctl_mod(self, config, "meter-mod cmd=del,meter=0xffffffff")
        apply_dpctl_mod(self, config, "group-mod cmd=add,type=ind,group=0xb000000"+str(output_port)+" group=any,port=any,weight=0 output="+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=10,cmd=add,prio=101 in_port="+str(input_port)+",vlan_vid=0x1000/0x1000 goto:20")
        apply_dpctl_mod(self, config, "flow-mod table=50,cmd=add,prio=501 eth_dst=00:00:00:00:02:00,vlan_vid=5 goto:60 write:group=0xb000000"+str(output_port))
        apply_dpctl_mod(self, config, "flow-mod table=210,cmd=add,prio=210 ofdpa_actset_output="+str(output_port)+",vlan_vid=5 apply:set_field=vlan_vid=3,push_vlan=0x8100,,set_field=vlan_vid=5")

        input_pkt = simple_tcp_packet(pktlen=100,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       vlan_vid=5,
                                       dl_vlan_enable=True)
        output_pkt = simple_tcp_packet_two_vlan(pktlen=104,
                                       eth_dst='00:00:00:00:02:00',
                                       eth_src='00:00:00:00:02:01',
                                       ip_src='192.168.5.10',
                                       ip_dst='192.168.3.2',
                                       ip_ttl=64,
                                       out_dl_vlan_enable=True,
                                       out_vlan_vid=5,
                                       in_dl_vlan_enable=True,
                                       in_vlan_vid=3)

        self.dataplane.send(input_port, str(input_pkt))
        verify_packet(self, str(output_pkt), output_port)
