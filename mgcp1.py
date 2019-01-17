from scapy.all import *
import re

def str_is_a_decimal_digit(string):
    return re.match("^[0-9]$", string) != None

#our packet callback
def packet_callback(packet):
    #print packet.show()

    if packet[UDP].payload:
        udp = packet[UDP]

	mgcp_payload = str(udp.payload)

        if "rqnt" in mgcp_payload:
            if "S:" in mgcp_payload:
                str2 = "S:"
                index2 = mgcp_payload.index(str2)

                str3 = "Q:"
                index3 = mgcp_payload.index(str3)
                s_string = mgcp_payload[index2:index3]

                str4 = ",U/dt(0,3,0,"
                if str4 in s_string:
                    index4 = s_string.index(str4)
                    #print s_string
		    slice_index = index4 + 13
                    new_str =  s_string[slice_index:]
                    my_str = ""
                    for blah in new_str:
                        if blah != ")":
                            my_str += blah
                        else:
			    break
                    my_str2 = my_str[:-1] 

                    if my_str2 == "Off Hook":
                        print "MGCP Messaging start\n%s --> %s" % (packet[0][1].src, packet[0][1].dst)
                        print "User went Off Hook"
                    elif my_str2 == "Dialing:":
                        print "User started dialing"
                    elif str_is_a_decimal_digit(my_str2):
                        print "User has dialed:  %s" % my_str2
                    elif my_str2 == "Park":
                        print "Phone Status is now 'Park' ~ User is on the phone"
                    elif my_str2 == "Standard":
                        print "Phone Status is now 'Standard' ~ User has hung up"
                    else:
                        print my_str2
                        #print "%s" % new_str 
	elif "NTFY" in mgcp_payload:
            if "O:" in mgcp_payload:
                index2 = mgcp_payload.index("O:")
                my_str = mgcp_payload[index2:]
                if "u/ku(" in my_str:
                    index3 = my_str.index("u/ku(")
                    my_str2 = my_str[index3+5:]
                    my_str3 = my_str2[:1]
                    print "Voice Mail Login:  User dialed %s" % my_str3
        else:
            pass
             

sniff(filter="udp port 2427",prn=packet_callback,store=0)
