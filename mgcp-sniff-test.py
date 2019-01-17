from scapy.all import *
import re
import json, urllib
import mechanize, cookielib, random

class anonBrowser(mechanize.Browser):

    def __init__(self, proxies = [], user_agents = []):
        mechanize.Browser.__init__(self)
        self.set_handle_robots(False)
        self.proxies = proxies
        self.user_agents = user_agents + ['Mozilla/4.0 ',\
        'FireFox/6.01','ExactSearch', 'Nokia7110/1.0']

        self.cookie_jar = cookielib.LWPCookieJar()
        self.set_cookiejar(self.cookie_jar)
        self.anonymize()

    def clear_cookies(self):
        self.cookie_jar = cookielib.LWPCookieJar()
        self.set_cookiejar(self.cookie_jar)

    def change_user_agent(self):
        index = random.randrange(0, len(self.user_agents) )
        self.addheaders = [('User-agent', \
          ( self.user_agents[index] ))]

    def change_proxy(self):
        if self.proxies:
            index = random.randrange(0, len(self.proxies))
            self.set_proxies( {'http': self.proxies[index]} )

    def anonymize(self, sleep = False):
        self.clear_cookies()
        self.change_user_agent()
        self.change_proxy()

        if sleep:
            time.sleep(60)
class Google_Result:
    def __init__(self,title,text,url):
        self.title = title
        self.text = text
        self.url = url
    def __repr__(self):
        return self.title

def google(search_term):
    ab = anonBrowser()
    search_term = urllib.quote_plus(search_term)
    response = ab.open('http://ajax.googleapis.com/'+'ajax/services/search/web?v=1.0&q=' + search_term)
    objects = json.load(response)
    results = []
    for result in objects['responseData']['results']:
        url = result['url']
        title = result['titleNoFormatting']
        text = result['content']
        new_gr = Google_Result(title, text, url)
        results.append(new_gr)
    if not results:
        return "No results"
    else:
        return results 

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

                    if "info" and "HangUp" in s_string:
                        if "Park" not in s_string:
                            my_str = new_str[0:13] 
                            print "[*] Call in Progress:  %s" % my_str
                            area_code = my_str[1:4]
                            npa_nxx1 = my_str[5:8]
                            npa_nxx2 = my_str[9:]
		            query_string1 = "1" + "." + area_code + "." + npa_nxx1 + "." + npa_nxx2 
		            query_string2 = "1" + "-" + area_code + "-" + npa_nxx1 + "-" + npa_nxx2 
		            query_string3 = my_str

                            print "[*] Querying Google for number: %s" % query_string1
                            print google(query_string1)
                            print "[*] Querying Google for number: %s" % query_string2
                            print google(query_string2)
                            print "[*] Querying Google for number: %s" % query_string3
                            print google(query_string3)
		    	else:
			    print s_string

                    elif my_str2 == "Off Hook":
                        print "[*] MGCP Messaging start\n[*] %s --> %s" % (packet[0][1].src, packet[0][1].dst)
                        print "[*] User went Off Hook"
                    elif my_str2 == "Dialing:":
                        print "[*] User started dialing"
                    elif my_str2 == "Park":
                        print "[*] Phone Status is now 'Park' ~ User is on the phone"
                    elif "(" in my_str2:
	                pass
                    elif my_str2 == "Standard":
                        print "[*] Phone Status is now 'Standard' ~ User has hung up"
		    elif my_str2.startswith("9") and len(my_str2) == 11:
                        my_str3 = my_str2[1:]
                        formatted_str3_1 = my_str3[0:3]
		        formatted_str3_2 = my_str3[3:6]
		        formatted_str3_3 = my_str3[6:]
		    elif my_str2.startswith("91") and len(my_str2) == 12:
                        my_str3 = my_str2[2:]
                        formatted_str3_1 = my_str3[0:3]
		        formatted_str3_2 = my_str3[3:6]
		        formatted_str3_3 = my_str3[6:]
                        query_string1 = "1." + formatted_str3_1 + "." + formatted_str3_2 + "." + formatted_str3_3
                        query_string2 = "1-" + formatted_str3_1 + "-" + formatted_str3_2 + "-" + formatted_str3_3
                    else:
                        print "[*] rqnt Message:  %s" % my_str2
	elif "NTFY" in mgcp_payload:
            if "O:" in mgcp_payload:
                index2 = mgcp_payload.index("O:")
                my_str = mgcp_payload[index2:]
                if "u/ku(" in my_str:
                    index3 = my_str.index("u/ku(")
                    my_str2 = my_str[index3+5:]
                    my_str3 = my_str2[:1]
                    print "[*] NTFY Message:  User dialed %s" % my_str3
        elif "a=crypto" in mgcp_payload:
            index10 = mgcp_payload.index("a=crypto")
            index20 = mgcp_payload.index("UNAUTHENTICATED_SRTP")
            

            myjasonstr1 = mgcp_payload[index10:index20+21]
            #print "[*] Warning!  Alert!  SDP message contains cleartext SRTP crypto keys!  Keys enumerated:"
            #print myjasonstr1 
        else:
            pass
             

sniff(filter="udp port 2427",prn=packet_callback,store=0)
