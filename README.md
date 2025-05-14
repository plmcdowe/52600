# Project highlights from 52600
- ## 📂 [\[ 1 \] C Vulnerabilities](https://github.com/plmcdowe/52600/tree/f359f56ece8bba40cd979996ab1ae614025c0368/1-C-Vulnerabilities)
  - ### 🚧
- ## 📂 [\[ 2a \] JSON PCAP Parser](https://github.com/plmcdowe/52600/tree/f359f56ece8bba40cd979996ab1ae614025c0368/2a-JSON-PCAP-Parser)
  There are two separate files: <i>part1.py</i> and <i>part2.py</i> due to the nature of the assignment.    
  They could easily be combined and extended to handle other cases.    
  Both parse for indicators of security events in PCAP files.     
  I elected to export the PCAP as JSON and simply parse the captures by *key*:*value* pairs instead of using a PCAP library.    
  ### [part1.py](https://github.com/plmcdowe/52600/blob/f359f56ece8bba40cd979996ab1ae614025c0368/2a-JSON-PCAP-Parser/part1.py) parses for:
  > - ***Successful* HTTP sessions**
  > - **Directory Traversal evidence**
  > - **Failed login attempts**
  > - **Clear text credentials**
  > - **Apache webserver versions**
  > - **DNS source port randomization**
  > - **TCP ISN deviation**
  > - **Traceroute evidence**
  > - **XSS evidence**
  >   
  ### [part2.py](https://github.com/plmcdowe/52600/blob/f359f56ece8bba40cd979996ab1ae614025c0368/2a-JSON-PCAP-Parser/part1.py) parses for:    
  > - **Client MAC & IP addresses**
  > - **FTP session details**
  > - **Facebook URIs & cookies**
  >   
- ## 📂 [\[ 2b \] SQL-XSS-CSRF](https://github.com/plmcdowe/52600/tree/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF)
  - ### [cors_server.py](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/cors_server.py)
  - ### [csrf_0.html](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/csrf_0.html)
  - ### [sql2_md5.py](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/sql2_md5.py)
  - ### [xss_payload.html](https://github.com/plmcdowe/52600/blob/ed4b61dbb8067082c3c6ec5d86f9f5ef0145be79/2b-SQL-XSS-CSRF/xss_payload.html)
