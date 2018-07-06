# COMP116IntoToComputerSecurity
COMP 116: Intro to Computer Security - Tufts Online Class - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/

## Week 1

### Slide Notes
- "CIA Triad"
  - confidentiality
  - integrity
  - availability
- Event -> Anything
- incident -> malicious event
- bug -> error at implementation level
- flaw -> error at a deeper level, particularly in the design
- https://stackoverflow.com/questions/152457/what-is-the-difference-between-a-port-and-a-socket
- OSI -> Open Systems Interconnection
  1. Physical
  2. Data link
  3. Network
  4. Transport
  5. Session
  6. Presentation
  7. Application
- Network Sniffing
  - looks at/analyzes packets
  - Most traffic is still unencrypted plaintext
  - Types of Networks: unswitched-> packets flow through all devices on network but you
look at only the packets addressed to you and switched->packets flow through specific devices on network; most
common today
- Network Scanning
  - Many scans get you flagged; you want to be stealthy
  - Stealthy scans
    - FIN scan: only TCP FIN flag in packet
    - NULL scan: No flags in packets
    - Christmas Tree (XMas) scan: FIN, PSH, URG flags in packet
  - Defending Against Scanners
    - Close services on computers that are not necessary
    - Packet filtering
    - Firewalls
  - Decoy Scanning (aka cloak scan)
    - Blame someone else
    - "which makes it appear to the remote host that the host(s) you specify as
decoys are scanning the target network too. Thus their IDS might report 5– 10 port scans from unique IP addresses, but they won't know which IP was scanning them and which were innocent decoys. While this can be defeated through router path tracing, response-dropping, and other active mechanisms, it is generally an effective technique for hiding your IP address."
- Distributed Denial of service
  - SYN Flood -> exhausts states in TCP/IP stack
    - To Prevent:
      - Reduce SYN-received Timeout
      - Drop half-open connections when limit has been reached and new requests for connection narrative
      - Limit the number of half-open connections from a specific source
      - Increase the length of the half-open connection queue
      - Use SYN cookies; they use special algorithm for determining the initial sequence number of the server
  - Teardrop
    - old; Since the machine receiving such packets cannot reassemble them due to a bug in TCP/IP fragmentation reassembly, the packets overlap one another, crashing the target network device.”
  - Ping of Death
    - However, many ping implementations allow the user to specify a packet size larger than 65,507 bytes. A grossly oversized ICMP packet can trigger a range of adverse system reactions such as denial of service (DoS), crashing, freezing, and rebooting.”
  - ICMP/UDP Flood Attack
    - Overload victim with a huge number of ICMP/UDP echo requests with spoofed source IP addresses

### Readings

#### A Disaster Foretold --and Ignored (Washington Post) - https://www.washingtonpost.com/sf/business/2015/06/22/net-of-insecurity-part-3/?noredirect=on&utm_term=.24978e555d1f
- "Pray and Patch" -> "Keep building, keep selling, and send out fixes as necessary.  If a system failed, ..., the burden fell not on the giant, rich tech companies but on their customers."
- "Featureitis" -> new features are added mroe quickly than they can be made secure.

#### Reflections on Trusting Trust - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/readings/p761-thompson.pdf
- "More precisely stated, the problem is to write a source program that, when compiled and executed, will produce as output an exact copy of its source."
- "Thus if this code were installed in binary and the binary were used to compile the login command, I could log into that system as any user"
- "You can't trust code that you did not totally create yourself"

#### Programmers: Stop Calling Yourselves Engineers - https://www.theatlantic.com/technology/archive/2015/11/programmers-should-not-call-themselves-engineers/414271/
- Engineers need to get things right the first time; software tends not too
- "Professional Engineering certification is usually offered only in fields where something could go terribly, horribly wrong with unqualified actors at the helm."
- 'The U.S. Bureau of Labor and Statistics (BLS) calls the “engineers” who work at Google and Uber and Facebook and its ilk “Computer Programmers” or “Software Developers.”'

#### Defending Against Hackers Took a Back Seat at Yahoo, Insiders Say - https://mobile.nytimes.com/2016/09/29/technology/yahoo-data-breach-hacking.html
- 'The “Paranoids,” the internal name for Yahoo’s security team, often clashed with other parts of the business over security costs.'
- "To make computer systems more secure, a company often has to make its products slower and more difficult to use."

#### Verizon 2018 Data Breach Investigations Report (DBIR) - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/readings/rp_DBIR_2018_Report_en_xg.pdf
- "When breaches are successful, the time to compromise continues to be very short"
- " The discovery time is also very dependent on the type of attack, with payment card compromises often discovered based on the fraudulent use of the stolen data (typically weeks or months) as opposed to a stolen laptop which is discovered when the victim realizes they have been burglarized."
- "Pretexting (170 incidents, 114 confirmed data breaches) is the creation of a false narrative to obtain information or influence behavior."
- "One of the differences between pretexting and phishing events is the lack of reliance on malware installation in the former for the attacker to meet their end goal"
- "Amplification attacks take advantage of the ability to send small spoofed packets to services that, as part of their normal operation, will in turn reply back to the victim with a much larger response. It is similar to asking a friend “How are you?” and then receiving a twenty-minute response about the price of gas, how much they love CrossFitTM, their cat’s hairball problem, etc"

#### Cybersecurity: Time for a New Definition (Lawfare) - https://www.lawfareblog.com/cybersecurity-time-new-definition
- Cybersecurity: "Prevention of damage to, protection of, and restoration of computers, electronic communications systems, electronic communications services, wire communication, and electronic communication, including information contained therein, to ensure its availability, integrity, authentication, confidentiality, and nonrepudiation"
- "...our policies, were focused on protecting computer systems and their data, not on protecting people's minds from misinformation planted on networks users relied upon."

#### The Trinity of Trouble: Why the Problem is Growing (Freedom to Tinker) - https://freedom-to-tinker.com/2006/02/15/software-security-trinity-trouble/
- " In practice, the defect rate tends to go up as the square of code size. "

#### Tools and Techniques to Succeed at the Wall of Sheep (on wallofsheep.com) - http://cdn.shopify.com/s/files/1/0177/9886/files/2013_WOS_ToolsAndTechniques.pdf?47

#### The Basics of Arpspoofing/Arppoisoning (Irongeek.com) - http://www.irongeek.com/i.php?page=security/arpspoof
- "ARP stands for Address Resolution Protocol and it allows the network to translate IP addresses into MAC addresses"

#### ARP Spoofing (Veracode) - https://www.veracode.com/security/arp-spoofing

#### Fun With Network Friends (2600 Magazine, Summer 2008) - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/readings/2600vol25no2.pdf

#### We scanned the Internet for port 22 (Errata Security) - https://blog.erratasec.com/2013/09/we-scanned-internet-for-port-22.html#.Wz5oQ9VKgUE

#### Thousands of computers open to eavesdropping and hijacking (Sophos) - https://nakedsecurity.sophos.com/2014/08/15/thousands-of-computers-open-to-eavesdropping-and-hijacking/
- Virtual Network Computing (VNC) is remote desktop and it should be secured with a long password

#### Deep Inside a DNS Amplification DDoS Attack (Cloudflare) - https://blog.cloudflare.com/deep-inside-a-dns-amplification-ddos-attack/
- "A SMURF attack involves an attacker sending ICMP requests (i.e., ping requests) to the network's broadcast address (i.e., X.X.X.255) of a router configured to relay ICMP to all devices behind the router. The attacker spoofs the source of the ICMP request to be the IP address of the intended victim. Since ICMP does not include a handshake, the destination has no way of verifying if the source IP is legitimate."

#### Brian Krebs' Blog Hit by 665 Gbps DDoS Attack (SecurityWeek) - https://www.securityweek.com/brian-krebs-blog-hit-665-gbps-ddos-attack
- 665 gbps is alot

#### Network Protocols (Destroy All Software) - https://www.destroyallsoftware.com/compendium/network-protocols?share_key=97d3ba4c24d21147

### Labs

#### Lab: Working with the Command Line
##### Part 1, The Basics
1. which
2. ifconfig -a
3. ps
4. netstat -ltnp
5. ls -la
6. file
7.
8. arp
9. China
10. geoiplookup

### Questions/Learn More's
1. Amplicifcation Attacks: https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/
2. DDOS being cover for other attacks: https://www.zdnet.com/article/denial-of-service-attacks-now-a-cover-for-something-more-sinister/
3.
