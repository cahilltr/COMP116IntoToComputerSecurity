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
2. ifconfig -a (deprecated)
3. ps
4. netstat -ltnp
5. ls -la
6. file
7. strings
8. arp
9. China
10. geoiplookup

#### Lab: Packet Sluth
1. 367
2. FTP
3. Password is in clear text, see packet 14
4. SFTP
5. 192.168.1.8, see packet 9
6. username: blinkythewonderchimp, password F00tball!
7. & 8.  Aleph1.txt, 045ece36a178933c16fba8ee340b7ac459e95475317df833bffd2c2f8bfb2c85.jpg, C-658VsXoAo3ovC.jpg, geer.source.27iv17.txt, wut.jpg (5 files)
9. N/A
10. 76409
11. 2
12.
  - ventas@wekiguatemala.com.gt:$Alesgt1.1 -> IMAP, 74.220.219.
  - wbgapp31216:Q827wO6656!nW99_al -> HTTP, utils.wbg-server.se
13. No
14. Wireshark -> Statistics -> Resolved addresses
15. 3
16. HTTP, 130.64.23.35:80
  - brodgers:TheyPlayWithGreatCharacter
  - dmoyes:IAmAFootballGenius
  - aoursler:ld10tExpert
17.
18.
19.
20. Use HTTPS

#### Lab: Scanning and Reconnaissance
##### Part 1, Using nmap
1. 80/tcp, http; 110, pop3; 443, https; 1720, h323q931; 5060, sip
2. Yes
2a. nmap -sv <ip address>, nginx - 1.10.3
3.
4. Oracle Virtualbox or QEMU
5. asdf
6. TODO: use telnet on 1720

### Questions/Learn More's
1. Amplicifcation Attacks: https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/
2. DDOS being cover for other attacks: https://www.zdnet.com/article/denial-of-service-attacks-now-a-cover-for-something-more-sinister/


## Week 2

### Slide Notes
- Cryptography - The process of communicating secretly through the use of cipher
- Cryptanalysis - The process of cracking or deciphering; code breaking
- Cryptology - The study of cryptography or cryptanalysis
- Cleartext / plaintext - What you are reading now
- Encrypt - convert information or data into code to prevent unauthorized access
- Decrypt – convert an encoded or unclear message into something intelligible, to plaintext
- Cipher - An algorithm to perform encryption and/or decryption
- Cryptosystem - Suite of algorithms to perform encryption and/or decryption
- Tradeoff 1: the cost of breaking a cipher exceeds the value of the encrypted information
- Tradeoff 2: the time required to break the cipher exceeds the useful lifetime of the information
- Hash functions - one way encryption, no decryption thus no secret key
- Symmetric - single key for encryption and decryption
- Asymmetric a.k.a., public key - uses two different keys: one public (for encryption) and one private (for decryption)
- Two files of interest on a typical Linux box:
  - /etc/passwd - Contains users' information but no encrypted password; required for login
  - /etc/shadow - Contains users' passwords (encrypted) with additional details relating to the password (see http://tldp.org/LDP/lame/LAME/linuxadmin-made-easy/shadow-file-formats.html for more details)

### Readings
#### How to Dramatically Improve Corporate IT Security Without Spending Millions (Praetorian) - https://p16.praetorian.com/downloads/report/How%20to%20Dramatically%20Improve%20Corporate%20IT%20Security%20Without%20Spending%20Millions%20-%20Praetorian.pdf
- "..attackers don’t rely on zero-day exploits extensively — unique attacks that take advantage of previously unknown software holes to get into systems. That’s because they don’t have to."
- Top Attack Vectors
  1. WEAK DOMAIN USER PASSWORDS
  2. BROADCAST NAME RESOLUTION POISONING
  3. LOCAL ADMINISTRATOR ATTACKS - AKA PASS THE HASH
  4. CLEARTEXT PASSWORDS FOUND IN MEMORY - MIMIKATZ
  5. INSUFFICIENT NETWORK ACCESS CONTROLS
- "If employees have Local Administrator rights to more than their own system, then malware is able to spread to those systems more easily."
- Broadcast Name Resolution Posioning: The attacker configures its system to respond to broadcast requests such as LLMNR, NetBIOS, or MDNS by providing its own IP.
- Modern versions of the Microsoft Windows operating system store domain credentials in cleartext within memory of the LSASS process.

#### You Wouldn't Base64 a Password - Cryptography Decoded (Paragon Initiative) - https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded
- Don't implement cryptography yourself
- Keyless Cryptography: cryptographic hash function, which accepts one input and returns a single deterministic fixed-size output.
- Secret Key Cryptography: they typically require two pieces of input: The message and a secret key
- Keyed Hash Functions - Message authentication: is a special implementation of a hash function that accepts a message and a secret key and produces a Message Authentication Code (MAC).

#### Enterprise Security - SSL/TLS Primer Part 1 - Data Encryption (Akamai) - https://blogs.akamai.com/2016/03/enterprise-security---ssltls-primer-part-1---data-encryption.html
- TLS is used to secure communication between two parties.  Originally called Secure Sockets Layer (SSL) and later changed to Transport Layer Security (TLS), it utilizes both asymmetric cryptography as well as symmetric cryptography to provide data privacy, integrity, and authentication.
- In asymmetric cryptography, there are two keys: a public and a private; In symmetric cryptography, the same key is used to both encrypt and decrypt data.
- TLS has two phases: The asymmetric phase and the bulk data encryption (symmetric phase).
- HTTPS is simply HTTP inside of a TLS session

#### Enterprise Security - SSL/TLS Primer Part 2 - Public Key Certificates (Akamai) - https://blogs.akamai.com/2016/03/enterprise-security---ssltls-primer-part-2---public-key-certificates.html
- Inside of the certificate is:
  - The common name for the site represented by the certificate.
  - The public key for the asymmetric key pair.
  - Some options for the certificate (not important in this discussion).
  - A Certificate Authority (CA) signature.
- Self-signed certificates are certificates that have no explicit CA signer, but rather vouch for themselves.

#### GitHub Security Update: Reused password attack - https://blog.github.com/2016-06-16-github-security-update-reused-password-attack/
- Don't reuse passwords

#### Analyzing the Patterns of Numbers in 10M Passwords (2015) - http://minimaxir.com/2015/02/password-numbers/
- "...2000 is a kewl number"
- ~51% of passwords have 1 or 0 digits
- "... the local maxima in number of digits in a password all occur at even numbers of digits..."
- Use a password manager

#### Salted Password Hashing - Doing it Right - https://crackstation.net/hashing-security.htm
- "... never tell the user if it was the username or password they got wrong."
- We can randomize the hashes by appending or prepending a random string, called a salt
- Key Stretching: The idea is to make the hash function very slow, so that even with a fast GPU or custom hardware, dictionary and brute-force attacks are too slow to be worthwhile.

#### Hacker, Hack Thyself - https://blog.codinghorror.com/hacker-hack-thyself/

#### AdiOS: Say Goodbye to Nosy iPhone Apps (Veracode) - https://www.veracode.com/blog/2012/02/adios-say-goodbye-to-nosy-iphone-apps
- Lots of apps access your whole contact list for legitimate reasons
- In order to check whether the app is actually transmitting the address book information, you'd need to perform a full static analysis, or a manual test using a tool such as mitmproxy.

#### Mitmproxy: Your D.I.Y. Private Eye (Medium) - https://medium.com/@maxgreenwald/mitmproxy-your-d-i-y-private-eye-864c08f84736
- The way Mitmproxy works is by sitting in the middle of the connection between your phone or computer, and the internet at large.

#### Reverse-engineering the Kayak app with mitmproxy - http://www.shubhro.com/2014/12/18/reverse-engineering-kayak-mitmproxy/
- To the dismay of travel hackers, fare comparison APIs frequently come and go.
- Developers often change the “look and feel” of the mobile app, but seldom swap out the server endpoints from which data are obtained.

#### How https works - https://www.sudhakar.online/programming/2015/08/09/https.html

### Labs

#### Lab 6: The Incident Alarm
- https://github.com/sophwang27/scapy/blob/master/alarm.py

## Week 3

### Slide Notes
- Cookies: The maximum size of a cookie is 4 KB, Key - Value Pairs, All cookies set by server are sent to server during interaction
- What a web proxy does: intercepts requests and responses so you can modify HTTP request header fields and request body including query strings and data; records and logs HTTP(S) traffic
- Bad mistake: using hidden field to store sensitive information so it can be passed from one page to another. Examples: account number, password, product price
- Path Traversal: “By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files.”
- Never trust user input

### Readings

#### How The Web Works --In One Easy Lesson (mkcohen.com) - http://mkcohen.com/how-the-web-works-in-one-easy-lesson
- URLs are formatted like this: “<protocol>://<server>/<path>”.
- DNS is the internet’s “phone book”, so to speak.

#### Veracode's State of Software Security 2016 - https://www.veracode.com/sites/default/files/Resources/Reports/state-of-software-security-volume-7-veracode-report.pdf
- 97% of java applications have a component with at least 1 known vulnerability.
- Internal software tends to be more secure than third party software
- CRLF injection: any vulnerability that enables any kind of Carriage Return Line Feed injection attacks. Included here are flaws involving improper output neutralization for logs and improper neutralization of CRLF in HTTP headers
- Command or Agrument injection: One of the most severe categories of vulnerabilities, these issues allow an attacker to run arbitrary commands on the server hosting the application, giving them complete control of the environment.
- Top 10 vulnerability categories overall
  - CATEGORY:% APPS
  - Information Leakage 72%
  - Cryptographic Issues 65%
  - Code Quality 62%
  - CRLF Injection 53%
  - Cross-Site Scripting 50%
  - Directory Traversal 49%
  - Insufficient Input Validation 44%
  - Credentials Management 41%
  - SQL Injection 32%
  - Encapsulation 25%
- In essence, developers are introducing vulnerabilities by poorly configuring elements that are actually meant to keep application data safe. This could mean utilizing SSL incorrectly or using secure cookies the wrong way
- Developers can grow very frustrated when they work to improve the overall security of their applications through frequent testing only to be hammered for policy violations while the application is still in active development

#### What happens when you type Google.com into your browser and press enter? (on GitHub) - https://github.com/alex/what-happens-when
- punycode: a representation of Unicode with the limited ASCII character subset used for Internet host names. Using Punycode, host names containing Unicode characters are transcoded to a subset of ASCII consisting of letters, digits, and hyphen, which is called the Letter-Digit-Hyphen (LDH) subset.

#### OWASP Top 10 - https://www.owasp.org/index.php/Top_10-2017_Top_10
1. injection
2. Broken authentication
3. Sensitive Data Exposure
4. XML External Entities:Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks.
5. Broken Access Control: Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users' accounts, view sensitive files, modify other users' data, change access rights, etc.
6. Security Misconfiguration
7. Cross Site Scripting
8. Insecure Deserialization: Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.
9. Using Components with Known vulnerabilities
10. Insuffcient logging and monitoring

#### CWE/SANS TOP 25 Most Dangerous Software Errors - https://www.sans.org/top25-software-errors/
- 3 categories: insecure interaction between components, risky resource management, and porous defenses
- insecure interaction between components: These weaknesses are related to insecure ways in which data is sent and received between separate components, modules, programs, processes, threads, or systems.
  -
    CWE ID	Name
    CWE-89	Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    CWE-78	Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    CWE-79	Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    CWE-434	Unrestricted Upload of File with Dangerous Type
    CWE-352	Cross-Site Request Forgery (CSRF)
    CWE-601	URL Redirection to Untrusted Site ('Open Redirect')
- Risky Resource Mangements: The weaknesses in this category are related to ways in which software does not properly manage the creation, usage, transfer, or destruction of important system resources.
  -
    CWE ID	Name
    CWE-120	Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
    CWE-22	Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    CWE-494	Download of Code Without Integrity Check
    CWE-829	Inclusion of Functionality from Untrusted Control Sphere
    CWE-676	Use of Potentially Dangerous Function
    CWE-131	Incorrect Calculation of Buffer Size
    CWE-134	Uncontrolled Format String
    CWE-190	Integer Overflow or Wraparound
- Porous Defenses: The weaknesses in this category are related to defensive techniques that are often misused, abused, or just plain ignored.
  -
    CWE ID	Name
    CWE-306	Missing Authentication for Critical Function
    CWE-862	Missing Authorization
    CWE-798	Use of Hard-coded Credentials
    CWE-311	Missing Encryption of Sensitive Data
    CWE-807	Reliance on Untrusted Inputs in a Security Decision
    CWE-250	Execution with Unnecessary Privileges
    CWE-863	Incorrect Authorization
    CWE-732	Incorrect Permission Assignment for Critical Resource
    CWE-327	Use of a Broken or Risky Cryptographic Algorithm
    CWE-307	Improper Restriction of Excessive Authentication Attempts
    CWE-759	Use of a One-Way Hash without a Salt

#### Metasploitable 2 Exploitability Guide (Rapid7) - https://metasploit.help.rapid7.com/docs/metasploitable-2-exploitability-guide
- The Metasploitable virtual machine is an intentionally vulnerable version of Ubuntu Linux designed for testing security tools and demonstrating common vulnerabilities

#### Cross-Site Request Forgery Guide: Learn All About CSRF Attacks and CSRF Protection (Veracode) - https://www.veracode.com/security/csrf
- Cross-Site Request Forgery (CSRF) is an attack whereby a malicious website will send a request to a web application that a user is already authenticated against from a different website
- Malicious requests are sent from a site that a user visits to another site that the attacker believes the victim is validated against.
- The malicious requests are routed to the target site via the victim’s browser, which is authenticated against the target site.
- The vulnerability lies in the affected web application, not the victim’s browser or the site hosting the CSRF.
- Prevent via CSRF token whish can be challenged with each request.
  - These tokens should be per session at a minimum and can be per request

#### Cross-Site Request Forgeries and You (Coding Horror) - https://blog.codinghorror.com/cross-site-request-forgeries-and-you/
- If your web site is vulnerable to XSRF, you're in good company. Digg, GMail, and Wikipedia have all been successfully attacked this way before.

#### CSRF Attacks - What They Are and How to Defend Against Them (Acunetix) - https://www.acunetix.com/websitesecurity/csrf-attacks/

#### Cross-Site Request Forgery (OWASP) - https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)

#### Cross-Site Request Forgeries: Exploitation and Prevention (Zeller, Felten) - http://www.cs.utexas.edu/~shmat/courses/cs378_spring09/zeller.pdf
- Now suppose Alice visits a malicious site M. Content supplied by M contains Javascript code or an image tag that causes Alice’s browser to send an HTTP request to T. Because the request is going to T, Alice’s browser “helpfully” appends the session cookie sid to the request. On seeing the request, T infers from the cookie’s presence that the request came from Alice, so T performs the requested operation on Alice’s account. This is a successful CSRF attack.
- CSRF attacks are possible without the use of JavaScript (for example, a simple <img> tag can be used).
- CSRF and XSS attacks differ in that XSS attacks require JavaScript, while CSRF attacks do not
- XSS attacks require that sites accept malicious code, while with CSRF attacks malicious code is located on third-party sites

#### Blind SQL Injection: What is it? (Acuenix) - https://www.acunetix.com/websitesecurity/blind-sql-injection/
- Discovered in 1998
- Time based attacks: attacker instructs db to perform a time intensive operation.

#### XKCD: Exploits of a Mom - https://xkcd.com/327/
- Little Bobby Tables

#### The History of SQL Injection, the Hack That Will Never Go Away (Vice) - https://motherboard.vice.com/en_us/article/aekzez/the-history-of-sql-injection-the-hack-that-will-never-go-away
- "You could teach a 4-year-old to do it," Al-Bassam added, summing up how incredibly easy the whole process is. Indeed, Hunt has uploaded a video of him teaching his 3-year-old son how to carry out an SQLi attack with Havij.

#### Anonymous Leaks Paris Climate Summit Officials' Private Data (Wired) - https://www.wired.com/2015/12/anonymous-leaks-paris-climate-summit-officials-private-data/

#### Why Even Google Is Susceptible to the Most Basic Website Vulnerabilities (Veracode) - https://www.veracode.com/blog/secure-development/why-even-google-susceptible-most-basic-website-vulnerabilities
- Given the systemic nature of these problems, the solution to application risks must be a systematic approach to security, including:
  - A comprehensive application security (AppSec) program that includes static and dynamic testing of all code, including software composition analysis of open-source, third-party components and vendor-supplied software.
  - A developer-friendly training program, such as online courses and video tutorials, to help developers recognize common coding weaknesses and learn preventive, secure coding practices.

#### Paypal 2FA Bypass (henryhoggard.co.uk) - https://henryhoggard.co.uk/blog/Paypal-2FA-Bypass
- Holy shit, that was easy to by pass

#### 10 Scariest Vulnerabilities (Veracode) - https://www.veracode.com/sites/default/files/Resources/Infographics/10-scariest-vulnerabilities.pdf

## Week 5

### Slide Notes
- “CWE: has to do with the vulnerability—not the instance within a product or system”
- “CVE: has to do with the specific instance within a product or system—not the underlying flaw.”

### Readings
#### Binary Static Analysis (Chris Wysopal's talk to this class back in spring 2012) - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/readings/static-binary-analysis-wysopal-tufts-comp-116.pdf
- Static Analysis: Analysis of software performed without actually executing the program
- Binary Analysis: Binary analysis has 100% coverage. All code can be analyzed, regardless of source availability.
- Components of Static Binary Analysis
  - Binary Modeler: This component builds a model from the binary directly, using type information from debug symbols if available, producing a high-level representation of the program that includes reconstructed dataflow and control flow elements suitable for human consumption or machinebased inspection.
  - Intermediate Representation: This component is the core of the analysis, the data structure that represents the entire ‘meaning’ of theprogram being analyzed, designed carefully to represent everything and make assumptions about very little to nothing.
  - Model Querying and Condition Searching System: This is responsible for searching the intermediate model for characteristics.

#### We See the Future and It's Not Pretty: Predicting the Future Using Vulnerability Data (Chris Wysopal's talk to this class back in fall 2013) - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/readings/predicting_the_future_veracode.pdf
- State of Software Security is before a Breach Report aka "crystal ball"
- SQL injection prevalence has plateaued, affecting approximately 32% of web applications.
- Java code quality is the largest Vulnerability

### A Brief History of Software, Security, and Software Security: Bits, Bytes, Bugs, and the BSIMM (Gary McGraw's talk to my class in fall 2013) - https://www.slideshare.net/Cigital/a-brief-history-of-software-security-and-software-security-bits-bytes-bugs-and-the-bsimm
- Moats and Drawbridges vs predator drones
- Software security touchpoints in SDLC
  - Code Review (with a tool)
  - Architectural Risk analysis
  - Penetration testing
#### Introduction to CVE, CWE, and the Top 25 (Steve Christey Coley's guest talk to this class back in fall 2015) - https://tuftsdev.github.io/DefenseAgainstTheDarkArts/readings/schristeycoley-20151029.pdf
- CVE: Common Vulnerabilities and Exposures list
- The Four I’s Principle of Vulnerability Information
  -Incomplete
    – Missing versions, product names
    – Missing patch information
  - Inaccurate
    – Incorrect diagnosis
    – Blatantly wrong
  - Inconsistent
    – Acknowledgement discrepancies
    – Bug type discrepancies
    – Varying severities
  - Incomprehensible
    – Poor writing
    – Lack of clear formatting
#### - Why Everything is Hackable: Computer Security is Broken From Top to Bottom (The Economist) - https://www.economist.com/science-and-technology/2017/04/08/computer-security-is-broken-from-top-to-bottom

#### The Difference Between CWE and CVE (Daniel Miessler) - https://danielmiessler.com/blog/difference-cve-cwe/
- CWE: Common Weakness Enumeration
- CVE: Common Vulnerability Exposure

#### Web Applications Under Attack: Tenable.io and the 2017 Verizon DBIR (Tenable) - https://www.tenable.com/blog/web-applications-under-attack-tenable-io-and-the-2017-verizon-dbir

#### The Language of AppSec (Veracode) - https://www.veracode.com/blog/2016/08/language-appsec
- Flaw Vs Vulnerability
  - When a static scan identifies a flaw, it doesn’t always mean it’s exploitable; it means it needs to be reviewed
  - A vulnerability is a flaw that has a proven exploit.
  - A flaw is a weakness in an application that needs to be investigated.
- Mitigate Vs Remediate
  -  When I mitigate a flaw, I am documenting a compensating control that I believe adequately addresses the risk associated with it.
  - When I remediate the flaw, I’m changing the code to address the risk.

#### Application Security Tools: Good or Bad? (Freedom-To-Tinker) - https://freedom-to-tinker.com/2006/02/16/software-security-badness-ometer/
-  Real attackers don’t simply “fuzz” a program with input to find problems. Attackers take software apart, determine how it works, and make it misbehave by doing what users are not supposed to do.
- That is, if your software fails any of the canned tests, you have some serious security work to do. The tools can help uncover known issues. But if you pass all the tests with flying colors, you know nothing more than that you passed a handful of tests with flying colors.

#### Badness-meters Are Good. Do You Own One? (Synopsys) - https://www.synopsys.com/blogs/software-security/badness-ometers-are-good-do-you-own-one/
