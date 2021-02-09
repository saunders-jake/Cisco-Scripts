#Login Enhancements

security passwords min-len 10
login block-for 120 attempts 5 within 60
login quiet-mode access-class PERMIT-ADMIN
login delay 3
login on-success log every 3
login on-failure log every 3
security authentication failure rate 3 log

#SSH
ip domain-name ccnasecurity.com
crypto key zeroize rsa
crypto key generate rsa general-keys modulus 1024
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retires 2
username admin algorithm-type secret cisco12345
line vty 0 15
  login local
  transport input ssh

#Privilege Levels
en
conf t
privilege exec level 5 show running-config
enable secret level 5 cisco5
end
disable
enable 5
cisco5
sho running-config

#Role Based Views (aka Parser Views)
aaa new-model
enable view 
parser view SHOWVIEW
  secret cisco1
exit
parser view ADMIN
view SHOWVIEW
secret cisco2

#Cisco IOS Resilient Feature
secure boot-image
secure boot-config
show secure bootset
secure boot-config restore flash0:rescue-cfg
copy flash0:rescue-cfg running-config

#Secure Copy

##SCP server config
ip domain-name ccnasecurity.com
crypto key generate rsa general-keys modulus 2048
username Admin priv 15 algorithm-type scrypt secret cisco12345
aaa new-model
aaa authenticaion login default local
aaa authorization exec default local
ip scp server enable

##SCP transfer to SCP server
copy flash0:Routerbackup.cfg scp:

#Syslog
memory free low-watermark processor 123456
memory free low-watermark IO 123456
##Syslog configuration on Cisco IOS host
logging host 192.168.0.1
logging trap 4
logging source-interface g0/1
no logging on 
logging on

#Syslog Agent

ip access-list standard PERMIT_SNMP
permit 192.168.0.1
snmp-server view SNMP_VIEW iso include
snmp-server group SNMP_GROUP v3 priv read SNMP_VIEW access PERMIT_SNMP
snmp-server user ADMIN SNMP_GROUP v3 auth sha ci$c0authpw priv 3des ci$c0privpw 

#NTP

##NTP Server
ntp master 3
##NTP Host
ntp server 192.168.0.1
ntp authenticate
ntp authentication-key 1 md5 K3Y-V@lu3
ntp trusted-key 1

#Autosecure
autosecure 
#OSPF authentication

##MD5
int g0/1
	ip ospf message-digest-key 1 md5 Ci$C0123
router ospf 1
	area 0 authentication message-digest

##SHA
key chain SHA256
	key 1
		key-string 0$PF-SHA_k3y
		cryptographic-algorithm hmac-sha-256
int g0/1
	ip ospf authentication key-chain 0$PF-SHA_k3y

#AAA authentication

##Local AAA authentication
username JR-ADMIN alg scrypt secret cisco12345
aaa new-model
aaa authentication login default local-case
aaa authentication login SSH-LOGIN local-case
line vty 0 15
	login authentication SSH-LOGIN
aaa local authentication attempts max-fail 5
clear aaa local user lockout 

##AAA server based authentication
aaa new-model

tacacs server Server-T
	address ipv4 192.168.1.101
	single-connection
	key TACACS-Pa55w0rd
radius server Server-R
	address ipv4 192.168.1.100 auth-port 1812 acct-port 1813
	key RADIUS-Pa55w0rd
aaa authentication login default group tacacs+ group radius local-case

#AAA authorization

username JR-ADMIN alg scrypt secret cisco12345
aaa new-model
aaa authorization exec default group tacacs+
aaa authorization network default group tacacs+
aaa authorization login default group tacacs+

#AAA accounting
username JR-ADMIN alg scrypt secret cisco12345
aaa new-model
aaa accounting exec default start-stop group tacacs+
aaa accounting network default start-stop group tacacs+

#802.1X port based access control
aaa new-model
radius server Server-R
	address ipv4 192.168.1.100 auth-port 1812 acct-port 1813
	key RADIUS-Pa55w0rd
aaa authentication dot1x default group radius

dot1x system-auth-control 
!(enables 802.1X globaly)
int g0/1
	description Access Port
	switchport mode access
	authentication port-control auto
	dot1x pae authenticator 
	!(Sets interface to use Port Access Entity type, so it doesn't respond to messages for supplicant)

#IPv4 access lists

##Standard
ip access-list standard NO_ACCESS
   deny host 192.168.11.10
   permit any
int g0/0
   ip access-group NO_ACCESS out

##Extended
ip access-list extended SURFING
permit tcp 192.168.10.0 0.0.0.255 any eq 80
permit tcp 192.168.10.0 0.0.0.255 any eq 443
ip access-list extended BROWSING
   permit tcp any 192.168.10.0 0.0.0.255 established
int g0/0
   ip access-group SURFING in
   ip access-group BROWSING out

#IPv6 access lists
ipv6 access-list LAN_ONLY
   permit 2001:db8:1:1::/64 ANY
   PERMIT ICMP ANY ANY ND-NA
   permit icmp any any nd-ns
   deny ipv6 any any
int g0/0
   !!!ipv6 access-filter LAN_ONLY out
   
#Classic firewalls
ip inspect name FWRULE ssh
ip access-list extended INSIDE
   permit tcp 10.0.0.0 0.0.0.255 any eq 22
   deny ip any any
int g0/0
   ip access-group INSIDE in
   ip inspect FWRULE in
ip access-list extended OUTSIDE
   deny ip any any
int g0/1
   ip access-group OUTSIDE in
   
  

