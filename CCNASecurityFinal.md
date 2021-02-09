# PART 1:
Use ur head

# PART 2:

## R3
```
en
conf t
security password min-len 10
enable algorithm-type scrypt secret cisco12345
username Admin01 privilege 15 algorithm-type scrypt secret admin01pass
banner motd $Unauthorized Access is Prohibited!$
no ip http server
ip domain-name ccnasecurity.com
crypto key generate rsa mod 1024 
ip ssh version 2
ip ssh time-out 90
ip ssh authentication-retries 2
line vty 0 15
transport input ssh
exit
aaa new-model
aaa authentication login default local
ntp authentication-key 1 md5 NTPpassword
ntp trusted-key 1
ntp server 209.165.200.233
ntp update-calendar
service timestamps log datetime msec
logging 172.30.3.3
logging trap warnings
```
# PART 3:

## R3
```
zone security INSIDE
exit
zone security INTERNET
class-map type inspect match-any INSIDE-PROTOCOLS
match protocol tcp
match protocol udp
match protocol icmp
policy-map type inspect INSIDE_TO_INTERNET
class type inspect INSIDE-PROTOCOLS
inspect
zone-pair security IN_TO_OUT_ZONE source INSIDE destination INTERNET
service-policy type inspect INSIDE_TO_INTERNET
int g0/1
zone-member security INSIDE
int s0/0/0
zone-member security INTERNET
```
# PART 4:

## R3
```
end
delete /recursive /force flash:/IPSDIR
mkdir IPSDIR
IPSDIR
conf t
crypto key pubkey-chain rsa 
named-key realm-cisco.pub signature
key-string
30820122 300D0609 2A864886 F70D0101
01050003 82010F00 3082010A 02820101
00C19E93 A8AF124A D6CC7A24 5097A975
206BE3A2 06FBA13F 6F12CB5B 4E441F16
17E630D5 C02AC252 912BE27F 37FDD9C8
11FC7AF7 DCDD81D9 43CDABC3 6007D128
B199ABCB D34ED0F9 085FADC1 359C189E
F30AF10A C0EFB624 7E0764BF 3E53053E
5B2146A9 D7A5EDE3 0298AF03 DED7A5B8
9479039D 20F30663 9AC64B93 C0112A35
FE3F0C87 89BCB7BB 994AE74C FA9E481D
F65875D6 85EAF974 6D9CC8E3 F0B08B85
50437722 FFBE85B9 5E4189FF CC189CB9
69C46F9C A84DFBA5 7A0AF99E AD768C36
006CF498 079F88F8 A3B3FB1F 9FB7B3CB
5539E1D1 9693CCBB 551F78D2 892356AE
2F56D826 8918EF3C 80CA4F4D 87BFCA3B BFF668E9 689782A5 CF31CB6E B4B094D3
F3020301 0001
quit
ip ips name iosips
ip ips config location IPSDIR
ip http server
ip ips notify sdee
ip ips notify log
ip ips signature-category
category all
retired true
exit
category ios_ips basic
retired false
exit
exit
c
en

int s0/0/0
ip ips iosips in
```
#####GO TO PC-C OPEN THE TFTPD64 SOFTWARE. SET DIRECTORY TO TOOLS FOLDER ON DESKTOP#####
```
do copy tftp://172.30.3.3/IOS-S854-CLI.pkg idconf
```
# PART 5:

## S2
```
en
conf t
enable algorithm-type scrypt secret cisco12345 
hostname S2
username Admin01 privilege 15 algorithm-type scrypt secret admin01pass
banner motd $Unauthorized Access is Prohibited!$
no ip http server
no ip http secure-server 
ip domain-name ccnasecurity.com
crypto key generate rsa mod 1024
ip ssh version 2 
ip ssh time-out 90
ip ssh authentication-retries 2
line vty 0 15
transport input ssh
aaa new-model
aaa authentication login default local
vlan 2
name NewNative
vlan 10
name LAN
vlan 99
name Blackhole
int range fa0/1-2
sw m t
sw tr n vlan 2 
sw nonegotiate
int r f0/18, fa0/24
sw m a
sw a vlan 10
Int range fa0/18, fa0/24
switchport mode access 
switchport access vlan 10
spanning-tree bpduguard enable
int fa0/24
spanning-tree portfast
int f0/18
spanning-tree portfast
switchport port-security maximum 2
switchport port-security mac-address sticky
switchport port-security violation shutdown
int range fa0/3-17, fa0/19-23, g0/1-2
switchport mode access
switchport access vlan 99
shut
exit
spanning-tree loopguard default
ip dhcp snooping
Int f0/24
ip dhcp snooping trust
exit
ip dhcp snooping vlan 10
```
## S1
```
en
conf t
vlan 2
name NewNative
vlan 10
name LAN
vlan 99
name Blackhole
int range fa0/1-2
sw m t
sw tr n vlan 2 
sw nonegotiate
```
# PART 6:

## ASA 
```
en
conf t
hostname CCNAS-ASA
domain-name ccnasecurity.com
enable password cisco12345
username Admin01 password admin01pass
int vlan 1 
nameif inside
security-level 100 
ip address 192.168.10.1 255.255.255.0
int vlan 2
nameif outside
security-level 0
ip address 209.165.200.226 255.255.255.248
no shut
aaa authentication ssh console LOCAL
crypto key generate rsa modulus 1024
y
ssh 192.168.10.0 255.255.255.0 inside 
ssh timeout 10 
ssh version 2 
int e0/1
switchport mode access
switchport access vlan 1
no shut
int e0/0
switchport mode access
switchport access vlan 2
no shut 
route outside 0.0.0.0 0.0.0.0 209.165.200.225 
http server enable
http 192.168.10.0 255.255.255.0 inside 
object network INSIDE-NET
subnet 192.168.10.0 255.255.255.0
nat (inside,outside) dyn interface
exit
policy-map global_policy
class inspection_default
inspect icmp
exit
```





