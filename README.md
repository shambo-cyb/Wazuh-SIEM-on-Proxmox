# Wazuh-SIEM-on-Proxmox
Built a SIEM environment by deploying Wazuh inside Proxmox on a base Ubuntu Server.     Designed to collect, analyze, and visualize security events in a virtualized lab

## Brief about the Project 
It is a Proxmox Worstation which has Ubuntu as the base VM for Wazzuh. Wazzuh server is configure to receive alert updates. Windows 10 is the victim machine that has Wazzuh agent installed and Kali is the attacker. When Kali is exploting the SMB open port on Windows10 , alerts are automatically generated on Wazzuh. 

## Main Requirements 
### Proxmox Workstation
- Proxmox as the bare bone hypervisor on a Workstation
- Ubuntu as the base operating system for Wazuh
- Wazuh installed on Ubuntu
### Windows Laptop with VMWare (VM Machines on the same network subnet)
- Windows 10 as the victim machine
- Kali as the attacker machine

## Process 
All the virtual machines are on the same network. They are in the subnet range of 10.0.0.255/24. 

### The environment in the project can be described by the following image 
<img width="408" height="469" alt="Picture24" src="https://github.com/user-attachments/assets/6f023ec8-0845-43fa-ba8e-7be8650e0ab3" />

## Starting point 
As with all the CTF like environment the first and foremost thing I have done is scanning an active subnet of 10.0.0.255. And after the NMap scanning the open ports on Window 10 (victim) machine was discovered as shown in the picture. 

<img width="575" height="97" alt="Pictur7" src="https://github.com/user-attachments/assets/f7a1c411-cbd3-4024-8971-a4d74921ff73" />

The ports which are in open state which are TCP/135, TCP/139 and TCP/445. I have exploited the TCP/445 and established a remote connection to the victim’s computer using windows Server Message Block. As soon as I am able to get into the victim’s computer since Wazuh was configured to monitor, it generated an alert coming in with the correct time stamp and the nature of the attack.  

## Cracking the password 
I have used John the Ripper built inside of Kali to extract the password and use a common list in this case Rockyou to crack the password 

## Successful exploit
The sucessful shell access can be shown by the picture. 

<img width="397" height="103" alt="Picture6767" src="https://github.com/user-attachments/assets/57e5095f-d9b1-47c1-992a-d8c1c982705f" />

## Wazzuh alerts 
As the exploit was sucessful Wazzuh server was producing alerts. . We see the type of alert generated indicating that the there was a successful logon to the Windows Machine via remote desktop, the time stamp of when the attack was done, the Ip address of the Victim which is 10.0.0.133 and the Ip address of the attacker as 10.0.0.130. In this scenario having a Wazuh server that is initiating the alerts is very useful to determine if there is any sort of attacks that’s done to a machine, also since it’s a host-based intrusion detection system it is essential to have the agent installed on the machine that is being monitored. We can see all sorts of alerts ranging from a simple event as when the user logged into the system, any apps or services that are running that is needing escalated privileges or any form of an actual attack like the one above where there is clear establishment of a remote desktop on a victim’s computer. 

<img width="1266" height="797" alt="Picture2" src="https://github.com/user-attachments/assets/fcd571bd-6861-439c-8067-14bd1d879e6c" />



<img width="579" height="395" alt="Picture78787" src="https://github.com/user-attachments/assets/6974a705-3deb-46fa-b02d-5393d26358ff" />

## Functionality 
Wazuh is typically very useful in generating different types of alerts for different types of exploits. It also provides a CIS health benchmarks of a pc that is currently being monitored and protected. The dashnoard view can be represented in the following. 


<img width="1246" height="851" alt="Picture78778778787" src="https://github.com/user-attachments/assets/53f0eec3-5842-447f-988d-6c74e4c613af" />

