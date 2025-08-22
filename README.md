# Cybersecurity lab simulating Windows attacks and monitoring with Wazuh SIEM in a Proxmox virtual environment.
## Wazuh-SIEM-on-Proxmox
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
All the virtual machines are on the same network. They are in the subnet range of 10.0.0.0/24. 

#### The environment in the project can be described by the following image 
<img width="600" height="469" alt="Picture24" src="https://github.com/user-attachments/assets/6f023ec8-0845-43fa-ba8e-7be8650e0ab3" />

## Starting point 
As with all the CTF like environment the first and foremost thing I have done is scanning an active subnet of 10.0.0.0. And after the NMap scanning the open ports on Window 10 (victim) machine was discovered as shown in the picture. 

<img width="600" height="97" alt="Pictur7" src="https://github.com/user-attachments/assets/f7a1c411-cbd3-4024-8971-a4d74921ff73" />

The ports which are in open state which are TCP/135, TCP/139 and TCP/445. I have exploited the TCP/445 and established a remote connection to the victim’s computer using windows Server Message Block. As soon as I am able to get into the victim’s computer since Wazuh was configured to monitor, it generated an alert coming in with the correct time stamp and the nature of the attack.  

## Cracking the password 
I have used John the Ripper built inside of Kali to extract the password and use a common list in this case Rockyou to crack the password 

## Successful exploit
The sucessful shell access can be shown by the picture. 

<img width="600" height="103" alt="Picture6767" src="https://github.com/user-attachments/assets/57e5095f-d9b1-47c1-992a-d8c1c982705f" />

## Wazzuh alerts 
As the exploit was sucessful Wazzuh server was producing alerts. . We see the type of alert generated indicating that the there was a successful logon to the Windows Machine via remote desktop, the time stamp of when the attack was done, the Ip address of the Victim which is 10.0.0.133 and the Ip address of the attacker as 10.0.0.130. In this scenario having a Wazuh server that is initiating the alerts is very useful to determine if there is any sort of attacks that’s done to a machine, also since it’s a host-based intrusion detection system it is essential to have the agent installed on the machine that is being monitored. We can see all sorts of alerts ranging from a simple event as when the user logged into the system, any apps or services that are running that is needing escalated privileges or any form of an actual attack like the one above where there is clear establishment of a remote desktop on a victim’s computer. 

<img width="600" height="797" alt="Picture2" src="https://github.com/user-attachments/assets/fcd571bd-6861-439c-8067-14bd1d879e6c" />



<img width="600" height="395" alt="Picture78787" src="https://github.com/user-attachments/assets/6974a705-3deb-46fa-b02d-5393d26358ff" />

## Functionality 
#### Wazuh is typically very useful in generating different types of alerts for different types of exploits. It also provides a CIS health benchmarks of a pc that is currently being monitored and protected. The dashnoard view can be represented in the following. 


<img width="600" height="851" alt="Picture78778778787" src="https://github.com/user-attachments/assets/53f0eec3-5842-447f-988d-6c74e4c613af" />

## Attacks Types and Definitions of some common attack groups by Wazuh

### Understanding Cybersecurity Threats Through Wazuh
<img width="600" height="681" alt="Picture1" src="https://github.com/user-attachments/assets/57030362-ec81-4b81-9999-f7e5b88c15cf" />

#### Wazuh offers a powerful look into the world of cyber threats, combining technical details with intelligence on the groups behind the attacks.

- The first image highlights a specific MITRE ATT&CK technique, T1003.008, which explains how attackers can steal password hashes from Linux systems. The description mentions the /etc/passwd and /etc/shadow files, which are key targets for this type of attack.
- The second image focuses on different adversary groups, such as Kimsuky and GALLIUM. The platform provides valuable details on these groups, including their country of origin and typical targets, helping users understand who might be trying to attack them.
- Together, these screenshots show how Wazuh provides a comprehensive view of cybersecurity threats by linking specific techniques to the real-world groups that use them, creating a clearer picture for security teams.

### Understanding OS Credential Dumping with Wazuh


<img width="600" height="666" alt="Picture3" src="https://github.com/user-attachments/assets/59fbfddd-d26c-4099-90a7-d059433ded30" />

#### Wazuh is a security platform that provides clear, actionable intelligence on how attackers operate, helping you understand and respond to threats effectively.
- The image displays the Wazuh dashboard, specifically highlighting the MITRE ATT&CK section.
- It details the "OS Credential Dumping" technique, which involves attackers targeting Linux's /etc/passwd and /etc/shadow files to steal password hashes.
- The platform provides actionable intelligence, explaining how these hashes can be used with tools like John the Ripper to crack passwords.

### The Attacker's Toolbelt: A Look at Malicious Software

<img width="600" height="727" alt="Picture2" src="https://github.com/user-attachments/assets/98412834-ceb0-4b6a-9a05-2263f8a55afa" />

#### This screenshot showcases some of the specific tools and software that cyber attackers use in their operations. It’s a valuable part of any threat intelligence platform because it moves beyond just talking about groups and tactics and gets into the nitty-gritty of the actual code and programs used. Some of the tools listed are:
- PoshC2: An open-source framework used for remote administration and post-exploitation.
- Pass-The-Hash Toolkit: A tool for using stolen password hashes to log into systems without knowing the actual password.
- Mimikatz: A very famous credential dumper for Windows systems that can reveal plaintext passwords from memory.
- HOPLIGHT: A specific backdoor Trojan reportedly used by a North Korean group.
This page helps security teams understand the technical side of attacks, which is essential for building effective defenses.

### Understanding the Dashboard 
<img width="600" height="814" alt="Picture4" src="https://github.com/user-attachments/assets/5605b86a-f257-4b8c-bad4-761d2547fe83" />

This is a great look at the Wazuh dashboard, which gives a visual overview of security events. It helps a security analyst quickly see what's happening in the environment, from the types of attacks to the rules that are being triggered.

- The dashboard shows a timeline of "Alerts evolution over time," so you can see when security events are spiking. This particular chart shows a significant increase in alerts between 6 PM and 9 PM.
- There are multiple charts displaying "Top tactics" and "Rule level by attack," which break down the types of attacks being detected. This includes things like Defense Evasion, Initial Access, and Privilege Escalation.
- It provides a comprehensive, at-a-glance view of the most common threats and tactics targeting the network, helping security teams prioritize their response efforts based on real-time data.

## Setting up the Environment 
Proxmox is installed on my workstation in the same home network subnet of 10.0.0.0 /24. I have used Ubuntu for the base virtual machine for Wazuh. Wazuh is downloaded using Curl. 
## Setup Procedure 
### Update system packages
- ```bash
   sudo apt-get update -y
- ```bash
   sudo apt-get upgrade -y 
### Install curl, apt-transport-https, and lsb-release if missing
- ```bash
  sudo apt-get install curl apt-transport-https lsb-release gnupg2 -y
### Download and run the Wazuh installation script
- ```bash  
  curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh
- ```bash  
  sudo bash wazuh-install.sh --all-in-one --overwrite
## Installing the Agent on Windows 10 
A Wazuh agent matching the exact release version is added to the Windows 10 victim machine and configured with the Wazuh Server Ip for management. 
## Adding the Agent to the Server 
Once the Wazuh agent is installed on an endpoint (Ubuntu/Windows), it needs to be registered with the Wazuh server using an enrollment key.
### On the Wazuh Server (Manager)
Run the following command:
- ```bash
  sudo /var/ossec/bin/manage_agents
Inside the menu:
Press A → Add an agent
Enter:
- Agent name (e.g., ubuntu-agent)
- Agent IP
- The system will generate an Agent key (long alphanumeric string).
- Copy the key.

Exit the menu by pressing Q.

### On the Wazuh Agent (Windows 10)
Open the Wazuh Agent Manager application from the Start Menu.
- In the Server field, enter the IP address of the Wazuh server .
- Click Manage keys → Import key.
- Paste the Agent key copied from the Wazuh server.
- Save the configuration.
- Start the agent by clicking Start in the Wazuh Agent Manager window.

### Verify the Agent Connection
On the Wazuh server, confirm the agent is active:
- ```bash
  sudo /var/ossec/bin/agent_control -ls
If successful, the Windows 10 agent will appear in the list with its ID, name, and status.

### Starting the Wazuh Agent on Windows 10 
- ```bash
  net start WazuhSvc
### Restaring the Wazuh Manager 
- ```bash
  sudo systemctl start wazuh-manager

If this is successful then open the Web browser and login to 
- https://<wazuh server's ip>:5601
and the dashboard is visible stating the number of agents which are connected and active. 

