# Cybersecurity lab simulating Windows attacks and monitoring with Wazuh SIEM in a Proxmox virtual environment.
## Wazuh-SIEM-on-Proxmox
Built a SIEM environment by deploying Wazuh inside Proxmox on a base Ubuntu Server.     Designed to collect, analyze, and visualize security events in a virtualized lab

## Brief about the Project 
It is a Proxmox Worstation which has Ubuntu as the base VM for Wazzuh. Wazzuh server is configure to receive alert updates. Windows 10 is the victim machine that has Wazzuh agent installed and Kali is the attacker. When Kali is exploting the SMB open port on Windows10 , alerts are automatically generated on Wazzuh. 

---

## Table of Contents

1. [Main Requirements](#main-requirements)  
2. [Proxmox Workstation](#proxmox-workstation)  
3. [Ubuntu Base OS](#ubuntu-base-os)  
4. [Wazuh Installation](#wazuh-installation)  
5. [Attack Simulation](#attack-simulation)  
6. [Alerts](#alerts)  
7. [Screenshots](#screenshots)  
8. [Conclusion](#conclusion)  


---

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
<img width="200" height="469" alt="Picture24" src="https://github.com/user-attachments/assets/6f023ec8-0845-43fa-ba8e-7be8650e0ab3" />

## Starting point 
As with all the CTF like environment the first and foremost thing I have done is scanning an active subnet of 10.0.0.0. And after the NMap scanning the open ports on Window 10 (victim) machine was discovered as shown in the picture. 

<img width="600" height="97" alt="Pictur7" src="https://github.com/user-attachments/assets/f7a1c411-cbd3-4024-8971-a4d74921ff73" />

In this scenario, several ports on the victim machine were found to be open: TCP/135, TCP/139, and TCP/445.
- ✅ I exploited TCP/445 by using Windows Server Message Block (SMB) to establish a remote connection to the victim’s computer.
- 🖥️ Once I gained access to the victim’s machine, since Wazuh was configured to monitor it, the server immediately generated an alert.

 #### 🔔 The alert included:
- 🕒 The correct timestamp of the attack
- 🚨 The nature of the attack, indicating the remote connection via SMB
- 📌 This shows how important it is to have Wazuh monitoring critical ports and services, as it helps detect unauthorized access in real-time.
## Cracking the password 
I have used John the Ripper built inside of Kali to extract the password and use a common list in this case Rockyou to crack the password 

## Successful exploit
The sucessful shell access can be shown by the picture. 

<img width="600" height="103" alt="Picture6767" src="https://github.com/user-attachments/assets/57e5095f-d9b1-47c1-992a-d8c1c982705f" />

## Wazzuh alerts 
In this scenario, a successful exploit was carried out on a Windows machine. The Wazuh server detected the activity and generated alerts that help us understand the nature and details of the attack.

✅ As the exploit was successful, the Wazuh server started producing alerts.
🔔 We can see the type of alert generated, which indicates:
A successful logon to the Windows machine via Remote Desktop (RDP).
🕒 The alert also includes:
The timestamp of when the attack occurred.

🌐 IP address details:
- Victim machine IP: 10.0.0.133
- Attacker machine IP: 10.0.0.130

📌 In this scenario, having a Wazuh server generating alerts is very useful to:
Detect if any kind of attack is happening on the machine.

🖥️ Since Wazuh is a host-based intrusion detection system (HIDS):
It is essential to have the Wazuh agent installed on the machine being monitored.

⚠️ Wazuh provides a variety of alerts, including:
When a user logs into the system
When apps or services request elevated privileges
When there is a clear sign of an attack, like:
Remote Desktop access being established on the victim’s computer

<img width="600" height="395" alt="Picture2" src="https://github.com/user-attachments/assets/fcd571bd-6861-439c-8067-14bd1d879e6c" /> 

<br><br>

<img width="600" height="395" alt="Picture78787" src="https://github.com/user-attachments/assets/6974a705-3deb-46fa-b02d-5393d26358ff" />





## Functionality 
#### Wazuh is typically very useful in generating different types of alerts for different types of exploits. It also provides a CIS health benchmarks of a pc that is currently being monitored and protected. The dashboard view can be represented in the following. 


<img width="600" height="851" alt="Picture78778778787" src="https://github.com/user-attachments/assets/53f0eec3-5842-447f-988d-6c74e4c613af" />


🛡️ **Wazuh Security Configuration Assessment Summary**

Uses CIS Benchmarks for Windows 10 Enterprise

Dashboard visualizes system compliance
  Donut chart shows:
  - ✅ **Passed:** 123
  - ❌ **Failed:** 265
  - 🚫 **Not applicable:** 6
  - The overall score is 31%
  Helps detect exploits and misconfigurations to enhance system hardening

## Attacks Types and Definitions of some common attack groups by Wazuh
### The Attacker's Toolbelt: A Look at Malicious Software and MITRE Att&cks Frameworks

<img width="600" height="727" alt="Picture2" src="https://github.com/user-attachments/assets/98412834-ceb0-4b6a-9a05-2263f8a55afa" />

#### This screenshot showcases some of the specific tools and software that cyber attackers use in their operations. It’s a valuable part of any threat intelligence platform because it moves beyond just talking about groups and tactics and gets into the nitty-gritty of the actual code and programs used. Some of the tools listed are:
- PoshC2: An open-source framework used for remote administration and post-exploitation.
- Pass-The-Hash Toolkit: A tool for using stolen password hashes to log into systems without knowing the actual password.
- Mimikatz: A very famous credential dumper for Windows systems that can reveal plaintext passwords from memory.
- HOPLIGHT: A specific backdoor Trojan reportedly used by a North Korean group.
This page helps security teams understand the technical side of attacks, which is essential for building effective defenses.

### More Attacks by Groups
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



### Understanding the Dashboard 
<img width="600" height="814" alt="Picture4" src="https://github.com/user-attachments/assets/5605b86a-f257-4b8c-bad4-761d2547fe83" />

The Wazuh dashboard is more than just a collection of charts—it's a real-time command center for cybersecurity teams, designed to turn chaos into clarity. It transforms raw data into actionable insights, helping analysts stay ahead of threats with speed and confidence.
- 📈 Alerts Evolution Over Time: This timeline graph isn’t just a visual—it’s a pulse check on your network. A sudden spike between 6 PM and 9 PM? That’s your cue to dig deeper. It helps teams correlate activity with known events, patch deployments, or suspicious behavior.
- 🧠 Top Tactics: The pie chart breaks down adversarial behavior into recognizable patterns like Defense Evasion, Initial Access, and Privilege Escalation. It’s like profiling the enemy’s playbook, so defenders can anticipate their next move.
- 🔐 Rule Level by Attack: This chart categorizes threats by severity and sophistication. Whether it’s a low-level phishing attempt or a high-risk privilege escalation, analysts can prioritize response efforts based on impact.
- 🚨 Threat Landscape Overview: Additional graphs show the most common attack vectors, targeted assets, and frequency of rule triggers. It’s a bird’s-eye view of what’s hitting your environment—and how often.
- 🧭 Navigation & Filtering: The dashboard allows filtering by time, rule level, tactic, and source IP. This empowers analysts to zoom in on specific incidents or trends without drowning in noise.
- 🛠️ Operational Efficiency: With intuitive visuals and drill-down capabilities, the dashboard reduces alert fatigue and accelerates triage. It’s not just about seeing the data—it’s about understanding it instantly.
In short, this dashboard turns threat detection into a visual narrative. It’s not just a tool—it’s a teammate.

### Report Generated 

<img width="600" height="901" alt="image" src="https://github.com/user-attachments/assets/c2d9b008-b44d-4da1-954a-4b63682f84b7" />

### 🛡️ Wazuh Alerts Summary
This table acts as a security event log, detailing every activity and potential threat detected by the Wazuh agent. It gives a clear, itemized account of what's happening on the monitored system.

- Diverse Events at a Glance: The table is a blend of routine system events and critical security alerts. You can see mundane actions like a user logging off (Rule ID 60137) right next to high-priority events like a successful remote logon (Rule ID 92657).
- The Power of Specifics: Each entry is a specific data point. For instance, the Apparmor DENIED entry shows a count of 38, indicating that this specific security policy has been triggered multiple times. This isn't just a general alert; it's a specific number pointing to a recurring event.
- Drilling Down on a High-Risk Event: The highlighted entry is a perfect example of Wazuh's detailed analysis. It identifies a successful remote logon with a high severity level. The description isn't vague; it specifies the user (kali) and even suggests a possible attack vector (pass-the-hash). Crucially, it provides an actionable recommendation: "Verify that KALI is allowed to perform RDP connections." This moves the alert from a simple notification to a task for an analyst to investigate.

## Wazuh Alert Evolution Dashboard
<img width="600" height="744" alt="image" src="https://github.com/user-attachments/assets/65cae696-9587-4f0a-9626-cca727f227f6" />



Top 5 Agents: The top graph shows that the sbmonitor-PC agent (green) generated a large number of alerts around 18:00, with another spike around 20:00. The Win10agent (blue) also had a small spike at the same time.

Alert Level Evolution: The bottom graph shows a significant spike in alert counts, primarily for Level 8 alerts (green/purple) and Level 7 alerts (light green), correlating with the activity seen in the top graph. This indicates a period of high-severity security events.


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
- ```bash
  https://<wazuh server's ip>:5601
  ```
  and the dashboard is visible stating the number of agents which are connected and active. 

