# packetsniffer

This assignment aims to show how to use Scapy, a program written in Python, to capture packets in real time. 

# Required Setup

> Virtual Box - Version 6.1.18 (a newer release should work fine)
	
Download here: https://www.virtualbox.org/wiki/Downloads. You will need to setup Ubuntu VM (I chose 18.04.5 LTS because it uses less resources than the newer LTS release). There is some configuration involved to be able to network with your host PC.	

> Ubuntu 18.04.5 LTS (Bionic Beaver)
	
Download the desktop image here: https://releases.ubuntu.com/18.04/. After downloading install Ubuntu on VirtualBox. Before starting the VM set the second network adapter to Host-Only. This will allow the Host PC to ping the Ubuntu VM.  

![adapter_1](https://user-images.githubusercontent.com/17943347/113603111-8088ee00-9611-11eb-93f1-517d76a0973d.png)
![adapter_2](https://user-images.githubusercontent.com/17943347/113603132-867ecf00-9611-11eb-8b41-200c879684a1.png)

# Additional Steps

After booting up the Ubuntu VM, you need to make the following changes in /etc/network/interfaces file:

![interfaces_packet_sniffer](https://user-images.githubusercontent.com/17943347/113606653-4b32cf00-9616-11eb-8c9a-78903dddc5ca.png)

You need to verify if the network interfaces are set using the command as shown below:

![ip_a_packet_sniffer](https://user-images.githubusercontent.com/17943347/113606697-584fbe00-9616-11eb-90f2-f3560bb8032c.png)

This specific code uses Scapy as a module that can be installed in the system using the following command:

> sudo python3 -m pip install --pre scapy[complete]

This will install Scapy and all its main dependencies. Please make sure you have pip installed your system before you run this command. Also, make sure to install python 3.6 or higher in order to get this code working. 

You can check if scapy is installed properly on your VM by doing this:

![scapy_sniffer](https://user-images.githubusercontent.com/17943347/113606745-68679d80-9616-11eb-8794-56ee0193e81e.png)

# Sniffing Packets

Execute the program using the command:

> sudo python3 packet_sniffer.py
	
The program is going to ask to input couple of parameters for the sniff() function and save packet log in a text file:

![Github_1](https://user-images.githubusercontent.com/17943347/113606801-7ae1d700-9616-11eb-887d-e07c7d444550.png)

![pacap1](https://user-images.githubusercontent.com/17943347/113618160-46294c00-9625-11eb-8b97-74ca46308827.png)
