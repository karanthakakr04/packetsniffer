# packetsniffer

This assignment aims to show how to use Scapy, a program written in Python, to capture packets in real time. 

# Required Setup

	> Virtual Box - Version 6.1.18 (a newer release should work fine)
	
Download here: https://www.virtualbox.org/wiki/Downloads. You will need to setup Ubuntu VM (I chose 18.04.5 LTS because it uses less resources than the newer LTS release). There is some configuration involved to be able to network with your host PC.	

	> Ubuntu 18.04.5 LTS (Bionic Beaver)
	
Download the desktop image here: https://releases.ubuntu.com/18.04/. After downloading install Ubuntu on VirtualBox. Before starting the VM set the second network adapter to Host-Only. This will allow the Host PC to ping the Ubuntu VM.  

<insert image here for network adapters>

# Additional Steps

After booting up the Ubuntu VM, you need to make the following changes in /etc/network/interfaces file:

<insert the image for network interfaces>

You need to verify if the network interfaces are set using the command as shown below:

<insert image for ip a> 

This specific code uses Scapy as a module that can be installed in the system using the following command:

	> sudo python3 -m pip install --pre scapy[complete]

This will install Scapy and all its main dependencies. Please make sure you have pip installed your system before you run this command. Also, make sure to install python 3.6 or higher in order to get this code working. 

You can check if scapy is installed properly on your VM by doing this:

<insert image scapy_sniffer>

# Sniffing Packets

Execute the program using the command:

	> sudo python3 packet_sniffer.py
	
The program is going to ask to input couple of parameters for the sniff() function and save packet log in a text file:

<insert image Github_1>

<insert image pcap_log1.txt>
