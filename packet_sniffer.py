# Please refer to the commented section below for a short Scapy recap!

# In Scapy, we will use the sniff() function to capture network packets.
# REMEMBER to open scapy as root
# To see a list of what functions Scapy has available, open Scapy in terminal and run the lsc() function.
# List out all of the protocols and layers available for packet manipulation by typing the ls() command.
# Run the ls(protocol) function to see the fields and default values for any protocol, e.g. ls(BOOTP)
# See packet layers and contents with the .show() method.
# Dig into a specific packet layer using a list index: pkt[3][2].summary()
# ..the first index chooses the packet out of the scapy.plist.PacketList, the second index chooses the layer for that
# specific packet
# Using the .command() method will return a string for the command necessary to recreate that sniffed packet.

# To see the list of optional arguments for the sniff() function:
# print(sniff.__doc__)

import logging
from datetime import datetime
import sys
import subprocess

global pcap_log  # we declare this file handler as global to use it in the try..except..else..finally block for file
# handling

"""
Python logging levels in descending order of importance:
    ------------------------------------
    |     Level     |   Numeric Value  |
    ------------------------------------
    |    CRITICAL   |        50        |
    |    ERROR      |        40        |
    |    WARNING    |        30        |
    |    INFO	    |        20        |
    |    DEBUG      |        10        |
    ------------------------------------
"""

# You can get rid of warnings by scapy by adding:
logging.getLogger('scapy.runtime').setLevel(level=logging.ERROR)
logging.getLogger('scapy.interactive').setLevel(level=logging.ERROR)
logging.getLogger('scapy.loading').setLevel(level=logging.ERROR)
# before importing Scapy. This will suppress all messages that have a lower level of seriousness than error messages.

try:
    from scapy.all import *
except ImportError:
    print('ImportError: Scapy is not installed on your system!')
    sys.exit()

# Printing a message to the user; always use 'sudo scapy' in Linux!
print('\n! Make sure to run this program as ROOT !\n')

# Asking the user for some parameters: interface on which to sniff, the number of packets to sniff, the time interval
# to sniff, and the protocol to sniff

# Asking the user for input - the interface on which to run the sniffer
interface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")

# Configure network interface in promiscuous mode
'''Wikipedia: In computer networking, promiscuous mode or "promisc mode"[1] is a mode for a wired network interface 
controller (NIC) or wireless network interface controller (WNIC) that causes the controller to pass all traffic it 
receives to the central processing unit (CPU) rather than passing only the frames that the controller is intended to 
receive. This mode is normally used for packet sniffing that takes place on a router or on a computer connected to a 
hub. '''

# To set an interface to promiscuous mode you can use the ‘ip’ command which is the current way of doing it.
try:
    subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
except subprocess.CalledProcessError as error:
    print(error)
    sys.exit()
else:
    # Executed if the try clause does not raise an exception
    print(f'\nInterface {interface} was set to PROMISC mode.\n')
# print(interface)  # TODO: remove after testing

# Asking the user for the number of packets to sniff (the 'count' parameter)
try:
    # this makes sure that an error is raised when a string or float value is entered instead of an int
    pkt_count = int(input('* Enter the number of packets to capture (0 is infinity): '))
except ValueError as error:
    print(error)
    sys.exit()
else:
    # In some situations, you might want to run a certain block of code if the code block inside try ran without any
    # errors. For these cases, you can use the optional else keyword with the try statement.
    if pkt_count < 0:  # packet count cannot be negative
        print('\nERROR: Packet count cannot be a negative number!\n')
        sys.exit()
    elif pkt_count > 0:  # packet count should either be a positive whole number or zero
        print(f'\nThe program will capture {pkt_count} packets.\n')
    else:  # this will execute only if the pkt_count is `0`
        print('\nThe program will capture packets until the timeout expires.\n')
# print(pkt_count)  # TODO: remove after testing

# Asking the user for the time interval to sniff (the 'timeout' parameter)
try:
    # this try-except block makes sure that an error is raised when a string or float value is passed
    pcap_timeout = int(input('* Enter the number of seconds to run the capture:'))
except ValueError as error:  # if an error is raised then exit the program
    print(error)
    sys.exit()
else:
    if pcap_timeout < 0 or pcap_timeout == 0:  # timeout cannot be negative or zero
        print('\nERROR: timeout cannot be less than or equal to 0\n')
        sys.exit()
    else:  # executes when timeout is a positive whole number
        print(f'\nThe program will capture packets for {pcap_timeout} seconds.\n')
# print(pcap_timeout)  # TODO: remove after testing

# Asking the user for any protocol filter he/she might want to apply to the sniffing process
# I chose four protocols: ARP, BOOTP, ICMP, and DNS
protocol = input('* Enter the protocol to filter by (arp | bootp | icmp | dns | 0 - is all): ')
if (protocol.lower() == 'arp') or (protocol.lower() == 'bootp') or (protocol.lower() == 'icmp') or (protocol.lower() == 'dns'):
    print(f'\nThe program will capture only {protocol.upper()} packets.')
elif protocol == '0':
    print('\nThe program will capture all protocols.\n')
else:
    print('\nERROR: input does not match any of these (arp | bootp | icmp | dns | 0 - is all)')
    sys.exit()
# print(protocol)  # TODO: remove after testing

try:
    # Asking the user to enter the name and path of the log file to be created
    file = input('* Please enter a complete path for the log file: ')
    # When working with files in text mode, it is highly recommended to specify the encoding type. , encoding='utf-8'
    pcap_log = open(file, 'a+', encoding='utf-8')
except IOError:
    print("\nAn IOError occurred while writing to the file")
    sys.exit()
except KeyboardInterrupt:
    print("User interrupted the execution, exiting...")
    sys.exit()
except Exception as error:
    print(f"\nAn exception occurred {error}")
    sys.exit()
else:
    # writing packet information to the specified log file
    def packet_log(pkt):
        if protocol == '0':
            print('Time: ' + str(datetime.now()) + ' Protocol: ALL' + ' SMAC: ' + pkt[0].src + ' DMAC: ' + pkt[0].dst, file=pcap_log)
        else:
            print('Time: ' + str(datetime.now()) + ' Protocol: ' + protocol.upper() + ' SMAC: ' + pkt[0].src + ' DMAC: ' + pkt[0].dst, file=pcap_log)

    print("\n* Starting the capture...")

    # Sniffing with or without filter
    if (protocol.lower() == 'arp') or (protocol.lower() == 'bootp') or (protocol.lower() == 'icmp') or (protocol.lower() == 'dns'):
        sniff(iface=interface, filter=protocol.lower(), count=pkt_count, timeout=pcap_timeout, prn=packet_log)
    else:
        sniff(iface=interface, count=pkt_count, timeout=pcap_timeout, prn=packet_log)

    print(f'\n* Please check {file} to see the captured packets.\n')
finally:
    # closing the file should be in finally block because if you write to a file without closing, the data won't make
    # it to the target file. This code block makes sure that the file is closed regardless of an exception.
    pcap_log.close()
