__author__ = "milad"
from scapy.all import Ether, IP, TCP


class TCPConnection:
    """
    The class `TCPConnection` represents a TCP connection.
    """

    def __init__(self, seq):
        """
        - Initializes the object with an initial sequence number (`seq`)
        - Creates an empty dictionary `packets` to store packets associated with this connection.
        """
        self.packets = {}
        self.nextseq = seq

    def addpacket(self, pkt):
        """
        - Used to add a packet (`pkt`) to the `packets` dictionary.
        - It checks if the packet's sequence number already exists in the `packets` dictionary and if the packet has payload data. If both conditions are true, it returns `True`, indicating that the packet is a duplicate.
        - Updates the `packets` dictionary with the new packet
        - Returns `False`, if a new packet was added to the `packets` dictionary.
        """
        ret = False
        if pkt[TCP].seq in self.packets and len(str(pkt[TCP].payload)) > 0:
            ret = True
        self.packets[pkt[TCP].seq] = pkt
        return ret

    def getpacket(self):
        """
        `getpacket` method retrieves packets from the `TCPConnection` object's `packets` dictionary in the order of their sequence numbers. It continues retrieving packets until there are no more packets in sequence, and then returns the list of retrieved packets.
        """
        ret = []
        while True:
            if self.nextseq in self.packets:
                # print 'before',self.nextseq
                pkt = self.packets.get(self.nextseq)
                self.nextseq += len((pkt[TCP].payload))
                # print 'after',self.nextseq
                ret.append(pkt)
            else:
                break
        return ret
