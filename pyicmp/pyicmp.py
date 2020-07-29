
from .exceptions import *
from .utils import is_ipv6_address


class ICMPRequest:
    def __init__(self, destination, id, sequence, pktcontent=None,
            pktcontent_size=56, timeout=2, ttl=64):

        id &= 0xffff
        sequence &= 0xffff

        if pktcontent:
            pktcontent_size = len(pktcontent)

        self._destination = destination
        self._id = id
        self._sequence = sequence
        self._pktcontent = pktcontent
        self._pktcontent_size = pktcontent_size
        self._timeout = timeout
        self._ttl = ttl
        self._time = 0

    def __repr__(self):
        return f'<ICMPRequest [{self._destination}]>'

    @property
    def destination(self):
        '''
        The IP address of the gateway or host to which the message
        should be sent.

        '''
        return self._destination

    @property
    def id(self):
        '''
        The identifier of the request.
        Used to match the reply with the request.

        '''
        return self._id

    @property
    def sequence(self):
        '''
        The sequence number.
        Used to match the reply with the request.

        '''
        return self._sequence

    @property
    def pktcontent(self):
        '''
        The pktcontent content in bytes.
        Return `None` if the pktcontent is random.

        '''
        return self._pktcontent

    @property
    def pktcontent_size(self):
        '''
        The pktcontent size.

        '''
        return self._pktcontent_size

    @property
    def timeout(self):
        '''
        The maximum waiting time for receiving the reply in seconds.

        '''
        return self._timeout

    @property
    def ttl(self):
        '''
        The time to live of the packet in seconds.

        '''
        return self._ttl

    @property
    def time(self):
        '''
        The timestamp of the ICMP request.
        Initialized to zero when creating the request and replaced by
        `ICMPv4Socket` or `ICMPv6Socket` with the time of sending.

        '''
        return self._time


class ICMPReply:
    '''
    A class that represents an ICMP reply. Generated from an
    `ICMPSocket` object (`ICMPv4Socket` or `ICMPv6Socket`).

    :type source: str
    :param source: The IP address of the gateway or host that composes
        the ICMP message.

    :type id: int
    :param id: The identifier of the reply. Used to match the reply
        with the request.

    :type sequence: int
    :param sequence: The sequence number. Used to match the reply with
        the request.

    :type type: int
    :param type: The type of message.

    :type code: int
    :param code: The error code.

    :type bytes_received: int
    :param bytes_received: The number of bytes received.

    :type time: float
    :param time: The timestamp of the ICMP reply.

    '''
    def __init__(self, source, id, sequence, type, code,
            bytes_received, time):

        self._source = source
        self._id = id
        self._sequence = sequence
        self._type = type
        self._code = code
        self._bytes_received = bytes_received
        self._time = time

    def __repr__(self):
        return f'<ICMPReply [{self._source}]>'

    def raise_for_status(self):
        '''
        Throw an exception if the reply is not an ICMP ECHO_REPLY.
        Otherwise, do nothing.

        :raises ICMPv4DestinationUnreachable: If the ICMPv4 reply is
            type 3.
        :raises ICMPv4TimeExceeded: If the ICMPv4 reply is type 11.
        :raises ICMPv6DestinationUnreachable: If the ICMPv6 reply is
            type 1.
        :raises ICMPv6TimeExceeded: If the ICMPv6 reply is type 3.
        :raises ICMPError: If the reply is of another type and is not
            an ICMP ECHO_REPLY.

        '''
        if is_ipv6_address(self._source):
            echo_reply_type = 129
            errors = {
                1: ICMPv6DestinationUnreachable,
                3: ICMPv6TimeExceeded
            }

        else:
            echo_reply_type = 0
            errors = {
                3: ICMPv4DestinationUnreachable,
               11: ICMPv4TimeExceeded
            }

        if self._type in errors:
            raise errors[self._type](self)

        if self._type != echo_reply_type:
            message = f'Error type: {self._type}, ' \
                      f'code: {self._code}'

            raise ICMPError(message, self)

    @property
    def source(self):
        '''
        The IP address of the gateway or host that composes the ICMP
        message.

        '''
        return self._source

    @property
    def id(self):
        '''
        The identifier of the request.
        Used to match the reply with the request.

        '''
        return self._id

    @property
    def sequence(self):
        '''
        The sequence number.
        Used to match the reply with the request.

        '''
        return self._sequence

    @property
    def type(self):
        '''
        The type of message.

        '''
        return self._type

    @property
    def code(self):
        '''
        The error code.

        '''
        return self._code

    @property
    def bytes_received(self):
        '''
        The number of bytes received.

        '''
        return self._bytes_received

    @property
    def received_bytes(self):
        '''
        Deprecated: use the `bytes_received` property instead.

        '''
        # Warning in v1.2
        # Deletion in v2.0
        return self._bytes_received

    @property
    def time(self):
        '''
        The timestamp of the ICMP reply.

        '''
        return self._time


class Host:
    '''
    A class that represents a host. Simplifies the exploitation of
    results from `ping` and `traceroute` functions.

    :type address: str
    :param address: The IP address of the gateway or host that
        responded to the request.

    :type min_rtt: float
    :param min_rtt: The minimum round-trip time.

    :type avg_rtt: float
    :param avg_rtt: The average round-trip time.

    :type max_rtt: float
    :param max_rtt: The maximum round-trip time.

    :type packets_sent: int
    :param packets_sent: The number of packets transmitted to the
        destination host.

    :type packets_received: int
    :param packets_received: The number of packets sent by the remote
        host and received by the current host.

    '''
    def __init__(self, address, min_rtt, avg_rtt, max_rtt,
            packets_sent, packets_received):

        self._address = address
        self._min_rtt = round(min_rtt, 3)
        self._avg_rtt = round(avg_rtt, 3)
        self._max_rtt = round(max_rtt, 3)
        self._packets_sent = packets_sent
        self._packets_received = packets_received

    def __repr__(self):
        return f'<Host [{self._address}]>'

    @property
    def address(self):
        '''
        The IP address of the gateway or host that responded to the
        request.

        '''
        return self._address

    @property
    def min_rtt(self):
        '''
        The minimum round-trip time.

        '''
        return self._min_rtt

    @property
    def avg_rtt(self):
        '''
        The average round-trip time.

        '''
        return self._avg_rtt

    @property
    def max_rtt(self):
        '''
        The maximum round-trip time.

        '''
        return self._max_rtt

    @property
    def packets_sent(self):
        '''
        The number of packets transmitted to the destination host.

        '''
        return self._packets_sent

    @property
    def transmitted_packets(self):
        '''
        Deprecated: use the `packets_sent` property instead.

        '''
        # Warning in v1.2
        # Deletion in v2.0
        return self._packets_sent

    @property
    def packets_received(self):
        '''
        The number of packets sent by the remote host and received by
        the current host.

        '''
        return self._packets_received

    @property
    def received_packets(self):
        '''
        Deprecated: use the `packets_received` property instead.

        '''
        # Warning in v1.2
        # Deletion in v2.0
        return self._packets_received

    @property
    def packet_loss(self):
        '''
        Packet loss occurs when packets fail to reach their destination.
        Return a `float` between 0 and 1 (all packets are lost).

        '''
        if not self._packets_sent:
            return 0.0

        return 1 - self._packets_received / self._packets_sent

    @property
    def is_alive(self):
        '''
        Indicate whether the host is reachable. Return a `boolean`.

        '''
        return self._packets_received > 0


class Hop(Host):
    '''
    A class that represents a hop. It extends the `Host` class and adds
    some features for the `traceroute` function.

    :type address: str
    :param address: The IP address of the gateway or host that
        responded to the request.

    :type min_rtt: float
    :param min_rtt: The minimum round-trip time.

    :type avg_rtt: float
    :param avg_rtt: The average round-trip time.

    :type max_rtt: float
    :param max_rtt: The maximum round-trip time.

    :type packets_sent: int
    :param packets_sent: The number of packets transmitted to the
        destination host.

    :type packets_received: int
    :param packets_received: The number of packets sent by the remote
        host and received by the current host.

    :type distance: int
    :param distance: The distance (in terms of hops) that separates the
        remote host from the current machine.

    '''
    def __init__(self, address, min_rtt, avg_rtt, max_rtt,
            packets_sent, packets_received, distance):

        super().__init__(address, min_rtt, avg_rtt, max_rtt,
            packets_sent, packets_received)

        self._distance = distance

    def __repr__(self):
        return f'<Hop {self._distance} [{self._address}]>'

    @property
    def distance(self):
        '''
        The distance (in terms of hops) that separates the remote host
        from the current machine.

        '''
        return self._distance
