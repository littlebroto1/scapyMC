from scapy.all import *
from datatypes.VarInt import VarInt
from zlib import *


class MC(Packet):
    fields_desc = [
        VarInt("packet_length", None),
    ]

    def post_build(self, pkt, pay):  # type: (bytes, bytes) -> bytes
        if self.packet_length is None and pay:
            a = len(pay)  # len(pay) includes data_length
            p = self.get_field("packet_length").i2m(self, a)
            pkt = p + pkt  # prepend to start of pkt
        return pkt + pay

    @staticmethod
    def from_raw(s, threshold=-1):  # type: (bytes, int) -> PacketList
        compression = threshold >= 0
        packet_list = []
        while len(s) > 0:
            primary = MC(s)
            primary_raw = raw(primary.payload)

            s = primary_raw[primary.packet_length:]
            primary_raw = primary_raw[:primary.packet_length]

            # chooses whether to use the compression or not
            if compression:
                second_layer = MCCompression.from_raw(primary_raw, threshold)
            else:
                second_layer = MCID(primary_raw)

            primary.remove_payload()
            primary.add_payload(second_layer)
            packet_list.append(primary)

        return PacketList(packet_list)

    def to_raw(self: Packet, threshold=-1):  # type: (int) -> bytes
        s = b""
        second_packet = self.getlayer(MC, 2)
        if second_packet is not None:
            second_packet.underlayer.remove_payload()

        # TODO: Finish this method
        if self.haslayer(MCCompression):
            self[MCCompression].threshold = threshold
        s += raw(self)
        if second_packet is not None:
            s += second_packet.to_raw(threshold=threshold)

        return s


class MCCompression(Packet):
    fields_desc = [
        VarInt("data_length", None)
    ]

    __slots__ = ["threshold"]

    def __init__(self, pkt=b"", threshold=-1, **kwargs):
        self.threshold = threshold
        Packet.__init__(self, _pkt=pkt, **kwargs)

    @staticmethod
    def from_raw(s, threshold=-1):  # type: (bytes, int) -> MCCompression
        primary_layer = MCCompression(s)
        primary_raw = raw(primary_layer.payload)

        if primary_layer.data_length != 0:
            primary_raw = decompress(primary_raw)

        second_layer = MCID(primary_raw)

        primary_layer.remove_payload()
        primary_layer.add_payload(second_layer)

        return primary_layer

    def do_build_payload(self):  # type: () -> bytes
        pay = Packet.do_build_payload(self)
        pay_len = len(pay)
        if pay_len < self.threshold:
            pay_len = 0
        else:
            pay = compress(pay)

        if self.data_length is None:
            pay = self.get_field("data_length").i2m(self, pay_len) + pay  # make data_length 0
        return pay


class MCID(Packet):
    fields_desc = [
        VarInt("packet_id", None)
    ]
