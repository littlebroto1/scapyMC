from scapy.all import *


def VarNumber(bits=32):
    class VarNumberClass(Field):
        __slots__ = ["length_of"]

        def __init__(self, name, default, length_of=None):
            Field.__init__(self, name, default, "B")
            self.length_of = length_of

        def str2extended(self, x=b""):
            # type: (bytes) -> Tuple[bytes, Optional[int]]

            value = 0b0
            byte_num = 0
            position = 0

            while True:
                byte = x[byte_num]
                value |= ((byte & 0x7F) << position)
                value &= 2**bits-1

                if (byte & 0x80) == 0:
                    break

                position += 7
                byte_num += 1
                if position >= bits:
                    raise RuntimeError("VarNumber is too big! Max Bits: ", bits)
            if value > 2**(bits-1)-1:
                value -= 2**bits

            return x[byte_num+1:], value

        def extended2str(self, x):
            # type: (Optional[int]) -> bytes
            s = b""
            if x is None:
                return s
            while True:
                if (x & ~0x7F) == 0:
                    s += bytes([x])
                    return s
                s += bytes([(x & 0x7F) | 0x80])
                x = (x >> 7) & ((2**bits-1) >> 7)

        def addfield(self, pkt, s, val):
            # type: (Optional[Packet], bytes, Optional[int]) -> bytes
            return s + self.i2m(pkt, val)

        def getfield(self, pkt, s):
            # type: (Optional[Any], bytes) -> Tuple[bytes, Optional[int]]
            return self.str2extended(s)

        def i2m(self, pkt, x):  # type: (Optional[Any], Optional[int]) -> bytes
            if x is None and pkt is not None:
                if self.length_of is not None:
                    fld, fval = pkt.getfield_and_val(self.length_of)
                    x = fld.i2len(pkt, fval)
            return self.extended2str(x)

        def m2i(self, pkt, x):  # type: (Optional[Packet], M) -> I
            return self.str2extended(x)[1]
    return VarNumberClass

