from datatypes.VarNumber import VarNumber


# Special implementation of MSBExtendedField; Reads at most 5 bytes
VarInt = VarNumber(bits=32)