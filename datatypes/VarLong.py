from datatypes.VarNumber import VarNumber


# Special implementation of MSBExtendedField; Reads at most 10 bytes
VarLong = VarNumber(bits=64)
