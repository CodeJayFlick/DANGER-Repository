class ResourceTypes:
    TYPE_CF_RG = ord('c') + (ord('f') << 8) + (ord('r') << 16) + (ord('g') << 24)
    TYPE_STR_SPACE = ord('s') + (ord('t') << 8) + (ord('r') << 16) + (0x20 << 24)
    TYPE_STR_POUND = ord('s') + (ord('t') << 8) + (ord('r') << 16) + (ord('#') << 24)
    TYPE_ICON = ord('I') + (ord('C') << 8) + (ord('N') << 16) + (ord('#') << 24)

print(ResourceTypes.TYPE_CF_RG)
print(ResourceTypes.TYPE_STR_SPACE)
print(ResourceTypes.TYPE_STR_POUND)
print(ResourceTypes.TYPE_ICON)
