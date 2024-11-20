def htonl(value):
    return [(value >> i) & 0xFF for i in range(24, -1, -8)]
