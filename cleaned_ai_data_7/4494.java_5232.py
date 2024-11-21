class SubroutineMatch:
    def __init__(self, reason):
        self.prog_a_addrs = []
        self.prog_b_addrs = []
        self.reason = reason

    def add(self, addr, is_a):
        if is_a:
            self.prog_a_addrs.append(addr)
        else:
            self.prog_b_addrs.append(addr)

    def remove(self, addr, is_a):
        if is_a:
            self.prog_a_addrs = [x for x in self.prog_a_addrs if x != addr]
        else:
            self.prog_b_addrs = [x for x in self.prog_b_addrs if x != addr]

    def get_reason(self):
        return self.reason

    def get_a_addresses(self):
        return self.prog_a_addrs

    def get_b_addresses(self):
        return self.prog_b_addrs

    def is_one_to_one(self):
        return len(self.prog_a_addrs) == 1 and len(self.prog_b_addrs) == 1

    def __str__(self):
        str = f"{self.reason} "
        for addr in self.prog_a_addrs:
            str += f"{addr},"
        str += " --- "
        for addr in self.prog_b_addrs:
            str += f"{addr},"
        return str
