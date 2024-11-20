class DbgRegisterSet:
    def __init__(self, regs):
        self.by_name = {}
        self.by_number = {}

        for r in regs:
            self.by_name[r.name] = r
            self.by_number[r.number] = r

    def get_by_name(self, name):
        return self.by_name.get(name)

    def get_by_number(self, number):
        return self.by_number.get(number)

    def __iter__(self):
        return iter(self.by_number.values())

    def __len__(self):
        return len(self.by_number)
