class MachineName:
    @staticmethod
    def get_name(machine):
        if isinstance(machine, int) or isinstance(machine, float):
            return str(int(machine))
        elif isinstance(machine, int):
            return "0x{:X}".format(machine)
        else:
            raise ValueError("Invalid machine type")
