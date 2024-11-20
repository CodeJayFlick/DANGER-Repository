class MsfStreamTable700:
    def __init__(self, msf):
        super().__init__(msf)

    def parse_extra_field(self, reader):
        # Do nothing
        pass

    def get_max_num_streams_allowed(self):
        return 0x10000


# Example usage:

if __name__ == "__main__":
    class AbstractMsf:
        pass

    msf = AbstractMsf()
    table700 = MsfStreamTable700(msf)
