class CoffArchiveHeader:
    def __init__(self):
        self._first_linker_member = None
        self._second_linker_member = None
        self._long_name_member = None
        self._member_headers = []
        self.is_ms = False

    @staticmethod
    def is_match(provider):
        return provider.length() > CoffArchiveConstants.MAGIC_LEN and CoffArchiveConstants.MAGIC == bytes(provider.read(CoffArchiveConstants.MAGIC_LEN)).decode('utf-8')

    @staticmethod
    def read(provider, monitor=None):
        if not CoffArchiveHeader.is_match(provider):
            return None

        reader = BinaryReader(provider)
        member_num = 0
        eof_pos = provider.length() - CoffArchiveMemberHeader.CAMH_MIN_SIZE

        while reader.get_pointer_index() < eof_pos:
            if monitor and monitor.is_cancelled():
                break

            try:
                camh = CoffArchiveMemberHeader.read(reader, False)

                if camh.name == CoffArchiveMemberHeader.SLASH:
                    switch member_num:
                        case 0:
                            self._first_linker_member = FirstLinkerMember(reader, camh)
                            break
                        case 1:
                            self._second_linker_member = SecondLinkerMember(reader, camh)
                            break
                        default:
                            raise CoffException("Invalid COFF: multiple first and second linker members detected.")
                    elif camh.name == CoffArchiveMemberHeader.SLASH_SLASH:
                        if not hasattr(self, '_long_name_member'):
                            self._long_name_member = LongNamesMember(reader, camh)
                        else:
                            raise CoffException("Invalid COFF: multiple long name members detected.")

                self._member_headers.append(camh)
                member_num += 1

                reader.set_pointer_index(camh.payload_offset + camh.size)

            except IOException as e:
                if member_num <= 3:
                    raise
                print(f"Problem reading COFF archive headers in {provider.get_fsrl()}: only {member_num} members found.", file=sys.stderr)
                break

        self.is_ms = (self._first_linker_member and self._second_linker_member and self._long_name_member)

    def to_data_type(self):
        struct = StructureDataType(CoffArchiveHeader.__name__, 0)
        return struct

    @property
    def archive_member_headers(self):
        return self._member_headers

    @property
    def first_linker_member(self):
        return self._first_linker_member

    @property
    def second_linker_member(self):
        return self._second_linker_member

    @property
    def long_name_member(self):
        return self._long_name_member

    def is_ms_format(self):
        return self.is_ms


class CoffArchiveConstants:
    MAGIC = b'COFF'
    MAGIC_LEN = 4
