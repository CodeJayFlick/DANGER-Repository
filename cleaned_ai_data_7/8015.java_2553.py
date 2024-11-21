class NameTable:
    def __init__(self, pdb):
        self.pdb = pdb
        self.name_buffer_size = 0
        self.num_pairs = 0
        self.domain_size = 0
        self.present_list = []
        self.deleted_list = []
        self.names = []
        self.stream_numbers = []
        self.stream_numbers_by_name = {}
        self.names_by_stream_number = {}
        self.string_tables_by_stream_number = {}

    def get_name_from_stream_number(self, index):
        return self.names_by_stream_number.get(index)

    def get_stream_number_from_name(self, name):
        return self.stream_numbers_by_name.get(name)

    def get_name_string_from_offset(self, offset):
        if not hasattr(self, 'names_by_offset'):
            return None
        return self.names_by_offset.get(offset)

    def for_testing_only_add_offset_name_pair(self, offset, name):
        if not hasattr(self, 'names_by_offset'):
            self.names_by_offset = {}
        self.names_by_offset[offset] = name

    def deserialize_directory(self, reader, monitor):
        try:
            self.name_buffer_size = reader.read_int()
            name_buffer_reader = reader.get_sub_reader(name_buffer_size)
            self.num_pairs = reader.read_int()
            self.domain_size = reader.read_int()

            if self.num_pairs > 0x100000:
                raise PdbException("Num pairs too large.")

            if self.num_pairs < 0:
                raise PdbException("Illegal negative value.")

            self.names = [None] * self.num_pairs
            self.stream_numbers = [None] * self.num_pairs

            present_list_reader = reader.get_sub_reader()
            deleted_list_reader = reader.get_sub_reader()

            for i in range(self.num_pairs):
                monitor.check_canceled()
                buf_offset = reader.read_int()
                stream_number = reader.read_int()
                name_buffer_reader.set_index(buf_offset)
                name = name_buffer_reader.read_null_terminated_string(pdb.get_pdb_reader_options().get_one_byte_charset())
                self.stream_numbers[i] = stream_number
                self.names[i] = name
                self.names_by_stream_number[stream_number] = name
                self.stream_numbers_by_name[name] = stream_number

            self.deserialize_name_table_streams(monitor)
        except (IOException, PdbException) as e:
            raise e
        except CancelledException:
            pass

    def deserialize_name_table_streams(self, monitor):
        for stream_number in self.stream_numbers_by_name.values():
            try:
                reader = pdb.get_reader_for_stream_number(stream_number, monitor)
                if reader.read_unsigned_int() == 0xeffeeffe and reader.read_int() != 0:
                    switch reader.read_int():
                        case 1:
                            length = reader.read_int()
                            string_reader = reader.get_sub_reader(length)
                            while string_reader.has_more():
                                monitor.check_canceled()
                                offset = string_reader.index
                                name = string_reader.read_null_terminated_utf8_string()
                                self.names_by_offset[offset] = name
                        case 2:
                            pass
                    break
                else:
                    # Back up for nonexistent hdrMagic and hdrVer.
                    reader.set_index(reader.index - 8)
            except (IOException, PdbException) as e:
                raise e

        stream_number = self.stream_numbers_by_name.get("/names")
        self.names_by_offset = self.string_tables_by_stream_number[stream_number]

    def dump(self):
        builder = StringBuilder()
        builder.append("NameTable---------------------------------------------------\n")
        builder.append(f"nameBufferSize: {self.name_buffer_size}\n")
        builder.append(f"numPairs: {self.num_pairs}\n")
        builder.append(f"domainSize: {self.domain_size}\n")
        # TODO: output map entries for each table.
        return str(builder)
