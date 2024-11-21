class AbstractSymbolInformation:
    HEADER_SIGNATURE = 0xffffffff
    GSI70 = 0xeffe0000 + 19990810  # 0xf12f091a = -248575718

    def __init__(self, pdb_in):
        self.pdb = pdb_in
        self.num_hash_records = None
        self.num_extra_bytes = None
        self.hash_records_bit_map_length = None
        self.header_signature = None
        self.version_number = None
        self.hash_records_length = None
        self.buckets_length = None

    def get_symbols(self):
        return self.symbols

    def get_modified_hash_record_symbol_offsets(self):
        return self.modified_hash_record_symbol_offsets

    def deserialize(self, stream_number, monitor):
        if self.pdb.has_minimal_debug_info():
            self.hash_records_bit_map_length = 0x8000
            self.num_extra_bytes = 0  # I believe;
            self.num_hash_records = 0x3ffff
        else:
            self.hash_records_bit_map_length = 0x200
            self.num_extra_bytes = 4
            self.num_hash_records = 0x1000

    def dump(self, writer):
        builder = StringBuilder()
        builder.append("AbstractSymbolInformation-----------------------------------\n")
        self.dump_hash_header(builder)
        self.dump_hash_basics(builder)
        self.dump_hash_records(builder)
        builder.append("\nEnd AbstractSymbolInformation-------------------------------\n")
        writer.write(builder.toString())

    def dump_hash_basics(self, builder):
        builder.append("HashBasics--------------------------------------------------\n")
        builder.append(f"hashRecordsBitMapLength: {self.hash_records_bit_map_length}\n")
        builder.append(f"numExtraBytes: {self.num_extra_bytes}\n")
        builder.append(f"numHashRecords: {self.num_hash_records}\n")
        builder.append("\nEnd HashBasics----------------------------------------------\n")

    def dump_hash_header(self, builder):
        builder.append("HashHeader--------------------------------------------------\n")
        builder.append(f"headerSignature: {self.header_signature}\n")
        builder.append(f"versionNumber: {self.version_number}\n")
        builder.append(f"lengthHashRecords: {self.hash_records_length}\n")
        builder.append(f"lengthBuckets: {self.buckets_length}\n")
        builder.append("\nEnd HashHeader----------------------------------------------\n")

    def generate_symbols_list(self, monitor):
        self.symbols = []
        symbols_by_offset = self.pdb.get_debug_info().get_symbols_by_offset()
        for record in self.hash_records:
            monitor.check_canceled()
            offset = record.offset - 2  # Modified offset
            symbol = symbols_by_offset.get(offset)
            if symbol is None:
                raise PdbException("PDB corrupted")
            self.modified_hash_record_symbol_offsets.append(offset)
            self.symbols.append(symbol)

    def dump_hash_records(self, builder):
        builder.append("HashRecords-------------------------------------------------\n")
        builder.append(f"numHashRecords: {len(self.hash_records)}\n")
        for record in self.hash_records:
            builder.append(
                f"{record.offset:08X}  {record.reference_count}\n"
            )
        builder.append("\nEnd HashRecords---------------------------------------------\n")

    def deserialize_hash_table(self, reader, monitor):
        if self.header_signature == self.HEADER_SIGNATURE:
            switch = {
                GSI70: lambda: self.deserialize_gsi_7_0_hash_table(reader, monitor),
                # default: raise PdbException("Unknown GSI Version Number"),
            }
            switch[self.version_number]()
        else:
            reader.reset()  # There was no header
            self.deserialize_gsi_pre_70_hash_table(reader, monitor)

    def deserialize_hash_header(self, reader):
        if not reader.has_more():
            return

        self.header_signature = reader.parse_unsigned_int_val()
        self.version_number = reader.parse_unsigned_int_val()
        self.hash_records_length = reader.parse_unsigned_int_val()
        self.buckets_length = reader.parse_unsigned_int_val()

    def deserialize_gsi_7_0_hash_table(self, reader, monitor):
        if not reader.has_more():
            return

        hash_records_reader = reader.get_sub_reader(reader.num_remaining() - 4)
        buckets_reader = reader.get_sub_reader(4)

        self.deserialize_compressed_hash_buckets(buckets_reader, monitor)

    def deserialize_gsi_pre_70_hash_table(self, reader, monitor):
        if not reader.has_more():
            return

        num_buckets_bytes = (self.num_hash_records + 1) * 4
        if reader.num_remaining() < num_buckets_bytes:
            raise PdbException("Not enough data for GSI")

        buckets_reader = reader.get_sub_reader(num_buckets_bytes)
        hash_records_reader = reader.get_sub_reader(reader.num_remaining())

    def deserialize_compressed_hash_buckets(self, reader, monitor):
        bit_encoder_reader = reader.get_sub_reader(4)

        while reader.has_more() and bit_encoder_reader.has_more():
            val = bit_encoder_reader.parse_unsigned_int_val()
            for _ in range(32):
                if (val & 0x01) == 0x01:
                    self.hash_bucket_offsets.append(reader.parse_unsigned_int_val())
                else:
                    self.hash_bucket_offsets.append(-1)
                val >>= 1

        if reader.has_more():
            raise PdbException("Compressed GSI Hash Buckets corrupt")

    def deserialize_hash_records(self, reader):
        self.hash_records = []
        while reader.has_more():
            record = SymbolHashRecord()
            record.parse(reader)
            self.hash_records.append(record)

class SymbolHashRecord:
    def __init__(self):
        pass

    def parse(self, reader):
        if not reader.has_more():
            return
