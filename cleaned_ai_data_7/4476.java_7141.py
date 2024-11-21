class LSDACallSiteTable:
    def __init__(self):
        self.bounds = None
        self.next_address = None
        self.region = None
        self.records = []

    def create(self, monitor, program, region):
        if not self.bounds and not self.next_address:
            return

        records.clear()

        header = region.get_lsd_table().get_header()
        if header.get_call_site_table_length() <= 0:
            return

        base_addr = addr
        monitor.set_message("Creating GCC LSDA Call Site Table")
        comment_cmd = SetCommentCmd(base_addr, CodeUnit.PLATE_COMMENT, "(LSDA) Call Site Table")
        comment_cmd.apply_to(program)

        limit = base_addr + header.get_call_site_table_length() - 1

        call_site_decoder = DwarfDecoderFactory().get_decoder(header.get_call_site_table_encoding())

        remain = limit - addr
        while remain > 0:
            rec = LSDACallSiteRecord(monitor, program, region)
            rec.create(addr, call_site_decoder)

            verify_call_site_record(rec)

            records.append(rec)

            addr = rec.next_address()
            remain -= (limit - addr)

        self.bounds = AddressRangeImpl(base_addr, base_addr + header.get_call_site_table_length())
        self.next_address = addr

    def get_table_end_address(self):
        return self.bounds.max_address()

    def get_next_address(self):
        return self.next_address

    def get_call_site_records(self):
        return records


class SetCommentCmd:
    def __init__(self, base_addr, code_unit_plate_comment, comment_text):
        self.base_addr = base_addr
        self.code_unit_plate_comment = code_unit_plate_comment
        self.comment_text = comment_text

    def apply_to(self, program):
        # implement the logic to set a comment in the given program


class AddressRangeImpl:
    def __init__(self, min_address, max_address):
        self.min_address = min_address
        self.max_address = max_address

    @property
    def get_min_address(self):
        return self.min_address

    @property
    def get_max_address(self):
        return self.max_address


class LSDACallSiteRecord:
    def __init__(self, monitor, program, region):
        self.monitor = monitor
        self.program = program
        self.region = region
        self.next_address = None

    def create(self, addr, call_site_decoder):
        # implement the logic to create a record


def verify_call_site_record(rec):
    body = rec.get_region().get_range()

    if not contains(body, rec.get_call_site()):
        Msg.error("Function body does not fully contain the call site area")
    if not contains(body, rec.get_landing_pad()):
        Msg.error("Function body does not contain the landing pad")


def contains(container, child):
    return container.min_address <= child.min_address and container.max_address >= child.max_address


class DwarfDecoderFactory:
    def get_decoder(self, encoding):
        # implement the logic to create a decoder based on the given encoding
