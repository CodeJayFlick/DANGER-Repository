class LSDATable:
    def __init__(self):
        self.monitor = None
        self.program = None

    def create(self, table_addr, region_descriptor):
        region_descriptor.set_lsd_table(self)
        
        base_address = table_addr
        
        header = LSDAHeader(self.monitor, self.program, region_descriptor)
        header.create(table_addr)

        table_addr = header.get_next_address()

        call_site_table = LSDACallSiteTable(self.monitor, self.program, region_descriptor)
        call_site_table.create(table_addr)

        table_addr = call_site_table.get_next_address()

        max_action_offset = 0
        generate_action_table = False

        for cs in call_site_table.get_call_site_records():
            max_action_offset = max(max_action_offset, cs.get_action_offset())
            if cs.get_action_offset() != LSDAActionRecord.NO_ACTION:
                generate_action_table = True
        
        if generate_action_table:

            max_table_addr = table_addr.add(max_action_offset)

            action_table = LSDAActionTable(self.monitor, self.program, region_descriptor)
            action_table.create(table_addr, max_table_addr)

            table_addr = action_table.get_next_address()

        if header.get_t_type_encoding() != LSDAHeader.OMITTED_ENCODING_TYPE:
            
            t_type_base_address = header.get_t_type_base_address()
            if t_type_base_address != Address.NO_ADDRESS:
                type_table = LSDATypeTable(self.monitor, self.program, region_descriptor)
                type_table.create(t_type_base_address, table_addr)

        comment_cmd = SetCommentCmd(base_address, CodeUnit.PLATE_COMMENT, "Language-Specific Data Area")
        comment_cmd.apply_to(self.program)


class Address:
    def __init__(self):
        pass

    NO_ADDRESS = None


class Program:
    def __init__(self):
        pass

    PLATE_COMMENT = ""


class RegionDescriptor:
    def __init__(self, lsda_table=None):
        self.lsd_table = lsda_table

    def set_lsd_table(self, lsda_table):
        self.lsd_table = lsda_table
