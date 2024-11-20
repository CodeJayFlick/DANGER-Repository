class PeUtils:
    @staticmethod
    def get_markup_address(program: 'Program', is_binary: bool, nt_header: dict, offset: int) -> Address:
        space = program.get_default_address_space()
        if is_binary:
            ptr = nt_header['rva_to_pointer'](offset)
            if ptr < 0 and offset > 0:
                print(f"Invalid RVA {hex(offset)}")
                return space.get_address(offset)
            else:
                return space.get_address(ptr)
        else:
            return space.get_address(offset + nt_header['optional_header']['image_base'])

    @staticmethod
    def create_data(program: 'Program', addr: Address, datatype: dict, log: list) -> Data or None:
        existing_data = program.get_listing().get_defined_data_at(addr)
        if existing_data is not None:
            existing_datatype = existing_data['datatype']
            if existing_datatype == datatype:
                return existing_data
        try:
            program.get_listing().create_data(addr, datatype)
            return program.get_listing().get_defined_data_at(addr)
        except Exception as e:
            log.append(f"Failed to create {datatype} at {addr}: {str(e)}")
        return None

    @staticmethod
    def create_data(program: 'Program', addr: Address, datatype: dict, length: int, log: list) -> None or None:
        try:
            program.get_listing().create_data(addr, datatype, length)
        except Exception as e:
            log.append(str(e))
