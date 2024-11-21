class XCoffSymbol:
    NL = '\n'
    SYMSZ = 18
    SYMNMLEN = 8
    N_DEBUG = -2
    N_ABS = -1
    N_UNDEF = 0

    def __init__(self, reader, optional_header):
        self._optionalHeader = optional_header
        self.n_name = reader.read_next_byte_array(XCoffSymbol.SYMNMLEN)
        self.n_value = reader.read_next_int()
        self.n_scnum = reader.read_next_short()
        self.n_type = reader.read_next_short()
        self.n_sclass = reader.read_next_byte()
        self.n_numaux = reader.read_next_byte()

        if self.n_numaux > 0:
            aux = [reader.read_next_byte() for _ in range(XCoffSymbol.SYMSZ)]
            self.x_smclas = aux[-7]
        else:
            self.x_smclas = 0

    def is_long_name(self):
        return (self.n_name[0] == 0 and
                self.n_name[1] == 0 and
                self.n_name[2] == 0 and
                self.n_name[3] == 0)

    def get_name(self):
        if len(self.n_name) > XCoffSymbol.SYMNMLEN:
            return ''.join(map(chr, self.n_name)).strip()
        else:
            return ''.join(map(chr, self.n_name))

    def is_function(self):
        return ((self.n_sclass in [XCoffSymbolStorageClass.C_EXT,
                                    XCoffSymbolStorageClass.C_HIDEXT,
                                    XCoffSymbolStorageClass.C_WEAKEXT]) and
                (self.n_scnum == self._optionalHeader.get_section_number_for_text() or
                 self.n_name.lower().strip() != '_text'))

    def is_variable(self):
        return ((self.n_sclass in [XCoffSymbolStorageClass.C_EXT,
                                    XCoffSymbolStorageClass.C_HIDEXT,
                                    XCoffSymbolStorageClass.C_WEAKEXT]) and
                (self.n_scnum == self._optionalHeader.get_section_number_for_bss() or
                 self.n_scnum == self._optionalHeader.get_section_number_for_data()) and
                self.x_smclas not in [XCoffSymbolStorageClassCSECT.XMC_TC0,
                                       XCoffSymbolStorageClassCSECT.XMC_TC,
                                       XCoffSymbolStorageClassCSECT.XMC_DS] and
                self.n_name.lower().strip() != '_bss' and
                self.n_name.lower().strip() != '_data')

    def __str__(self):
        buffer = ''
        buffer += 'SYMBOL TABLE ENTRY\n'
        buffer += f'n_value  = {self.n_value}\n'
        buffer += f'n_scnum  = {self.n_scnum}\n'
        buffer += f'n_type  = {self.n_type}\n'
        buffer += f'n_sclass  = {self.n_sclass}\n'
        buffer += f'n_numaux  = {self.n_numaux}\n'
        return buffer
