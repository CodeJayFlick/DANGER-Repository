class DataTypeSymbol:
    def __init__(self, dt, nr, cat):
        self.sym = None
        self.datatype = dt
        self.nmroot = nr
        self.category = cat

    @property
    def symbol(self):
        return self.sym

    @symbol.setter
    def symbol(self, value):
        self.sym = value

    @property
    def address(self):
        if not hasattr(self.sym, 'getAddress'):
            raise AttributeError("Symbol does not have an 'address' attribute")
        return self.sym.getAddress()

    @property
    def data_type(self):
        return self.datatype

    def build_hashed_data_type(self, dtmanage):
        if isinstance(self.datatype, FunctionSignature) and dtmanage.contains(self.datatype):
            return None  # Signature is already in the manager, shouldn't change name
        elif not isinstance(self.datatype, (FunctionSignature, TypeDef)):
            return None  # Do not make typedef unless datatype is in our manager

        category_path = CategoryPath(self.category)
        hash_value = self.generate_hash(self.datatype)

        if dtmanage.contains(self.datatype):
            try:
                self.datatype.setNameAndCategory(category_path, "dt_" + hash_value)
            except (InvalidNameException, DuplicateNameException) as e:
                return None

        preexists = dtmanage.get_data_type(category_path, "dt_" + hash_value)

        if preexists is not None and preexists.is_equivalent(self.datatype):
            self.datatype = preexists
            return hash_value  # We are done
        else:
            return None  # Otherwise we can't proceed

    def build_symbol_name(self, hash_value, addr):
        return f"{self.nmroot}_{int(addr.get_offset(), 16)}_{hash_value}"

    def write_symbol(self, symtab, addr, namespace, dtmanage, clearold=False):
        if clearold:
            self.delete_symbols(symtab, namespace)

        hash_value = self.build_hashed_data_type(dtmanage)
        if hash_value is None:
            raise InvalidInputException("Unable to create datatype associated with symbol")

        sym_name = self.build_symbol_name(hash_value, addr)
        HighFunction.create_label_symbol(symtab, addr, sym_name, namespace, SourceType.USER_DEFINED, False)

    @staticmethod
    def delete_symbols(nmroot, addr, symtab, space):
        dellist = []
        iter = symtab.get_symbols(space)
        while iter.has_next():
            symbol = iter.next()
            if not symbol.name.startswith(nmroot) or symbol.symbol_type != SymbolType.LABEL:
                continue

            if symbol.address != addr:
                continue
            elif symbol.references:
                raise InvalidInputException("DataTypeSymbol has a reference")

            dellist.append(symbol)

        for s in dellist:
            s.delete()

    @staticmethod
    def read_symbol(cat, sym):
        if sym.symbol_type != SymbolType.LABEL:
            raise ValueError("Expected CODE symbol")
        hash_value = extract_hash(sym.name)
        nmroot = extract_name_root(sym.name)

        dtmanage = sym.program.data_type_manager

        datatype = dtmanage.get_data_type(CategoryPath(cat), f"dt_{hash_value}")
        if datatype is None or isinstance(datatype, TypeDef) and not (isinstance((datatype).get_base_datatype(), FunctionSignature)):
            return None

        res = DataTypeSymbol(datatype, nmroot, cat)
        res.sym = sym
        return res

    @staticmethod
    def generate_hash(dt):
        if isinstance(dt, FunctionSignature):
            material = dt.prototype_string
        elif isinstance(dt, TypeDef):
            material = (dt).get_data_type().path_name
        else:
            material = None  # No hash scheme

        hash_value = 0x12cf91ab  # Initial hash
        if material is not None:
            for char in material:
                hash_value = SimpleCRC32.hash_one_byte(hash_value, ord(char))

        return f"{hash_value:x}"

    @staticmethod
    def extract_hash(symname):
        last_index = symname.rfind('_')
        if last_index < 0:
            return None

        return symname[last_index + 1:]

    @staticmethod
    def extract_name_root(symname):
        first_index = symname.find('_')
        if first_index < 0:
            return ""

        return symname[:first_index]
