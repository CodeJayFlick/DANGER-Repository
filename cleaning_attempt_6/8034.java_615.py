class RecordNumber:
    T_NOTYPE = 0
    T_VOID = 3

    NO_TYPE = TypeRecordNumber(T_NOType)

    @staticmethod
    def type_record_number(number):
        if number == T_NOTYPE:
            return NO_TYPE
        else:
            return TypeRecordNumber(number)

    @staticmethod
    def item_record_number(number):
        if number == T_NOTYPE:
            return NO_TYPE
        else:
            return ItemRecordNumber(number)

    @staticmethod
    def make(category, number):
        if category == 'TYPE':
            return type_record_number(number)
        elif category == 'ITEM':
            return item_record_number(number)
# TODO: for consideration... has implications... SymbolGroup iterator vs. RecordNumber
#         elif category == 'SYMBOL':
#             return symbol_record_number(number)

    @staticmethod
    def parse(pdb, reader, category, size):
        number = reader.parse_var_sized_int(size)
        record_number = make(category, number)
        pdb.get_pdb_reader_metrics().witness_record_number(record_number)
        return record_number

    # TODO: figure out the issues stated here... and revert to parse() method.
    @staticmethod
    def parse_no_witness(pdb, reader, category, size):
        number = reader.parse_var_sized_int(size)
        record_number = make(category, number)
        return record_number


class RecordNumber(ABC):
    def __init__(self, number):
        self.number = number

    def get_category(self):
        pass  # abstract method

    def get_number(self):
        return self.number

    def is_no_type(self):
        return self.number == T_NOTYPE

    def __str__(self):
        return f"{self.get_category().name()}[{self.get_number()}]"

    def __hash__(self):
        prime = 31
        result = 1
        result *= prime * (result + self.number)
        result *= prime * (result + hash(self.get_category()))
        return result

    def __eq__(self, other):
        if self is other:
            return True
        if other is None:
            return False
        if not isinstance(other, RecordNumber):
            return False
        record_number = cast(RecordNumber, other)
        if self.number != record_number.number or self.get_category() != record_number.get_category():
            return False
        return True


class TypeRecordNumber(RecordNumber):
    def __init__(self, number):
        super().__init__(number)

    def get_category(self):
        return 'TYPE'


class ItemRecordNumber(RecordNumber):
    def __init__(self, number):
        super().__init__(number)

    def get_category(self):
        return 'ITEM'
