Here is the translation of the given Java code into Python:

```Python
class NextPreviousLabelAction:
    def __init__(self, tool, owner, sub_group):
        super().__init__(tool, "Next Label", owner, sub_group)

    @property
    def icon(self):
        return ResourceManager.load_image("images/L.gif")

    @property
    def key_stroke(self):
        return KeyStroke(key=ord('L'), modifiers=KeyStroke.CONTROL_DOWN | KeyStroke.ALT_DOWN)

    @property
    def navigation_type_name(self):
        return "Label"

    def get_next_address(self, monitor, program, address):
        if not isinstance(address, Address):
            raise ValueError("Invalid address")
        
        next_code_unit = program.get_listing().get_code_unit_after(address)
        if next_code_unit is None:
            return None
        else:
            return next_code_unit.get_address()

    def get_previous_address(self, monitor, program, address):
        if not isinstance(address, Address):
            raise ValueError("Invalid address")
        
        previous_code_unit = program.get_listing().get_code_unit_before(address)
        if previous_code_unit is None:
            return None
        else:
            return previous_code_unit.get_address()

    def get_next_previous_label(self, monitor, program, address, forward=True):
        if not isinstance(address, Address):
            raise ValueError("Invalid address")
        
        next_defined_lable_address = self._get_next_defined_lable_address(program, address, forward)
        next_reference_to_address = self._get_next_reference_to_address(program, address, forward)

        if next_defined_lable_address is None:
            return next_reference_to_address
        elif next_reference_to_address is None:
            return next_defined_lable_address

        compare = next_defined_lable_address.compare(next_reference_to_address)
        
        if forward:
            return next_defined_lable_address if compare <= 0 else next_reference_to_address
        else:
            return next_defined_lable_address if compare >= 0 else next_reference_to_address

    def _get_next_reference_to_address(self, program, address, forward=True):
        reference_manager = program.get_reference_manager()
        iterator = reference_manager.get_reference_destination_iterator(address, forward)
        
        while iterator.has_next():
            current_address = iterator.next()
            if isinstance(current_address, Address):
                return current_address
        return None

    def _get_next_defined_lable_address(self, program, address, forward=True):
        symbol_table = program.get_symbol_table()
        iterator = symbol_table.get_symbol_iterator(address, forward)
        
        while iterator.has_next():
            current_symbol = iterator.next()
            if isinstance(current_symbol, Symbol) and hasattr(current_symbol, 'address'):
                return current_symbol.address
        return None

class ResourceManager:
    @staticmethod
    def load_image(image_name):
        # Implement your image loading logic here
        pass

class KeyStroke:
    CONTROL_DOWN = 0x0001
    ALT_DOWN = 0x0002
    
    def __init__(self, key=None, modifiers=0):
        self.key = key if isinstance(key, int) else ord(key)
        self.modifiers = modifiers

    @property
    def key(self):
        return chr(self._key)

    @key.setter
    def key(self, value):
        self._key = value if isinstance(value, int) else ord(value)

class Address:
    def __init__(self, address_value):
        self.address_value = address_value

    def get_address(self):
        return self.address_value

    def compare(self, other):
        # Implement your comparison logic here
        pass

class Symbol:
    def __init__(self, symbol_name):
        self.symbol_name = symbol_name

    @property
    def name(self):
        return self.symbol_name

    @name.setter
    def name(self, value):
        self.symbol_name = value

    @property
    def address(self):
        # Implement your address logic here
        pass

class SymbolTable:
    def __init__(self):
        self.symbols = []

    def get_symbol_iterator(self, start_address, forward=True):
        if not isinstance(start_address, Address):
            raise ValueError("Invalid start address")
        
        iterator = iter(self.symbols)
        current_address = None
        
        for symbol in iterator:
            if forward and (current_address is None or symbol.address > current_address):
                yield symbol
            elif not forward and (current_address is None or symbol.address < current_address):
                yield symbol
            
            current_address = symbol.address

class ReferenceManager:
    def __init__(self, program):
        self.program = program

    def get_reference_manager(self):
        # Implement your reference manager logic here
        pass

    def get_reference_destination_iterator(self, start_address, forward=True):
        if not isinstance(start_address, Address):
            raise ValueError("Invalid start address")
        
        iterator = iter([])
        current_address = None
        
        for reference in iterator:
            if forward and (current_address is None or reference.address > current_address):
                yield reference
            elif not forward and (current_address is None or reference.address < current_address):
                yield reference
            
            current_address = reference.address

class Program:
    def __init__(self, program_name):
        self.program_name = program_name
        self.get_listing()
        self.get_symbol_table()

    @property
    def listing(self):
        return self._listing

    @listing.setter
    def listing(self, value):
        if not isinstance(value, Listing):
            raise ValueError("Invalid listing")
        
        self._listing = value

    @property
    def symbol_table(self):
        return self._symbol_table

    @symbol_table.setter
    def symbol_table(self, value):
        if not isinstance(value, SymbolTable):
            raise ValueError("Invalid symbol table")
        
        self._symbol_table = value

class Listing:
    def __init__(self):
        pass

    def get_code_unit_after(self, address):
        # Implement your code unit logic here
        pass

    def get_code_unit_before(self, address):
        # Implement your code unit logic here
        pass

class CodeUnit:
    def __init__(self, cu_value):
        self.cu_value = cu_value

    @property
    def value(self):
        return self.cu_value

    @value.setter
    def value(self, value):
        self.cu_value = value

    @property
    def address(self):
        # Implement your code unit logic here
        pass