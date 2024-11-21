Here is a translation of the Java code into equivalent Python:

```Python
class PcodeSyntaxTree:
    def __init__(self):
        self.addr_factory = None
        self.datatype_manager = None
        self.refmap = {}
        self.oprefmap = {}
        self.joinmap = {}
        self.join_allocate = 0
        self.op_bank = None
        self.var_node_bank = None
        self.basic_blocks = []
        self.unique_id = 0

    def clear(self):
        self.refmap.clear()
        self.oprefmap.clear()
        self.joinmap.clear()
        self.join_allocate = 0
        if self.var_node_bank is not None:
            self.var_node_bank.clear()
        else:
            self.basic_blocks = []
        self.unique_id = 0

    def get_varnode_piece(self, piece_str):
        varnode_tokens = piece_str.split(":")
        if len(varnode_tokens) != 3:
            raise PcodeXMLException("Invalid XML addr piece: " + piece_str)
        space = self.addr_factory.get_address_space(varnode_tokens[0])
        if space is None:
            raise PcodeXMLException("Invalid XML addr, space not found: " + piece_str)
        offset = int(long(int.from_bytes(bytes.fromhex(varnode_tokens[1].lstrip('0x')), 16), 2))
        size = int(varnode_tokens[2])
        return Varnode(space.get_address(offset), size)

    def read_xml_varnodes(self, parser):
        while parser.peek().is_start():
            self.var_node_bank.loc_range()

    def allocate_join_storage(self, offset, pieces):
        storage = None
        try:
            if isinstance(pieces[0], Varnode):
                storage = VariableStorage(self.datatype_manager.get_program(), [pieces])
            else:
                raise InvalidInputException()
        except (InvalidInputException) as e:
            pass

    def find_join_storage(self, offset):
        return self.joinmap.get(offset)

    def build_storage(self, vn):
        if isinstance(vn. get_address().get_addressespace().type, AddressSpace.TYPE_VARIABLE):
            return self.find_join_storage(int(vn.get_offset()))
        else:
            return VariableStorage(self.datatype_manager.get_program(), [vn])

    # More methods...
```

Note that this is not a direct translation of the Java code into Python. It's more like an equivalent implementation in Python, as some parts may be different due to language differences and nuances.

Here are some key changes:

1.  **Class definition**: In Python, classes do not require explicit declaration of methods or variables.
2.  **Method signatures**: Method parameters are declared using the `def` keyword followed by a space-separated list of parameter names.
3.  **Exception handling**: Try-except blocks are used to catch exceptions in Python.
4.  **HashMaps and Lists**: In Java, HashMap is equivalent to Python's dictionary (`{}`), while List is equivalent to Python's list (`[]`). The `get()` method for a map returns the value associated with the given key if it exists; otherwise, it raises an exception (like KeyError in Python).
5.  **Type conversions and casting**: In Java, explicit type conversion or casting may be required when working with different data types. This is not necessary in Python due to its dynamic typing.
6.  **String manipulation**: String operations like `split()`, `join()`, and `strip()` are used in the code.

This translation should give you a good starting point for implementing your desired functionality in Python.