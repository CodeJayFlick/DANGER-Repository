import ghidra.program.model.data as Data
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Listing, DefinedDataIterator
from ghidra.program.model.mem import Mem

class NameStringPointersPlus(GhidraScript):
    def run(self) -> None:
        listing = self.currentProgram.getListing()
        data_iterator = listing.getDefinedData(True)
        
        while data_iterator.hasNext():
            data = data_iterator.next()
            
            if isinstance(data.getDataType(), Data.Pointer):
                value = Address.cast(data.getValue())
                
                name = get_string_from_pointer(value)
                
                if name is not None:
                    self.create_symbol_at_address(name, data.getAddress())

    def create_symbol_at_address(self, name: str, address: Address) -> None:
        try:
            name = name.replace(" ", "_")
            self.createLabel(address, name, True)
        except Exception as e:
            print(e.getMessage())
            
    def get_string_from_pointer(self, address: Address) -> str | None:
        data = self.get_data_at(address)

        if data is not None:
            value = data.getValue()
            
            if value is None and isinstance(data.getDataType(), Data.Structure):
                return self.get_name_from_struct(data)
                
            elif isinstance(value, str):
                return "sp_" + value
                
            elif isinstance(value, Address):
                name = data.getLabel() or ""
                return f"p_{name}"
                
        # this wasn't a pointer to string. Let's check for function pointer
        func = self.get_function_at(address)
        
        if func is not None:
            name = func.getName()
            
            if name is not None:
                return "fp_" + name
                
        data = self.get_undefined_data_at(address)

        if data is not None:
            name = data.getLabel() or ""
            
            if name is not None:
                return f"p_{name}"
                
    def get_name_from_struct(self, data: Data) -> str | None:
        name = None
        data_type_name = data.getDataType().getName()
        
        if data_type_name == "cfstringStruct":
            string_pointer_field = data.getComponent(2)
            
            if string_pointer_field is not None:
                value = string_pointer_field.getValue()
                
                if isinstance(value, Address):
                    address = Address.cast(string_pointer_field.getValue())
                    
                    data_string = self.get_data_at(address)
                    
                    name = f"sp_{data_string.getValue()}"
                    
        else:
            name = data.getLabel() or ""
            
            if name is not None:
                return f"p_{name}"
                
    def get_function_at(self, address: Address) -> Data.Function | None:
        # todo
        pass

    def get_undefined_data_at(self, address: Address) -> Data | None:
        # todo
        pass

    def createLabel(self, address: Address, name: str, isPublic: bool) -> None:
        # todo
        pass

    def get_data_at(self, address: Address) -> Data | None:
        # todo
        pass
