Here is the translation of the given Java code into Python:

```Python
class ItemProgramInterfaceParser:
    ITEM_PROGRAM_INTERFACE_STREAM_NUMBER = 4

    def get_stream_number(self):
        return self.ITEM_PROGRAM_INTERFACE_STREAM_NUMBER


    def get_category(self):
        from enum import Enum
        class RecordCategory(Enum):
            ITEM = 'ITEM'
        
        return RecordCategory.ITEM


    @staticmethod
    def hack_check_no_name_for_stream(name_table):
        name = name_table.get_name_from_stream_number(ItemProgramInterfaceParser.ITEM_PROGRAM_INTERFACE_STREAM_NUMBER)
        if not name:
            return True
        else:
            return False

class NameTable:
    def get_name_from_stream_number(self, stream_number):
        # implement your logic here to retrieve the name from the given stream number
        pass


# usage example:

name_table = NameTable()
parser = ItemProgramInterfaceParser()

print(parser.get_stream_number())  # prints: 4

print(parser.get_category())  # prints: 'ITEM'

print(parser.hack_check_no_name_for_stream(name_table))  # prints: True or False
```

Please note that the Python code does not include any actual implementation of `NameTable` class as it was missing in the original Java code.