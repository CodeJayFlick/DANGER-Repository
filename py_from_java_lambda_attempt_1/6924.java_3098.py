Here is the translation of the given Java code into Python:

```Python
class RemoveEquateAction:
    def __init__(self):
        self.name = "Remove Equate"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionRemoveEquate")
        self.popup_menu_data = MenuData(["Remove Convert/Equate"], "Decompile")

    def is_enabled_for_decompiler_context(self, context):
        token_at_cursor = context.get_token_at_cursor()
        if not isinstance(token_at_cursor, ClangVariableToken):
            return False
        convert_vn = token_at_cursor.get_varnode()
        if convert_vn is None or not convert_vn.is_constant():
            return False
        symbol = convert_vn.get_high().get_symbol()
        return isinstance(symbol, EquateSymbol)

    def remove_reference(self, program, equate, ref_addr, convert_hash):
        transaction = program.start_transaction("Remove Equate Reference")
        try:
            if equate.get_reference_count() <= 1:
                program.get_equate_table().remove_equate(equate.get_name())
            else:
                equate.remove_reference(convert_hash, ref_addr)
        finally:
            program.end_transaction(transaction)

    def decompiler_action_performed(self, context):
        token_at_cursor = context.get_token_at_cursor()
        if not isinstance(token_at_cursor, ClangVariableToken):
            return
        convert_vn = token_at_cursor.get_varnode()
        if convert_vn is None or not convert_vn.is_constant():
            return
        symbol = convert_vn.get_high().get_symbol()
        if isinstance(symbol, EquateSymbol):
            program = context.get_program()
            equate_table = program.get_equate_table()
            address = symbol.get_pc_address()
            entry = symbol.get_first_whole_map()
            if not isinstance(entry, DynamicEntry):
                return
            convert_hash = entry.get_hash()
            for equate in equates:
                if equate.get_value() != convert_vn.get_offset():
                    continue
                self.remove_reference(program, equate, address, convert_hash)
                break

class HelpLocation:
    def __init__(self, topic, location):
        self.topic = topic
        self.location = location

class MenuData:
    def __init__(self, items, label):
        self.items = items
        self.label = label

class ClangVariableToken:
    def get_varnode(self):
        pass  # implement this method

class EquateSymbol:
    def get_pc_address(self):
        pass  # implement this method

class Program:
    def start_transaction(self, message):
        pass  # implement this method
    def end_transaction(self, transaction):
        pass  # implement this method
    def get_equate_table(self):
        pass  # implement this method
    def get_program(self):
        pass  # implement this method

class Varnode:
    def is_constant(self):
        pass  # implement this method
    def get_offset(self):
        pass  # implement this method

class HighSymbol:
    def get_symbol(self):
        pass  # implement this method

class EquateTable:
    def remove_equate(self, name):
        pass  # implement this method
    def get_equates(self, address):
        pass  # implement this method

class DynamicEntry:
    def get_hash(self):
        pass  # implement this method