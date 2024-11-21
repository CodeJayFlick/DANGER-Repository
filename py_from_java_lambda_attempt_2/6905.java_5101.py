Here is the translation of the given Java code into equivalent Python:

```Python
class DeletePrototypeOverrideAction:
    def __init__(self):
        super().__init__("Remove Signature Override")
        self.set_help_location(HelpTopics.DECOMPILER, "ActionRemoveOverride")
        self.set_popup_menu_data(["Remove Signature Override"], "Decompile")

    @staticmethod
    def get_symbol(func, token_at_cursor):
        if token_at_cursor is None:
            return None

        addr = token_at_cursor.get_min_address()
        if addr is None:
            return None

        overspace = HighFunction.find_override_space(func)
        if overspace is None:
            return None

        symtab = func.get_program().get_symbol_table()
        iter = symtab.get_symbols(overspace)

        while iter.has_next():
            sym = iter.next()

            if not sym.name.startswith("prt"):
                continue
            elif not isinstance(sym, CodeSymbol):
                continue
            elif sym.address != addr:
                continue

            return sym

        return None

    def is_enabled_for_decompiler_context(self, context):
        func = context.get_function()
        if func is None or isinstance(func, UndefinedFunction):
            return False

        return self.get_symbol(func, context.get_token_at_cursor()) is not None

    def decompiler_action_performed(self, context):
        func = context.get_function()
        sym = self.get_symbol(func, context.get_token_at_cursor())
        program = func.get_program()
        symtab = program.get_symbol_table()

        transaction = program.start_transaction("Remove Override Signature")
        commit = True
        if not symtab.remove_symbol_special(sym):
            commit = False
            print(f"Error removing override signature: {sym.name}")

        program.end_transaction(transaction, commit)
```

Please note that Python does not have direct equivalent of Java's static methods. I've used a class method (`@staticmethod`) to achieve the same effect in this translation.