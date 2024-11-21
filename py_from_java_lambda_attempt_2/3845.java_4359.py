Here is a translation of the provided Java code into equivalent Python:

```Python
class CreateExternalFunctionAction:
    def __init__(self, name, plugin):
        self.plugin = plugin
        super().__init__(name)

        menu_data = MenuData([name], None, "FUNCTION_MENU_SUBGROUP", 0)
        key_binding_data = KeyBindingData(KeyEvent.VK_F, 0)
        help_location = HelpLocation("FunctionPlugin", "ExternalFunctions")
        
        set_popup_menu_data(menu_data)
        set_key_binding(key_binding_data)
        set_help_location(help_location)

    def get_external_code_symbol(self, listing_context):
        program = listing_context.get_program()
        selection = listing_context.get_selection()

        if selection and not selection.is_empty():
            return None

        location = listing_context.get_location()
        
        if isinstance(location, OperandFieldLocation):
            op_loc = location
            ref_mgr = program.get_reference_manager()
            ref = ref_mgr.get_primary_reference_from(op_loc.get_address(), op_loc.get_operand_index())
            
            if ref and ref.is_external_reference():
                s = program.get_symbol_table().get_primary_symbol(ref.get_to_address())

                if isinstance(s, Symbol) and s.get_symbol_type() == "LABEL":
                    return s
        return None

    def is_enabled_for_context(self, context):
        if isinstance(context, ListingActionContext):
            listing_context = context
            return self.get_external_code_symbol(listing_context)

        elif isinstance(context, ProgramSymbolActionContext):
            symbol_context = context
            
            if not symbol_context.get_symbols():
                return False
                
            for s in symbol_context.get_symbols():
                if not s.is_external() or s.get_symbol_type() != "LABEL":
                    return False
            return True

    def action_performed(self, context):
        compound_cmd = None
        
        if isinstance(context, ListingActionContext):
            listing_context = context
            cmd = CreateExternalFunctionCmd(self.get_external_code_symbol(listing_context))
            
        elif isinstance(context, ProgramSymbolActionContext):
            symbol_context = context
            
            for s in symbol_context.get_symbols():
                ext_func_cmd = CreateExternalFunctionCmd(s)
                
                if compound_cmd:
                    if not compound_cmd:
                        compound_cmd = CompoundCmd("Create External Functions")
                        compound_cmd.add(cmd)
                    compound_cmd.add(ext_func_cmd)
                else:
                    cmd = ext_func_cmd
        if not cmd:
            return  # assume all selected symbols have been deleted

        if compound_cmd:
            self.plugin.execute(context.get_program(), compound_cmd)
        else:
            self.plugin.execute(context.get_program(), cmd)

```

Please note that Python does not support direct translation of Java code. The provided Python code is an equivalent implementation based on the functionality and logic present in the original Java code.