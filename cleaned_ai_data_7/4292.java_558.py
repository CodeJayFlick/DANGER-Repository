class SelectBackRefsAction:
    def __init__(self, tool):
        self.tool = tool
        
    def get_menu_bar_data(self):
        return {"Select", "Back Refs"}, None, "references"
    
    def get_key_binding_data(self):
        return {"key": ";", "modifiers": "ctrl"}
    
    def get_help_location(self):
        return HelpTopics.SELECTION, "Backward"

    def is_enabled_for_context(self, context):
        if hasattr(context, 'get_address'):
            address = getattr(context, 'get_address')()
            return address is not None
        elif hasattr(context, 'has_selection'):
            return context.has_selection()

    def perform_action(self, context):
        address_set = None
        
        if hasattr(context, 'has_selection'):
            selection = context.get_selection()
            address_set = selection
        else:
            address_set = AddressSet([context.get_address()])
        
        program = getattr(context, 'get_program')()
        selection = self.get_selection(program, address_set)
        NavigationUtils.set_selection(self.tool, context.get_navigatable(), selection)

    def get_selection(self, program, address_set):
        ref_addr_iter = program.reference_manager().reference_destination_iterator(address_set, True)
        
        while ref_addr_iter.has_next():
            reffed_addr = ref_addr_iter.next()
            
            mem_ref_iter = program.reference_manager().references_to(reffed_addr)
            while mem_ref_iter.has_next():
                mem_ref = mem_ref_iter.next()
                addr = mem_ref.get_from_address()
                
                if isinstance(addr, MemoryAddress):
                    address_set.add_range(addr, addr)

        return ProgramSelection(address_set)


class AddressSet:
    def __init__(self, addresses=None):
        self.addresses = addresses or []

    def add(self, *addresses):
        for address in addresses:
            self.addresses.append(address)

    def add_range(self, start, end):
        self.add(range(start, end+1))

    @property
    def ranges(self):
        return [(start, end) for start, end in zip(self.addresses[::2], self.addresses[1::2])]


class ProgramSelection:
    def __init__(self, address_set):
        self.address_set = address_set

    @property
    def selection(self):
        return self.address_set


# Example usage:
tool = PluginTool()  # Replace with your actual plugin tool instance.
action = SelectBackRefsAction(tool)
