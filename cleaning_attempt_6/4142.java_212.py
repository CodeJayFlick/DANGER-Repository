class ShowInstructionInfoPlugin:
    def __init__(self):
        self.connected_provider = None
        self.disconnected_providers = []
        self.instruction_label = None
        self.function_label = None
        self.address_label = None
        self.go_to_service = None

    @property
    def instruction_label(self):
        return self._instruction_label

    @instruction_label.setter
    def instruction_label(self, value):
        self._instruction_label = value

    # ... other properties and methods ...

class ShowInfoAction:
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
        self.set_popup_menu_data(['Instruction Info...'], None, 'Disassembly')

    @property
    def plugin(self):
        return self._plugin

    @plugin.setter
    def plugin(self, value):
        self._plugin = value

    # ... other methods ...

class ShowProcessorManualAction:
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
        set_menu_bar_data(['Tools', 'Processor Manual...'], None, 'Disassembly')
        set_popup_menu_data(['Processor Manual...'], None, 'Disassembly')

    @property
    def plugin(self):
        return self._plugin

    @plugin.setter
    def plugin(self, value):
        self._plugin = value

    # ... other methods ...

def create_status_panels():
    instruction_panel = JPanel(BoxLayout.Y_AXIS)
    address_label = JLabel("                          ")
    function_label = JLabel("                    ")

class browse_instruction(context):
    if is_dynamic:
        create_or_show_connected_provider()
        connected_provider.set_program(current_program)
        connected_provider.set_address(context.get_address())
    else:
        provider = InstructionInfoProvider(self, False)
        provider.set_program(context.get_program())
        provider.show()

def get_valid_url(file_url):
    # ... implementation ...

class locate_manual_entry(language):
    if language == null || context == null: return null
    instruction = None
    if isinstance(context, ListingActionContext): instruction = get_instruction_for_context((ListingActionContext)context)
    mnemonic_string = instruction.get_mnemonic_string() if instruction else None

def build_missing_manual_message():
    # ... implementation ...

class InstructionInfoProvider:
    def __init__(self):
        self.program = None
        self.address = None

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

def get_instruction_for_context(context):
    # ... implementation ...

class GoToService:
    def go_to(self):  # ... implementation ...
