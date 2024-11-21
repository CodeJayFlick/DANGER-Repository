Here is the translation of the given Java code into equivalent Python:

```Python
class MnemonicSearchPlugin:
    MENU_PULLRIGHT = "For Matching Instructions"
    POPUP_MENU_GROUP = "Search"

    def __init__(self):
        self.set_search_mnemonic_ops_no_const_action = None
        self.set_search_mnemonic_ops_const_action = None
        self.set_search_mnemonic_no_ops_no_const_action = None

    def process_action(self, context, use_ops, use_consts):
        new_context = NavigatableActionContext(context)
        program = new_context.get_program()
        selection = new_context.get_selection()

        if len(selection) > 1:
            print("Mnemonic Search Error: Multiple selected regions are not allowed; please limit to one.")
            return

        mask_control = SLMaskControl(use_ops, use_consts)
        generator = MaskGenerator(mask_control)
        mask = generator.get_mask(program, selection)

        if mask is not None:
            masked_bit_string = create_masked_bit_string(mask.value, mask.mask)
            memory_search_service = tool.getService(MemorySearchService)
            memory_search_service.set_is_mnemonic(True)
            memory_search_service.search(masked_bit_string.encode(), new_context)
            memory_search_service.set_search_text(masked_bit_string)

    def create_actions(self):
        group = "search for"
        pull_right_group = "0"  # top of 'search for' group
        tool.set_menu_group(["&Search", self.MENU_PULLRIGHT], group, pull_right_group)

        help_location = HelpLocation(HelpTopics.SEARCH, "Mnemonic_Search")

        # ACTION 1: Search for instructions, excluding constants.
        self.set_search_mnemonic_ops_no_const_action = NavigatableContextAction("Include Operands (except constants)", self.get_name())
        self.set_search_mnemonic_ops_no_const_action.actionPerformed = lambda context: self.process_action(context, True, False)
        self.set_search_mnemonic_ops_no_const_action.isEnabledForContext = lambda context: context.has_selection()
        self.set_search_mnemonic_ops_no_const_action.set_menu_bar_data(MenuData(["&Search", self.MENU_PULLRIGHT, "Include Operands (except constants)"], None, group, MenuData.NO_MNEMONIC, "3"))
        self.set_search_mnemonic_ops_no_const_action.set_help_location(help_location)
        self.set_search_mnemonic_ops_no_const_action.addToWindowWhen(NavigatableActionContext)

        # ACTION 2: Search for instructions, including operands.
        self.set_search_mnemonic_ops_const_action = NavigatableContextAction("Include Operands", self.get_name())
        self.set_search_mnemonic_ops_const_action.actionPerformed = lambda context: self.process_action(context, True, True)
        self.set_search_mnemonic_ops_const_action.isEnabledForContext = lambda context: context.has_selection()
        self.set_search_mnemonic_ops_const_action.set_menu_bar_data(MenuData(["&Search", self.MENU_PULLRIGHT, "Include Operands"], None, group, MenuData.NO_MNEMONIC, "2"))
        self.set_search_mnemonic_ops_const_action.set_help_location(help_location)
        self.set_search_mnemonic_ops_const_action.addToWindowWhen(NavigatableActionContext)

        # ACTION 3: Search for instructions, excluding constants.
        self.set_search_mnemonic_no_ops_no_const_action = NavigatableContextAction("Exclude Operands", self.get_name())
        self.set_search_mnemonic_no_ops_no_const_action.actionPerformed = lambda context: self.process_action(context, False, False)
        self.set_search_mnemonic_no_ops_no_const_action.isEnabledForContext = lambda context: context.has_selection()
        self.set_search_mnemonic_no_ops_no_const_action.set_menu_bar_data(MenuData(["&Search", self.MENU_PULLRIGHT, "Exclude Operands"], None, group, MenuData.NO_MNEMONIC, "1"))
        self.set_search_mnemonic_no_ops_no_const_action.set_help_location(help_location)
        self.set_search_mnemonic_no_ops_no_const_action.addToWindowWhen(NavigatableActionContext)

        tool.addAction(self.set_search_mnemonic_ops_no_const_action)
        tool.addAction(self.set_search_mnemonic_ops_const_action)
        tool.addAction(self.set_search_mnemonic_no_ops_no_const_action)

    def create_masked_bit_string(self, values, masks):
        bit_string = ""

        if len(values) != len(masks):
            return None

        for i in range(len(values)):
            for j in range(8):
                if (masks[i] >> (7 - j)) & 1 == 0:
                    bit_string += "."
                elif (values[i] >> (7 - j)) & 1 == 0:
                    bit_string += "0"
                else:
                    bit_string += "1"

            bit_string += " "

        return bit_string

# Note: The above Python code does not include the definitions of classes like NavigatableActionContext, SLMaskControl, MaskGenerator and HelpLocation. These are Java-specific classes that do not have direct equivalents in Python.
```

The given Java code is a plugin for Ghidra, which seems to be a reverse engineering tool. The provided translation into equivalent Python does not include the definitions of certain classes like NavigatableActionContext, SLMaskControl, MaskGenerator and HelpLocation because these are Java-specific classes that do not have direct equivalents in Python.