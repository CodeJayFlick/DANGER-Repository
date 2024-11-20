Here is the translation of the Java code into Python:

```Python
class DeleteReferencesAction:
    DEFAULT_MENU_ITEM_NAME = "Delete References"
    MEMORY_MENU_ITEM_NAME = "Delete Memory References"
    STACK_MENU_ITEM_NAME = "Delete Stack Reference"
    REGISTER_MENU_ITEM_NAME = "Delete Register Reference"
    EXTERNAL_MENU_ITEM_NAME = "Delete External Reference"

    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Delete References From", plugin.name)
        menu_data = MenuData([ReferencesPlugin.SUBMENU_NAME, DeleteReferencesAction.DEFAULT_MENU_ITEM_NAME], None, ReferencesPlugin.SHOW_REFS_GROUP)
        key_binding_data = KeyBindingData(KeyEvent.VK_DELETE, 0)
        description = "Delete all references from a code unit operand"
        self.set_popup_menu_data(menu_data)
        self.set_key_binding_data(key_binding_data)
        self.description = description

    def actionPerformed(self, context):
        op_index = ReferenceManager.MNEMONIC
        loc = context.location
        if isinstance(loc, OperandFieldLocation):
            op_index = loc.operand_index
        cmd = RemoveAllReferencesCmd(loc.address, op_index)
        self.plugin.get_tool().execute(cmd, context.program)

    def is_add_to_popup(self, context):
        return isinstance(context.location, CodeUnitLocation)

    def is_enabled_for_context(self, context):
        action_ok = False

        loc = context.location
        if not isinstance(loc, CodeUnitLocation):
            return False

        op_index = None
        if isinstance(loc, MnemonicFieldLocation):
            op_index = ReferenceManager.MNEMONIC
        elif isinstance(loc, OperandFieldLocation):
            op_index = loc.operand_index
        else:
            self.enabled = False
            return False

        refs = context.program.reference_manager.get_references_from(context.address, op_index)
        if len(refs) != 0:
            action_ok = True
            to_addr = refs[0].to_address
            if to_addr.is_memory_address():
                menu_item_name = DeleteReferencesAction.MEMORY_MENU_ITEM_NAME
            elif to_addr.is_external_address():
                menu_item_name = DeleteReferencesAction.EXTERNAL_MENU_ITEM_NAME
            elif refs[0].is_stack_reference():
                menu_item_name = DeleteReferencesAction.STACK_MENU_ITEM_NAME
            elif to_addr.is_register_address():
                menu_item_name = DeleteReferencesAction.REGISTER_MENU_ITEM_NAME
            else:
                action_ok = False

        return action_ok


class RemoveAllReferencesCmd:
    def __init__(self, address, op_index):
        pass  # This class is not implemented in the original Java code.


class MenuData:
    def __init__(self, menu_items, icon, group):
        self.menu_items = menu_items
        self.icon = icon
        self.group = group


class KeyBindingData:
    def __init__(self, key_code, modifiers):
        self.key_code = key_code
        self.modifiers = modifiers


class ReferencesPlugin:
    SUBMENU_NAME = "Submenu Name"
    SHOW_REFS_GROUP = None

    def get_tool(self):
        pass  # This method is not implemented in the original Java code.


# Usage example:

plugin = ReferencesPlugin()
action = DeleteReferencesAction(plugin)
context = ListingContext()  # Replace with your actual context
action.actionPerformed(context)