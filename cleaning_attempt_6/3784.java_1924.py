class ContextAction:
    def __init__(self, plugin: 'DisassemblerPlugin', group_name: str):
        super().__init__("Processor Options", plugin.name)
        self.plugin = plugin
        popup_menu_data = {'menu_items': ['Processor Options...'], 'group_name': group_name}
        set_popup_menu_data(popup_menu_data)

    def get_help_location(self) -> dict:
        return {"topic": "DisassemblerPlugin", "section": "ProcessorOptions"}

    def action_performed(self, context: 'ListingActionContext'):
        self.plugin.set_default_context(context)

    def is_enabled_for_context(self, context: 'ListingActionContext') -> bool:
        program = context.get_program()
        return self.plugin.has_context_registers(program)
