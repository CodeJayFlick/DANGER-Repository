class StaticDisassembleAction:
    def __init__(self, plugin, group_name):
        self.plugin = plugin
        super().__init__("Disassemble Static", plugin.name)

    @property
    def popup_menu_data(self):
        return {"menu_items": ["Disassemble (Static)"], "group_name": group_name}

    def run(self, context):
        self.plugin.disassemble_static_callback(context)


class DisassemblerPlugin:
    pass


# Usage example:

plugin = DisassemblerPlugin()
action = StaticDisassembleAction(plugin, "My Group")
