Here is a translation of the Java code into equivalent Python:

```Python
class ForwardSliceAction:
    def __init__(self):
        super().__init__("Highlight Forward Slice")
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ActionHighlight")
        self.popup_menu_data = MenuData(["Highlight", "Forward Slice"], "Decompile")

    def is_enabled_for_decompiler_context(self, context):
        token_at_cursor = context.get_token_at_cursor()
        varnode = DecompilerUtils().get_varnode_ref(token_at_cursor)
        return varnode is not None

    def decompiler_action_performed(self, context):
        token_at_cursor = context.get_token_at_cursor()
        varnode = DecompilerUtils().get_varnode_ref(token_at_cursor)
        if varnode is None:
            return
        op = token_at_cursor.get_pcode_op()
        forward_slice = DecompilerUtils().get_forward_slice(varnode)
        decompiler_panel = context.get_decompiler_panel()
        decompiler_panel.clear_primary_highlights()

        color_provider = SliceHighlightColorProvider(decompiler_panel, forward_slice, varnode, op)
        decompiler_panel.add_varnode_highlights(forward_slice, color_provider)

class HelpLocation:
    def __init__(self, topic, help_topic):
        self.topic = topic
        self.help_topic = help_topic

class MenuData:
    def __init__(self, items, label):
        self.items = items
        self.label = label

# Assuming these classes exist in DecompilerUtils module
from decompiler_utils import ClangToken, Varnode, PcodeOp, Set
```

Please note that this translation is not a direct conversion from Java to Python. The code has been adapted and modified to fit the syntax and structure of Python.