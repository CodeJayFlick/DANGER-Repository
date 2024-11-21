import pyghidra.datatypemanager as datatype_manager
from typing import List

class ClearCutAction:
    def __init__(self, plugin: datatype_manager.DataTypeManagerPlugin):
        self.clipboard = plugin.get_clipboard()
        super().__init__("Clear Cut", plugin.name)
        self.set_key_binding_data({"key": "Escape", "modifiers": 0})
        self.enabled = True

    def is_enabled_for_context(self, context) -> bool:
        return True

    def perform_action(self, context):
        transferable = self.clipboard.get_contents()
        if isinstance(transferable, datatype_manager.GTreeNodeTransferable):
            gt_transferable = transferable
            node_list: List[datatype_manager.GTreeNode] = gt_transferable.get_all_data()
            if not node_list:
                return
            node = node_list[0]
            if node.is_cut():
                self.clipboard.set_contents(None, None)
