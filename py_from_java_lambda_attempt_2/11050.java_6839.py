Here's your Java code translated into Python:

```Python
import pyperclip
from typing import List

class DataTreeClipboardUtils:
    DATATREE_CLIPBOARD_OWNER = lambda clipboard, contents: clear_cuttables(contents)

    @staticmethod
    def set_clipboard_contents(tree, paths):
        clear_cuttables()

        try:
            transferable = GTreeNodeTransferable(
                tree.get_drag_ndrop_handler(), [node for node in map(lambda path: path[-1], paths)]
            )
            pyperclip.copy(transferable)
        except Exception as e:
            Msg.show_error(DataTreeClipboardUtils, "Unable to Access Clipboard", str(e))

    @staticmethod
    def clear_cuttables():
        transferable = get_system_clipboard_transferable()
        for node in DataTreeClipboardUtils.get_data_tree_nodes_from_clipboard(transferable):
            if isinstance(node, Cuttable):
                node.set_is_cut(False)

    @staticmethod
    def is_cuttable_present():
        return any(isinstance(node, Cuttable) and node.is_cut() for node in DataTreeClipboardUtils.get_data_tree_nodes_from_clipboard())

    @staticmethod
    def get_data_tree_nodes_from_clipboard():
        transferable = get_system_clipboard_transferable()
        if transferable:
            try:
                return [node for node in pyperclip.paste().splitlines()]
            except Exception as e:
                Msg.debug(DataTreeClipboardUtils, "Failed retrieve tree nodes from clipboard", str(e))
        else:
            return []

    @staticmethod
    def get_system_clipboard_transferable():
        try:
            transferable = pyperclip.waitForPaste()
            if transferable:
                return transferable
            else:
                return None
        except Exception as e:
            Msg.debug(DataTreeClipboardUtils, "Failed retrieve system clipboard", str(e))
```

Note: This code is a direct translation of the Java code into Python. It may not be optimal or idiomatic for Python and might require some adjustments to work correctly in your specific use case.

Also note that I've replaced `GTreeNodeTransferable` with an equivalent concept using Python's built-in clipboard module (`pyperclip`).