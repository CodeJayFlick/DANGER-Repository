Here is your Java code translated into Python:

```Python
import unittest
from ghidra.app.plugin import CodeBrowserPlugin
from ghidra.framework.datatree import DataTree
from ghidra.framework.model import Model
from ghidra.program.database import ProgramBuilder
from ghidra.util.task import TaskMonitor

class ToolActionManagerTest(unittest.TestCase):

    def setUp(self):
        self.frontEndTool = None
        self.env = None
        self.exportFile = 'untitled.tool'

    def testDeleteTool(self):
        create_tool()
        action = get_action("Untitled", "Delete Tool")
        perform_action(action, True)
        dialog = waitFor_dialog_component(OptionDialog.class)
        assertNotNone(dialog)
        assertEquals("Confirm Delete", dialog.getTitle())
        press_buttonByText(dialog.getComponent(), "Delete")

    def testDeleteToolFromIcon(self):
        create_tool()
        action = get_action("Delete Tool")
        perform_tool_button_action(action, True)

    # ... and so on for the rest of your tests

def create_tool():
    pass  # implement this method to create a tool

def get_actions_by_owner_and_name(tool, owner, name):
    return []  # implement this method to retrieve actions by owner and name

def perform_action(action, do_wait=False):
    if do_wait:
        run_swing()
    else:
        run_swing(False)

def run_swing(wait_time=1000):
    pass  # implement this method to simulate a GUI event loop

def wait_for_dialog_component(component_class):
    return None  # implement this method to wait for the specified dialog component

def press_buttonByText(button, text):
    pass  # implement this method to click on a button with the given text

# ... and so on for your other utility methods
```

Please note that I have not implemented all of the methods as they are specific to Java Swing GUI components. You would need to translate these into Python using a library like Tkinter or PyQt, depending on which one you prefer.

Also, please be aware that this is just an example translation and may require significant modifications based on your actual use case.