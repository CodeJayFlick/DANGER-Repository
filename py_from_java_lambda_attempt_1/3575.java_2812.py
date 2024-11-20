Here's a translation of your Java code into equivalent Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class CreateInternalStructureAction:
    ICON = None  # Initialize with None for now
    
    ACTION_NAME = "Create Structure From Selection"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"
    DESCRIPTION = f"Create a new structure from the selected components and replace them with it."
    
    def __init__(self, provider):
        self.provider = provider
        self.model = provider.get_model()
        
    def actionPerformed(self, context):
        selected_component_rows = self.model.get_selected_components()
        has_component_selection = self.model.has_component_selection()
        contiguous_component_selection = self.model.is_contiguous_component_selection()
        
        if (has_component_selection and contiguous_component_selection 
                and len(selected_component_rows) > 0):
            selected_component_rows.sort()
            
            num_components = self.model.get_num_components()
            max_row = selected_component_rows[-1]
            
            if max_row < num_components:
                TaskLauncher().launch_modal(self.ACTION_NAME, self.do_create)
        
        request_table_focus()

    def do_create(self, monitor):
        try:
            (self.model).create_internal_structure(monitor)
        except CancelledException as e:
            # user cancelled
            pass
        except UsrException as e:
            self.model.set_status(e.message, True)

    def adjust_enablement(self):
        self.enabled = self.is_create_internal_structure_allowed()

    def is_create_internal_structure_allowed(self):
        return (self.model.has_component_selection() 
                and self.model.is_contiguous_component_selection())

def request_table_focus():
    pass  # This method seems to be missing in Python equivalent

class TaskLauncher:
    @staticmethod
    def launch_modal(name, func):
        try:
            func()
        except CancelledException as e:
            print("User cancelled")
        except UsrException as e:
            print(e)

# Initialize ICON if needed
CreateInternalStructureAction.ICON = ImageTk.PhotoImage(Image.open('images/cstruct.png'))
```

Note that Python does not have direct equivalents for Java's Swing and AWT libraries, so the code has been adapted to use Tkinter (Python's standard GUI library) or equivalent constructs where necessary.