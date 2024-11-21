Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog

class CommitSingleDataTypeAction:
    def __init__(self):
        self.plugin = None
        self.COMMIT_ICON = None

    def set_plugin(self, plugin):
        self.plugin = plugin

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        
        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()
        
        if selection_paths == None or len(selection_paths) != 1:
            return False
        
        node = selection_paths[0].get_last_child_node()
        if not isinstance(node, DataTypeNode):
            return False
        
        data_type = node.get_data_type()
        handler = self.plugin.get_data_type_manager_handler()
        
        sync_status = get_sync_status(handler, data_type)
        
        switch (sync_status):
            case UNKNOWN:
                return False
            case CONFLICT or COMMIT or ORPHAN:
                return True
            case UPDATE or IN_SYNC:
                return False
        
    def action_performed(self, context):
        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()
        
        if selection_paths == None or len(selection_paths) != 1:
            return
        
        node = selection_paths[0].get_last_child_node()
        if not isinstance(node, DataTypeNode):
            return
        
        data_type = node.get_data_type()
        dtm = data_type.get_data_type_manager()
        handler = self.plugin.get_data_type_manager_handler()
        
        sync_status = get_sync_status(handler, data_type)
        
        if sync_status == CONFLICT:
            result = show_option_dialog(g_tree, "Lose Changes in Archive?", 
                "This data type has changes in the archive that will be\n" + 
                    "overwritten if you commit this data type", 
                "Continue?")
            
            if result == CANCEL_OPTION:
                return
        
        source_archive = data_type.get_source_archive()
        source_dtm = handler.get_data_type_manager(source_archive)
        
        if source_dtm is None:
            show_info(g_tree, "Commit Failed", f"Source Archive not open: {source_archive.name}")
            return
        
        if not source_dtm.is_updatable():
            show_unmodifiable_archive_error_message(g_tree, "Commit Failed!", source_dtm)
            return
        
        self.plugin.commit(data_type)

        synchronizer = DataTypeSynchronizer(handler, dtm, source_archive)
        synchronizer.re_sync_out_of_sync_in_time_only_data_types()

def get_sync_status(handler, data_type):
    # Implement this function to retrieve the sync status
    pass

def show_option_dialog(g_tree, title, message, option_text):
    root = tk.Tk()
    root.withdraw()
    
    result = messagebox.askyesno(title=title, message=message, default='cancel', button="Continue")
    
    if not result:
        return CANCEL_OPTION
    
    return YES

def show_info(parent, title, message):
    parent.title("Info - " + title)
    label = tk.Label(parent, text=message)
    label.pack()

def show_unmodifiable_archive_error_message(g_tree, title, source_dtm):
    g_tree.title(title)
    
    error_label = tk.Label(g_tree, text="Source Archive not updatable: " + str(source_dtm))
    error_label.pack()
```

Note that the code above is a direct translation of your Java code into Python. However, it does not include any implementation for certain functions like `get_sync_status`, `show_option_dialog` and some others which are used in the original Java code.