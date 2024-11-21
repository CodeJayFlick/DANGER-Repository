import tkinter as tk
from tkinter import messagebox
from threading import Thread

class LanguageProviderPlugin:
    def __init__(self):
        self.set_language_action = None

    def init(self):
        if not isinstance(tool, FrontEndTool):
            return
        
        self.set_language_action = DockingAction("Set Language", "Language Provider")
        
        self.set_language_action.actionPerformed = lambda context: self.set_language(get_domain_file(context))
        
        self.set_language_action.isEnabledForContext = lambda action_context: is_enabled_for_context(action_context)
        
    def dispose(self):
        if tool and self.set_language_action:
            tool.removeAction(self.set_language_action)

    def set_language(self, domain_file):
        df_name = domain_file.name
        
        if not domain_file.is_writable_project():
            messagebox.showinfo("Permission Denied", f"Program {df_name} is read-only!\nSet language may not be done on a read-only Program.")
            return

        if any(domain_file.get_consumers()) or domain_file.is_busy():
            messagebox.showinfo("File In-Use", f"Program {df_name} is in-use!\nSet language may not be done while the associated file is open or in-use.  Be sure the file is not open in a tool.")
            return

        if domain_file.checked_out and not domain_file.checked_out_exclusive:
            msg = "check-in this file" if domain_file.modified_since_checkout() else "undo your checkout"
            
            messagebox.showinfo("Exclusive Checkout Required", f"You do not have an exclusive checkout of: {df_name}\n  \nAn exclusive checkout is required in order to change the current language associated with the selected Program file.  Be sure the file is not open in a tool, {msg}, then\ndo a checkout with the exclusive lock.")
            return

        msg = "Setting the language can not be undone!\n"
        
        if domain_file.modified_since_checkout():
            msg += "\nIt is highly recommended that you check-in your recent changes before performing this operation."
        else:
            msg += "\nIt is highly recommended that you make a copy of the selected file before performing this operation."

        result = OptionDialog.show_option_dialog("Set Language: " + df_name, msg + "\n  \nDo you want to continue?", "Ok", OptionDialog.WARNING_MESSAGE)
        
        if result > 0:
            task = SetLanguageTask(domain_file)
            
            Thread(target=lambda: self.open_tool(task)).start()

    def open_tool(self, task):
        try:
            tool_services.launch_default_tool(task.domain_file)
        except Exception as e:
            messagebox.showerror("Tool Launch Failed", "An error occurred while attempting to launch your default tool!", e)

class SetLanguageTask(Thread):
    def __init__(self, domain_file):
        super().__init__()
        
        self.domain_file = domain_file

    def run(self):
        try:
            monitor.setMessage("Open " + self.domain_file.name + "...")

            dobj = None
            for tx_id in range(1000):  # dummy loop to simulate transaction start and end
                dobj = self.domain_file.get_domain_object(tool, True, False, monitor)
                
                if not dobj:
                    break

            if dobj:
                try:
                    language_service.set_language(dobj, lang_desc_id, compiler_spec_desc_id, False, monitor)

                    for tx_id in range(1000):  # dummy loop to simulate transaction start and end
                        tool_services.end_transaction(tx_id)
                    
                    return True
                except Exception as e:
                    if not monitor.is_cancelled():
                        messagebox.showerror("Set Language Error", "An error occurred while setting the language!", e)

            else:
                for tx_id in range(1000):  # dummy loop to simulate transaction start and end
                    tool_services.end_transaction(tx_id)
                
        except Exception as e:
            if not monitor.is_cancelled():
                messagebox.showerror("Set Language Failed", "An error occurred while setting the language!", e)

class OptionDialog:
    @staticmethod
    def show_option_dialog(title, message, option1_text, option2_text):
        root = tk.Tk()
        
        label = tk.Label(root, text=message)
        label.pack()

        button_frame = tk.Frame(root)
        button_frame.pack()

        ok_button = tk.Button(button_frame, text=option1_text, command=root.destroy)
        cancel_button = tk.Button(button_frame, text=option2_text)

        root.mainloop()
        
        return 0 if option1_text == "Ok" else 1

class DockingAction:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        
    def actionPerformed(self, context):
        pass
    
    def isEnabledForContext(self, action_context):
        return True

class MenuData:
    def __init__(self, options, title):
        self.options = options
        self.title = title

# Usage example:

tool = None  # your tool object here
domain_file = DomainFile()  # your domain file object here
lang_desc_id = LanguageID()  # your language description ID here
compiler_spec_desc_id = CompilerSpecID()  # your compiler specification description ID here

plugin = LanguageProviderPlugin()
plugin.init()

# Now you can use the set_language_action and other methods of the plugin.
