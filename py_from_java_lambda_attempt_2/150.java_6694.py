Here is a translation of the Java code into equivalent Python:

```Python
import tkinter as tk
from threading import Thread
from queue import Queue

class DebuggerAttachDialogOld:
    def __init__(self, provider):
        self.provider = provider
        self.attacher = None
        self.pid_field = None
        self.attach_button = None
        self.cancel_button = None
        
        self.root = tk.Tk()
        self.root.title("Debugger Attach Dialog")
        
        panel = tk.Frame(self.root)
        center_panel = tk.Frame(panel, bg="white", borderwidth=1, relief='ridge')
        panel.pack(side=tk.TOP, fill=tk.X)
        center_panel.pack(fill=tk.BOTH, expand=True)

        grid = tk.Frame(center_panel)
        cmd_line_label = tk.Label(grid, text="Target pid")
        self.pid_field = tk.Entry(grid)
        grid.pack()
        cmd_line_label.grid(row=0, column=0)
        self.pid_field.grid(row=1, column=0)

        attach_button_frame = tk.Frame(panel)
        self.attach_button = tk.Button(attach_button_frame, text="Attach", command=self.attach)
        cancel_button_frame = tk.Frame(panel)
        self.cancel_button = tk.Button(cancel_button_frame, text="Cancel")
        
        panel.pack(side=tk.TOP, fill=tk.X)
        attach_button_frame.pack()
        cancel_button_frame.pack()

    def populate_components(self):
        pass

    def attach(self):
        pid_str = self.pid_field.get()
        if pid_str.startswith("0x"):
            pid = int(pid_str, 16)
        else:
            try:
                pid = int(pid_str)
            except ValueError as e:
                print(f"Invalid PID: {e}")
                return
        def attach_pid():
            self.status_text.set("Attaching")
            try:
                self.attacher.attach(pid).get()
            except Exception as e:
                Msg.show_error(self, "Could not attach", str(e))
                self.status_text.set("Could not attach: " + str(e), MessageType.ERROR)
        
        Thread(target=attach_pid).start()

    def set_launcher(self, attacher):
        self.attacher = attacher

    def set_args(self, *args):
        cmd_line = ShellUtils.generate_line(args)
        self.pid_field.delete(0, tk.END)
        self.pid_field.insert(tk.INSERT, cmd_line)

class Msg:
    @staticmethod
    def show_error(root, title="Error", message=""):
        pass

class ShellUtils:
    @staticmethod
    def generate_line(args):
        return " ".join(map(str, args))

if __name__ == "__main__":
    provider = None  # Replace with your actual provider
    dialog = DebuggerAttachDialogOld(provider)
```

Please note that this is a translation of the Java code into equivalent Python. It's not a direct conversion and some parts might be different due to differences in syntax, semantics or libraries used between languages.