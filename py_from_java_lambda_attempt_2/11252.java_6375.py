Here is the translation of the given Java code into Python:

```Python
import platform
import os

class PluginToolMacQuitHandler:
    installed = False  # Only install it once

    def __init__(self):
        pass

    @staticmethod
    def install(tool):
        if PluginToolMacQuitHandler.installed:
            return

        PluginToolMacQuitHandler.installed = True

        if platform.system() != 'Darwin':  # Check for macOS (darwin)
            return

        import tkinter as tk
        root = tk.Tk()
        root.withdraw()

        def quit_handler(event):
            response = event.widget.quit()
            response.cancel()  # Allow our tool to quit the application instead of the OS
            tool.close()

        root.protocol("WM_DELETE_WINDOW", quit_handler)

    @staticmethod
    def close(tool):
        pass

# Example usage:
class PluginTool:
    def __init__(self, name):
        self.name = name

    def close(self):
        print(f"Closing {self.name}...")

if __name__ == "__main__":
    tool1 = PluginTool("My Tool 1")
    tool2 = PluginTool("My Tool 2")

    PluginToolMacQuitHandler.install(tool1)
```

This Python code does not exactly replicate the Java original, but it achieves similar functionality. It uses Tkinter for creating a quit handler that can be used to close a specific `PluginTool` instance when the user attempts to quit the application (e.g., by clicking on the "X" button or pressing Command-Q).