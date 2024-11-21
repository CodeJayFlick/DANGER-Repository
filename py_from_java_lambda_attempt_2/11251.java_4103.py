Here is the translation of the given Java code into Python:

```Python
import platform
from tkinter import Tk, filedialog

class PluginToolMacAboutHandler:
    installed = False  # Only install it once

    @staticmethod
    def install(win_mgr):
        if PluginToolMacAboutHandler.installed:
            return
        
        PluginToolMacAboutHandler.installed = True

        if platform.system() != 'Darwin':  # Check for macOS (Darwin)
            return
        
        root = Tk()
        root.withdraw()

        filedialog.about(root, "Custom About Dialog")
```

Please note that Python does not have a direct equivalent to Java's `Desktop` class. The above code uses the built-in `tkinter` module and its `filedialog` function to create an about dialog box.