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
