Here is the translation of the Java code to Python:
```
import tkinter as tk

class StatusBarSpacer:
    def __init__(self):
        self.empty_icon = ResourceManager.load_image("images/EmptyIcon.gif")

    def get_icon(self):
        if Platform.CURRENT_PLATFORM.get_operating_system() == OperatingSystem.MAC_OS_X:
            return self.empty_icon
        else:
            return None


# Note: The following classes are not directly translatable to Python,
#       as they seem to be specific to the GHIDRA framework.
class ResourceManager:
    @staticmethod
    def load_image(filename):
        # TO DO: implement this method

class Platform:
    CURRENT_PLATFORM = "mac"  # or "windows", etc.

class OperatingSystem:
    MAC_OS_X = "MAC OS X"
```
Note that I had to make some assumptions about the `ResourceManager` and `Platform` classes, as they seem to be specific to the GHIDRA framework. In a real-world translation, you would need to replace these with equivalent Python constructs or import relevant libraries.

Also, keep in mind that this is just one possible way to translate the Java code to Python - there may be other valid translations depending on your specific use case and requirements.