Here's your Java code translated into equivalent Python:

```Python
import tkinter as tk
from PIL import ImageTk, Image

class SelectExistingMatchAction:
    ICON = None  # Load icon using ResourceManager.loadImage("images/text_align_justify.png")
    MENU_GROUP = "Create"

    def __init__(self, controller):
        self.controller = controller
        super().__init__("Select Exising Match", VTPlugin.OWNER)
        setToolBarData(Icon=ICON, MenuGroup=MENU_GROUP)  # equivalent to Java's setToolBarData()
        setPopupMenuData(MenuData=["Select Existing Match"], Icon=ICON)  # equivalent to Java's setPopupMenuData()
        self.setEnabled(False)  # equivalent to Java's setEnabled(false)
        self.setHelpLocation(HelpLocation("VersionTrackingPlugin", "Select_Existing_Match"))  # equivalent to Java's setHelpLocation()

    def actionPerformed(self, context):
        provider_context = FunctionAssociationContext(context)
        match = provider_context.get_existing_match()
        if match:
            self.controller.setSelectedMatch(match)

    def is_enabled_for_context(self, context):
        return isinstance(context, FunctionAssociationContext) and context.get_existing_match() is not None

    def is_add_to_popup(self, context):
        return isinstance(context, FunctionAssociationContext)
```

Note that this Python code does not include the equivalent of Java's `package ghidra.feature.vt.gui.actions;` statement.