Here is the translation of the given Java code into Python:

```Python
class DiffReplaceAllAction:
    ACTION_NAME = "Set Replace for All Apply Settings"
    GROUP_NAME = "DIFF_APPLY_ACTION"
    DESCRIPTION = "Change all the difference type apply settings to Replace."

    def __init__(self, provider):
        self.provider = provider

    def set_menu_bar_data(self, menu_path):
        return {"menuPath": menu_path}

    def set_popup_menu_data(self, popup_path):
        return {"popupPath": popup_path}

    def get_description(self):
        return self.DESCRIPTION

    def actionPerformed(self, context):
        self.provider.set_apply_filter(ProgramMergeFilter.ALL, ProgramMergeFilter.REPLACE)

class DiffApplySettingsProvider:
    pass
```

Please note that this is a direct translation of the given Java code into Python. However, in order to make it fully functional, you would need to implement the `DiffApplySettingsProvider` class and its methods (`set_apply_filter`, etc.) as well as any other classes or functions used by these two classes (like `ProgramMergeFilter`).