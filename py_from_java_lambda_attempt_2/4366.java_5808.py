Here is the translation of the given Java code into Python:

```Python
class EditExternalLocationDialog:
    PREFERRED_CREATE_PANEL_HEIGHT = 240
    PREFERRED_EDIT_PANEL_HEIGHT = 220
    PREFERRED_PANEL_WIDTH = 450

    CREATE_HELP = {"plugin": "SymbolTreePlugin", "help_location": "createExternalLocation"}
    EDIT_HELP = {"plugin": "SymbolTreePlugin", "help_location": "editExternalLocation"}

    def __init__(self, external_location=None, program=None, library_name=None):
        self.ext_loc_panel = None
        if external_location:
            self.external_location = external_location
            self.program = external_location.get_symbol().get_program()
        elif program and library_name:
            self.program = program
            self.library_name = library_name

    def dispose(self):
        self.close()

    def build_main_panel(self):
        panel_border = {"top": 5, "left": 10, "bottom": 5, "right": 10}
        if self.external_location:
            self.ext_loc_panel = EditExternalLocationPanel(self.external_location)
        else:
            self.ext_loc_panel = EditExternalLocationPanel(self.program, self.library_name)

        panel_height = PREFERRED_EDIT_PANEL_HEIGHT
        if not self.external_location:
            panel_height = PREFERRED_CREATE_PANEL_HEIGHT

        return {"work_panel": {"layout_manager": "BorderLayout", 
                               "components": [self.ext_loc_panel]}, 
                "panel_height": panel_height, 
                "preferred_size": (PREFERRED_PANEL_WIDTH, panel_height)}

    def init_dialog(self):
        if self.external_location:
            title = f"Edit External Location ({get_edit_name()})"
            help_location = self.EDIT_HELP
        else:
            title = "Create External Location"
            help_location = self.CREATE_HELP

        return {"title": title, 
                "help_location": help_location}

    def get_edit_name(self):
        if self.external_location:
            symbol = self.external_location.get_symbol()
            name = symbol.name(True)
            addr = self.external_location.get_address()
            if addr:
                name += f" @ {addr.toString(True)}"
            return name
        else:
            edit_name = self.program.get_parent_namespace().name(True)
            has_name = bool(self.location_name and len(self.location_name) > 0)
            if has_name:
                edit_name += f"::{self.location_name}"
            if self.address:
                edit_name += f" @ {self.address.toString()}"
            return edit_name

    def apply_callback(self):
        if self.ext_loc_panel.apply_location():
            self.close()
            self.cleanup()

    def cancel_callback(self):
        self.close()
        self.cleanup()


class EditExternalLocationPanel:
    def __init__(self, external_location=None, program=None, library_name=None):
        pass  # This class is not implemented in the given Java code

    def cleanup(self):
        pass  # This method is not implemented in the given Java code


def main():
    dialog = EditExternalLocationDialog(external_location="some_external_location", 
                                         program="some_program", 
                                         library_name="some_library")
    print(dialog.build_main_panel())
    print(dialog.init_dialog())


if __name__ == "__main__":
    main()
```

Please note that the `EditExternalLocationPanel` class is not implemented in the given Java code, so I left it as a placeholder.