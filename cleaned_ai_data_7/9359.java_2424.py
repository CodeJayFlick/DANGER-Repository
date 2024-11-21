class DockingMenuItem:
    def __init__(self):
        self.set_ui(DockingMenuItemUI.create_ui(self))
        self.set_html_rendering_enabled(False)

    def process_key_binding(self, ks: 'KeyStroke', e: 'KeyEvent', condition: int, pressed: bool) -> bool:
        # TODO this note doesn'nt really make sense.  I think this idea is outdated.  Leaving this
        #      here for a bit, in case there is something we missed.  This code is also in
        #      DockingCheckboxMenuItemUI.
        # return True  # we will take care of the action ourselves

        # Our KeyBindingOverrideKeyEventDispatcher processes actions for us, so there is no
        # need to have the menu item do it
        return False


# Note: The following code assumes that you are using Python's built-in tkinter library,
# which does not support Java-like Swing components. Therefore, this translation may not be exact.
