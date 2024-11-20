class DockingUtils:
    ICON_SIZE = 16

    CONTROL_KEY_MODIFIER_MASK = None
    CONTROL_KEY_NAME = ""

    UNDO_KEYSTROKE = None
    REDO_KEYSTROKE = None

    def create_toolbar_separator(self):
        sep_dim = (2, self.ICON_SIZE + 2)
        separator = JSeparator(orientation=SwingConstants.VERTICAL)
        if DockingWindowsLookAndFeelUtils.is_using_aqua_ui(separator.getUI()):
            separator.set_UI(BasicSeparatorUI())
        separator.set_preferred_size(sep_dim)  # ugly work around to force height of separator
        return separator

    def scale_icon_as_needed(self, icon):
        if icon is None:
            return None

        if (icon.get_height() != self.ICON_SIZE or 
                icon.get_width() != self.ICON_SIZE):
            return ResourceManager().get_scaled_icon(icon, self.ICON_SIZE, self.ICON_SIZE)
        return icon

    def is_control_modifier(self, mouse_event):
        modifiers = mouse_event.modifiers
        os_specific_mask = self.CONTROL_KEY_MODIFIER_MASK
        if (modifiers & os_specific_mask) == os_specific_mask:
            return True
        else:
            return False

    def install_undo_redo(self, text_component):
        document = text_component.get_document()
        undo_redo_keeper = UndoRedoKeeper()

        document.add_undoable_edit_listener(lambda e: 
                self._add_undo(undo_redo_keeper, e))

        text_component.add_key_listener(KeyAdapter(
            lambda event:
                if KeyStroke(event).equals(self.REDO_KEYSTROKE):
                    undo_redo_keeper.redo()
                elif KeyStroke(event).equals(self.UNDO_KEYSTROKE):
                    undo_redo_keeper.undo()))

    def _add_undo(self, undo_redo_keeper, e):
        edit = e.get_edit()
        undo_redo_keeper.add_undo(edit)

    class ComponentCallback:
        def __init__(self):
            pass

        def call(self, component):
            return TreeTraversalResult.CONTINUE  # default behavior

    enum TreeTraversalOrder:
        CHILDREN_FIRST
        PARENT_FIRST

    enum TreeTraversalResult:
        CONTINUE
        FINISH
        TERMINATE

    @staticmethod
    def for_all_descendants(start, type, order, cb):
        result = TreeTraversalResult.CONTINUE
        if isinstance(order, DockingUtils.TreeTraversalOrder):
            for component in start.get_components():
                if (isinstance(component, Container) and 
                        isinstance(type, type)):
                    res = cb.call(component)
                    if res == TreeTraversalResult.FINISH or \
                            res == TreeTraversalResult.TERMINATE:
                        return res
                elif isinstance(order, DockingUtils.TreeTraversalOrder.CHILDREN_FIRST):
                    for child in component.get_components():
                        if (isinstance(child, type)):
                            res = cb.call(child)
                            if res == TreeTraversalResult.FINISH or \
                                    res == TreeTraversalResult.TERMINATE:
                                return res
                elif isinstance(order, DockingUtils.TreeTraversalOrder.PARENT_FIRST):
                    for child in component.get_components():
                        if (isinstance(child, type)):
                            res = cb.call(component)
                            if res == TreeTraversalResult.FINISH or \
                                    res == TreeTraversalResult.TERMINATE:
                                return res
        return result

    @staticmethod
    def set_transparent(c):
        do_set_transparent(c)

        if isinstance(c, JScrollPane):
            do_set_transparent(((JScrollPane) c).get_viewport())

    @staticmethod
    def do_set_transparent(c):
        # transparent...
        c.set_opacity(False)
        # ...I really mean it!
        if not (isinstance(c, JViewport)):
            # ugly, I know, but you cannot do this
            c.set_border(BorderFactory.create_empty_border())
        c.set_background_color(Color(0, 0, 0, 0))

    @staticmethod
    def hide_tip_window():
        ToolTipManager.shared_instance().set_enabled(False)
        ToolTipManager.shared_instance().set_enabled(True)

class UndoRedoKeeper:
    undo_stack = []
    redo_stack = []

    def add_undo(self, edit):
        self.undo_stack.append(edit)

    def undo(self):
        if len(self.undo_stack) > 0:
            last_edit = self.undo_stack.pop()
            self.redo_stack.append(last_edit)
        else:
            print("No more undos available")

    def redo(self):
        if len(self.redo_stack) > 0:
            last_edit = self.redo_stack.pop()
            self.undo_stack.append(last_edit)
        else:
            print("No more redos available")
