import logging

class ShowFocusInfoAction:
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        super().__init__("Show Focus Info", False)

    def actionPerformed(self, context):
        self.print_focus_info()

    def is_enabled_for_context(self, context):
        return True

    @staticmethod
    def print_focus_info():
        win_mgr = DockingWindowManager.get_active_instance()
        info = win_mgr.get_focused_component()
        dockable_comp = None
        if info:
            dockable_comp = info.component
        self.log.info("====================================")
        self.log.info(f"Active Docking Window Manager: {win_mgr.root_frame.title} : {id(win_mgr.root_frame)}")
        if info:
            self.log.info(f"Focused Docking Window: {info.title} : {id(dockable_comp)}")
        else:
            self.log.info("Focused Docking Window: null")

        self.log.info("")
        kfm = KeyboardFocusManager().get_current_keyboard_focus_manager()
        self.log.info(f"Active Java Window: {self.print_component(kfm.active_window)}")
        self.log.info(f"Focused Java Window: {self.print_component(kfm.focused_window)}")
        self.log.info(f"Focused Java Component: {self.print_component(kfm.focus_owner)}")

        mouse_over_object = DockingWindowManager().get_mouse_over_object()
        if isinstance(mouse_over_object, tuple):
            self.log.info(f"Mouse-Over Object: {self.print_component(mouse_over_object[0])}")
        self.log.info("")

    @staticmethod
    def print_component(print_component):
        if not print_component:
            return None

        if isinstance(print_component, JFrame):
            frame = print_component
            return f"Window ({frame.title}) : {id(frame)}"

        elif isinstance(print_component, DockingDialog):
            docking_dialog = print_component
            return f"Docking Dialog: {docking_dialog.title} : {id(dockable_comp)}"

        elif isinstance(print_component, JButton):
            button = print_component
            return f"JButton: {button.text} : {id(button)}"

        name = ""
        component_name = print_component.name if hasattr(print_component, 'name') else None
        if component_name:
            name = " - '" + component_name + "' "

        return f"{print_component.__class__.__name__}{name} : {id(print_component)}"
