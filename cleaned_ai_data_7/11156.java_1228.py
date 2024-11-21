class ProjectTypePanel:
    def __init__(self):
        self.panel_manager = None
        self.build_panel()

    def build_panel(self):
        from tkinter import Tk, Label, Button, StringVar, BooleanVar
        root = Tk()
        frame = Frame(root)
        frame.pack(fill='both', expand=True)

        shared_var = BooleanVar(value=False)
        non_shared_var = BooleanVar(value=True)

        def on_change(*args):
            self.panel_manager.get_wizard_manager().validity_changed()

        Button(frame, text="Non-Shared Project", variable=non_shared_var).pack()
        Button(frame, text="Shared Project", variable=shared_var).pack()

    @property
    def title(self):
        return "Select Project Type"

    def initialize(self):
        pass

    def is_valid_information(self):
        return self.panel_manager.get_wizard_manager().validity_changed()

    def get_help_location(self):
        from ghidra.util.help_topics import GenericHelpTopics
        return HelpLocation(GenericHelpTopics.FRONT_END, "SelectProjectType")

    @property
    def is_shared_project(self):
        return True  # equivalent to sharedRB.isSelected() in Java

class Frame:
    pass

class HelpLocation:
    def __init__(self, topic, location):
        self.topic = topic
        self.location = location

if __name__ == "__main__":
    panel = ProjectTypePanel()
