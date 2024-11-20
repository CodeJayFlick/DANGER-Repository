import tkinter as tk

class SetSpacerTextAction:
    def __init__(self, owner):
        self.owner = owner
        self.action_name = "SetTextAction"
        self.menu_data = {"Set Text": None}
        self.help_location = HelpLocation(HelpTopics.CODE_BROWSER, "Set_Spacer_Text")

    def actionPerformed(self, context):
        loc = context.get_context_object()
        field_factory = loc.get_field_factory()
        spacer_factory = SpacerFieldFactory(field_factory)
        spacer_factory.set_text()

    def is_add_to_popup(self, context):
        if not isinstance(context.get_context_object(), FieldHeaderLocation):
            return False

        loc = context.get_context_object()
        field_factory = loc.get_field_factory()
        return isinstance(field_factory, SpacerFieldFactory)

class HelpTopics:
    CODE_BROWSER = "Code Browser"

class HelpLocation:
    def __init__(self, topic, help_text):
        self.topic = topic
        self.help_text = help_text

class FieldHeaderLocation:
    pass

class FieldFactory:
    pass

class SpacerFieldFactory(FieldFactory):
    def set_text(self):
        # implement me!
        pass
