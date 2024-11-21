class MessageComponent:
    def __init__(self):
        self.text = ""
        self.reset = False
        self.bold = False
        self.italic = False
        self.underlined = False
        self.strikethrough = False
        self.obfuscated = False
        self.color = None
        self.insertion = None
        self.click_event = None
        self.font = None
        self.hover_event = None

    def copy(self):
        message_component = MessageComponent()
        message_component.text = self.text
        message_component.reset = self.reset
        message_component.bold = self.bold
        message_component.italic = self.italic
        message_component.underlined = self.underlined
        message_component.strikethrough = self.strikethrough
        message_component.obfuscated = self.obfuscated
        message_component.color = self.color
        message_component.insertion = self.insertion
        message_component.click_event = self.click_event
        message_component.font = self.font
        message_component.hover_event = self.hover_event
        return message_component

class ClickEvent:
    def __init__(self, action, value):
        self.action = action
        self.value = value

class HoverEvent:
    def __init__(self, action, value):
        self.action = action
        self.value = value

BooleanSerializer = lambda x: True if x else None


