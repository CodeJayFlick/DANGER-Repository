Here is the translation of the Java code into Python:

```Python
class EmptyBorderToggleButton:
    def __init__(self):
        self.toggle_button_action_listener = lambda e: self.doActionPerformed(e)
        self.property_change_listener = lambda evt: self.doPropertyChange(evt)

    def init(self):
        pass  # equivalent to super() in Java

    def doActionPerformed(self, event):
        if hasattr(self, 'action'):
            action = getattr(self, 'action')
            action.actionPerformed(event)
        else:
            selected = not self.isSelected()
            self.setSelected(selected)

    def doPropertyChange(self, event):
        name = event.get_property_name()
        value = event.get_new_value()

        if name == "enabled":
            enabled = bool(value)
            self.setEnabled(enabled)
        elif name in ["short_description", "small_icon"]:
            setattr(self, name.replace("_", "").lower(), value)

    def initFromAction(self, action):
        if not hasattr(action, 'get_tool_bar_data'):
            return

        tool_bar_data = action.get_tool_bar_data()
        icon = tool_bar_data.get_icon() if tool_bar_data else None
        self.setIcon(icon)
        description = action.getDescription() or action.getName()

        self.setToolTipText(description)

    def updateBorder(self):
        selected = self.isSelected()
        if selected:
            self.setBorder("lowered_button_border")
        else:
            self.setBorder("no_button_border")

    def isButtonSelected(self):
        return self.isSelected()

    def removeListeners(self):
        pass  # equivalent to super.removeListeners() in Java

    @property
    def action(self):
        raise NotImplementedError("This method should be implemented by the subclass.")

    def setIcon(self, icon):
        if hasattr(icon, 'getScaledInstance'):
            scaled_icon = icon.getScaledInstance()
            self.setIcon(scaled_icon)
        else:
            super().setIcon(icon)

    @property
    def selected(self):
        return self._selected

    @selected.setter
    def selected(self, value):
        old_value = self.isSelected()

        if not hasattr(self, 'action'):
            raise AttributeError("Action is required for this button.")

        action = getattr(self, 'action')
        action.actionPerformed(None)  # Perform the action on toggle.

        super().setSelected(value)
        self.updateBorder()
```

Note that Python does not have direct equivalents to Java's `package`, `import`, and `class` statements. The code above is a translation of the provided Java class into equivalent Python syntax, without any imports or packages specified.