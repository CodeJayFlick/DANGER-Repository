class PointerAction:
    ACTION_NAME = "Create Pointer"
    GROUP_NAME = "COMPONENT_ACTION_GROUP"
    DESCRIPTION = "Create a pointer(s) on the selection"
    POINTER_DT = {"name": "PointerDataType", "type": "pointer"}
    KEY_STROKE = ("P", 0)

    def __init__(self, provider):
        self.provider = provider
        super().__init__(provider, f"{EDIT_ACTION_PREFIX}{ACTION_NAME}", GROUP_NAME)
        self.setDescription(DESCRIPTION)
        self.setKeyBindingData({"keyStroke": KeyStroke(*KEY_STROKE), "defaultLevel": "Default"})
        self.adjustEnablement()

    def actionPerformed(self):
        try:
            model.add(PointerDataType())
        except Exception as e1:
            model.setStatus(str(e1))
        requestTableFocus()

    def isEnabledForContext(self, context):
        return (model.getRowCount() > 0 and
               model.hasSelection() and
               model.isContiguousSelection())

    def adjustEnablement(self):
        has_selection = model.hasSelection()
        enable = (model.getRowCount() > 0) and (
            not has_selection or 
            (has_selection and model.isContiguousSelection())
        )
        self.setEnabled(enable)
