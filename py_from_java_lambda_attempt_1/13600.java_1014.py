Here is the translation of the given Java code into Python:

```Python
class ChooseJavaProjectWizardPage:
    def __init__(self, selected_project):
        self.selected_project = selected_project
        self.project_combo = None

    def create_control(self, parent):
        container = wx.Panel(parent)
        sizer = wx.GridBagSizer(2, 0)

        label = wx.StaticText(container, label="Java project:")
        sizer.Add(label, pos=(0, 0), flag=wx.ALL | wx.ALIGN_CENTER_VERTICAL, border=5)
        
        self.project_combo = wx.ComboBox(container)
        self.project_combo.Bind(wx.EVT_COMBOBOX, lambda event: self.validate())
        gd = wx.GridBagSizer(1, 0)
        gd.Add(self.project_combo, pos=(0, 0), flag=wx.ALL | wx.ALIGN_CENTER_VERTICAL, border=5)

        for java_project in GhidraProjectUtils.get_java_projects():
            project = java_project.get_project()
            self.project_combo.Append(project.name)
            if project == selected_project:
                self.project_combo.SetSelection(self.project_combo.FindString(project.name))

        container.Fit()

    def get_java_project(self):
        for java_project in GhidraProjectUtils.get_java_projects():
            project = java_project.get_project()
            if project.name == self.project_combo.GetValue():
                return java_project
        return None

    def validate(self):
        message = None
        name = self.project_combo.GetValue()

        if not name:
            message = "Existing Java project must be specified"
        
        set_error_message(message)
        set_page_complete(not bool(message))
```

Note: The wxPython library is used to create the GUI components in Python.