class EditPluginPathDialog:
    ADD_DIR_BUTTON_TEXT = "Add Dir..."
    ADD_JAR_BUTTON_TEXT = "Add Jar..."

    def __init__(self):
        self.mainPanel = None
        self.listModel = DefaultListModel()
        super().__init__("Edit Plugin Path", True, False, True, False)
        setHelpLocation(HelpLocation("FrontEndPlugin", "Edit_Plugin_Path"))
        addWorkPanel(self.buildMainPanel())
        addOKButton()
        addApplyButton()
        addCancelButton()

    def buildMainPanel(self):
        self.mainPanel = JPanel(BoxLayout.Y_AXIS)

        self.listModel.clear()
        setPluginPathsListData(Preferences.getPluginPaths())

        statusMessagePanel = JPanel()
        status_message_label = GDLabel("Ready to set User Plugin Paths")
        status_message_label.setForeground(Color.BLUE.brighter())
        statusMessagePanel.add(status_message_label)

        plugin_paths_panel = buildPluginPathsPanel()

        self.mainPanel.add(plugin_paths_panel)
        self.mainPanel.add(Box.createVerticalStrut(10))
        self.mainPanel.add(Box.createVerticalGlue())
        self.mainPanel.add(statusMessagePanel)

    def applyCallback(self):
        handleApply()

    def cancelCallback(self):
        close()
        resetOriginalStateOfDialogForNextDisplayOfDialog()

    def okCallback(self):
        if isApplyEnabled():
            applyCallback()
        else:
            cancelCallback()

    def show(self, tool):
        setPluginPathsListData(Preferences.getPluginPaths())
        setApplyEnabled(plugin_paths_changed)
        setStatusMessage("")

        file_chooser = GhidraFileChooser(getComponent())
        file_chooser.setCurrentDirectory(File(System.getProperty("user.home")))
        file_chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY)
        file_chooser.setFileFilter(JAR_FILTER)

    def addJarCallback(self):
        if file_chooser is None:
            file_chooser = GhidraFileChooser(getComponent())
            file_chooser.setCurrentDirectory(File(System.getProperty("user.home")))
            file_chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY)
            file_chooser.setFileFilter(JAR_FILTER)

    def addDirCallback(self):
        if file_chooser is None:
            file_chooser = GhidraFileChooser(getComponent())
            file_chooser.setCurrentDirectory(File(System.getProperty("user.home")))
            file_chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY)
            file_chooser.setFileFilter(ALL)

    def getUserPluginPaths(self):
        return [str(x) for x in listModel]

    def buildPluginPathsPanel(self):
        up_button = ButtonPanelFactory.createButton("Up")
        down_button = ButtonPanelFactory.createButton("Down")
        remove_button = ButtonPanelFactory.createButton("Remove")

        arrow_buttons_panel = JPanel(FlowLayout.LEFT, 10, 10)
        arrow_buttons_panel.add(up_button)
        arrow_buttons_panel.add(down_button)

    def enableButtons(self, enabled):
        up_button.setEnabled(enabled)
        down_button.setEnabled(enabled)
        remove_button.setEnabled(enabled)

    def handleApply(self):
        user_plugin_paths = getUserPluginPaths()
        Preferences.setPluginPaths(user_plugin_paths)
        errorMsg = None
        if Preferences.store():
            setStatusMessage("Saved plugin paths successfully!")
            setApplyEnabled(False)
            Msg.showInfo(getClass(), rootPanel, "Restart Ghidra", "You must restart Ghidra in order for path changes to take effect.")
        else:
            setStatusMessage("")
            Msg.showError(this, rootPanel, "Error Saving Plugin Paths", "Failed to update user preferences (see log for details)")

    def handleSelection(self, which_action):
        if selected_in_list is None:
            enable_buttons(False)
            return

        # confirm removal of plugin path entries
        if which_action == REMOVE:
            for path_name in list_model:
                index = list_model.index(path_name)
                if index >= 0:
                    list_model.remove(index)

    def setPluginPathsListData(self, plugin_path_names):
        self.listModel.clear()
        for plugin_path_name in plugin_path_names:
            self.listModel.addElement(plugin_path_name)

class PathListSelectionListener:
    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            return

        selected_values = list_model.getSelectedValuesList()

        remove_button.setEnabled(False)
