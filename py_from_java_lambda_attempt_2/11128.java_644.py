Here is the translation of the Java code into Python:

```Python
class FindCheckoutsAction:
    def __init__(self, owner, plugin):
        self.plugin = plugin
        super().__init__("Find Checkouts", owner)
        group = "Repository"
        search_icon = ResourceManager.load_image("images/magnifier.png")
        small_check_icon = ResourceManager.load_image("images/check.png")
        icon = MultiIcon(search_icon)
        icon.add_icon(small_check_icon)
        self.set_tool_bar_data(ToolBarData(icon, group))
        self.set_popup_menu_data(MenuData(["Find Checkouts..."], icon, "Repository"))
        self.setDescription("Find my checkouts recursively")
        self.set_help_location(HelpLocation("VersionControl", "Find_Checkouts"))
        self.setEnabled(False)

    def actionPerformed(self, context):
        domain_folder = context.getSelectedFolders()[0]
        project_data = domain_folder.getProjectData()
        repository = project_data.getRepository()
        if repository and not repository.isConnected():
            if OptionDialog.show_option_dialog_with_cancel_as_default_button(None,
                                                                              "Find Checkouts...",
                                                                              "Action requires connection to repository.\nWould you like to connect now?",
                                                                              "Connect", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE:
                return
            try:
                repository.connect()
            except NotConnectedException as e:
                # ignore - likely caused by cancellation
                return
            except IOException as e:
                ClientUtil.handle_exception(repository, e, "Find Checkouts", None)
                return

        self.find_checkouts(domain_folder, context.getTree())

    def isEnabledForContext(self, context):
        if context.isReadOnlyProject():
            return False
        return len(context.getFolders()) == 1


class FindCheckoutsDialog:
    def __init__(self, plugin, folder):
        self.plugin = plugin
        self.folder = folder

    # other methods and properties as needed


# usage example:

plugin = Plugin()  # or any instance of your class that has the necessary attributes and methods
owner = "Your Owner"
action = FindCheckoutsAction(owner, plugin)
```

Please note that this is a direct translation from Java to Python. You may need to adjust it according to your specific requirements in terms of classes, functions, variables, etc., as well as any dependencies or imports required by the code.