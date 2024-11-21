Here is the translation of the Java code into Python:

```Python
class EclipseIntegrationOptionsPlugin:
    PLUGIN_OPTIONS_NAME = "Eclipse Integration"
    
    ECLIPSE_INSTALL_DIR_OPTION = "Eclipse Installation Directory"
    ECLIPSE_INSTALL_DIR_DESC = "Path to Eclipse installation directory"
    ECLIPSE_INSTALL_DIR_DEFAULT = None
    
    ECLIPSE_WORKSPACE_DIR_OPTION = "Eclipse Workspace Directory (optional)"
    ECLIPSE_WORKSPACE_DIR_DESC = ("Optional path to Eclipse workspace "
                                    "directory. If defined and the directory does not exist, "
                                    "Eclipse will create it. If undefined, Eclipse will be "
                                    "responsible for selecting the workspace directory.")
    ECLIPSE_WORKSPACE_DIR_DEFAULT = None
    
    SCRIPT_EDITOR_PORT_OPTION = "Script Editor Port"
    SCRIPT_EDITOR_PORT_DESC = ("The port number used to communicate with Eclipse "
                                 "for script editing. It must match the port number set in "
                                 "the Eclipse GhidraDev plugin preference page in order for them "
                                 "to communicate.")
    SCRIPT_EDITOR_PORT_DEFAULT = 12321
    
    SYMBOL_LOOKUP_PORT_OPTION = "Symbol Lookup Port"
    SYMBOL_LOOKUP_PORT_DESC = ("The port number used to communicate with Eclipse "
                                "for script editing. It must match the port number set in "
                                "the Eclipse GhidraDev plugin preference page in order for them "
                                "to communicate.")
    SYMBOL_LOOKUP_PORT_DEFAULT = 12322
    
    AUTO_GHIDRADEV_INSTALL_OPTION = "Automatically install GhidraDev"
    AUTO_GHIDRADEV_INSTALLATION_DESC = ("Automatically install the GhidraDev plugin into "
                                          "the \"dropins\" directory of the specified Eclipse if it has not yet been installed.")
    AUTO_GHIDRADEV_INSTALL_DEFAULT = True
    
    def __init__(self, tool):
        super().__init__()
    
    def init(self):
        options = self.tool.get_options(self.PLUGIN_OPTIONS_NAME)
        
        options.register_option(self.ECLIPSE_INSTALL_DIR_OPTION,
                                 "file_type",
                                 self.ECLIPSE_INSTALL_DIR_DEFAULT,
                                 None,
                                 self.ECLIPSE_INSTALL_DIR_DESC)
        
        options.register_option(self.ECLIPSE_WORKSPACE_DIR_OPTION,
                                 "file_type",
                                 self.ECLIPSE_WORKSPACE_DIR_DEFAULT,
                                 None,
                                 self.ECLIPSE_WORKSPACE_DIR_DESC)
        
        options.register_option(self.SCRIPT_EDITOR_PORT_OPTION, 
                                 self.SCRIPT_EDITOR_PORT_DEFAULT, 
                                 None, 
                                 self.SCRIPT_EDITOR_PORT_DESC)
        
        options.register_option(self.SYMBOL_LOOKUP_PORT_OPTION, 
                                 self.SYMBOL_LOOKUP_PORT_DEFAULT, 
                                 None, 
                                 self.SYMBOL_LOOKUP_PORT_DESC)
        
        options.register_option(self.AUTO_GHIDRADEV_INSTALL_OPTION,
                                 "boolean",
                                 self.AUTO_GHIDRADEV_INSTALL_DEFAULT,
                                 None,
                                 self.AUTO_GHIDRADEV_INSTALLATION_DESC)
        
        options.set_options_help_location("EclipseIntegration", "EclipseIntegration")
```

Please note that Python does not have direct equivalent of Java's `@PluginInfo` and other annotations.