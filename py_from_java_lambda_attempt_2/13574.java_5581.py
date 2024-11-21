Here is a translation of the provided Java code into equivalent Python:

```Python
class AbstractGhidraLaunchShortcut:
    def __init__(self, launch_config_type_id: str, launch_config_name_suffix: str):
        self.launch_config_type_id = launch_config_type_id
        self.launch_config_name_suffix = launch_config_name_suffix

    def launch(self, selection=None, mode=""):
        if not selection:
            return
        
        project = GhidraProjectUtils.get_selected_project(selection)
        
        if project is None:
            return
        
        self._launch(project, mode)

    def _launch(self, java_project: dict, mode):
        try:
            launch_manager = DebugPlugin.getDefault().get_launch_manager()
            launch_type = launch_manager.get_launch_configuration_type(self.launch_config_type_id)
            
            launch_config_name = f"{java_project['name']}_{self.launch_config_name_suffix}"
            
            if not GhidraLaunchUtils.is_launch_config_available(launch_config_name):
                wc = GhidraLaunchUtils.create_launch_config(java_project, self.launch_config_type_id, 
                                                            launch_config_name, None)
            else:
                lc = GhidraLaunchUtils.get_launch_config(launch_config_name)
                wc = lc.get_working_copy()
            
            if not wc or wc.type != launch_type:
                raise CoreException(f"Failed to launch. Run configuration with name '{launch_config_name}' already exists.")
            
            wc.do_save().launch(mode, None)

        except Exception as e:
            EclipseMessageUtils.show_error_dialog(str(e))

class GhidraProjectUtils:
    @staticmethod
    def get_selected_project(selection):
        # Implement this method to return the selected project based on the given selection.
        pass

class DebugPlugin:
    @staticmethod
    def get_default():
        # Implement this method to return an instance of your debug plugin.
        pass

class GhidraLaunchUtils:
    @staticmethod
    def is_launch_config_available(launch_config_name):
        # Implement this method to check if a launch configuration with the given name exists.
        pass
    
    @staticmethod
    def get_launch_config(launch_config_name):
        # Implement this method to return an instance of your launch config based on its name.
        pass

    @staticmethod
    def create_launch_config(java_project, launch_config_type_id, launch_config_name, None):
        # Implement this method to create a new launch configuration with the given details.
        pass

class EclipseMessageUtils:
    @staticmethod
    def show_error_dialog(message):
        # Implement this method to display an error dialog box with the given message.
        pass
```

Please note that you will need to implement the methods marked as `pass` in your Python code.