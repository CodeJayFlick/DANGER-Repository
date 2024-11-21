Here is the translation of the Java code into Python:

```Python
class ProgramTreeModularizationPlugin:
    def __init__(self):
        pass

    def create_actions(self):
        from ghidra.app import CorePluginPackage
        from ghidra.framework.plugintool import PluginInfo, PluginTool
        from ghidra.util import HelpLocation
        from docking.action import DockingAction, MenuData
        from docking import ActionContext

        self.create_dominance_tree_action = DockingAction("Create Dominance Tree", "ProgramTreeModularizationPlugin")
        self.create_complexity_depth_tree_action = DockingAction("Create Complexity Depth Tree", "ProgramTreeModularizationPlugin")

        def apply_dominance_algorithm(node):
            block_model_service = CorePluginPackage.get_instance().get_block_model_service()
            dominance_modularization_cmd = DominanceModularizationCmd(
                node.group_path, 
                node.group.tree_name, 
                current_selection, 
                block_model_service.active_subroutine_model
            )
            tool.execute_background_command(dominance_modularization_cmd, current_program)

        def apply_complexity_depth_algorithm(node):
            block_model_service = CorePluginPackage.get_instance().get_block_model_service()
            complexity_depth_modularization_cmd = ComplexityDepthModularizationCmd(
                node.group_path,
                node.group.tree_name,
                current_selection,
                block_model_service.active_subroutine_model
            )
            tool.execute_background_command(complexity_depth_modularization_cmd, current_program)

        self.create_dominance_tree_action.actionPerformed = lambda context: apply_dominance_algorithm(context.getContextObject())
        self.create_complexity_depth_tree_action.actionPerformed = lambda context: apply_complexity_depth_algorithm(context.getContextObject())

        self.create_dominance_tree_action.isEnabledForContext = lambda context: isinstance(context.getContextObject(), ProgramNode) and context.getContextObject().program is not None
        self.create_complexity_depth_tree_action.isEnabledForContext = lambda context: isinstance(context.getContextObject(), ProgramNode) and context.getContextObject().program is not None

        self.create_dominance_tree_action.setPopupMenuData(MenuData(["Modularize By", "Dominance"], "select"))
        self.create_dominance_tree_action.setHelpLocation(HelpLocation("ProgramTreePlugin", "Create_Dominance_Tree"))

        self.create_complexity_depth_tree_action.setPopupMenuData(MenuData(["Modularize By", "Complexity Depth"], "select"))
        self.create_complexity_depth_tree_action.setHelpLocation(HelpLocation("ProgramTreePlugin", "Complexity_Depth"))

        tool.add_action(self.create_dominance_tree_action)
        tool.add_action(self.create_complexity_depth_tree_action)

    def init(self):
        self.create_actions()

class DominanceModularizationCmd:
    pass

class ComplexityDepthModularizationCmd:
    pass
```

Please note that the Python code above is a direct translation of Java to Python, and it may not work as expected without further modifications. The original Java code seems to be part of a larger program (Ghidra) which provides many classes and services that are used in this plugin. In order for the Python code to function correctly, you would need to have access to these same classes and services or implement them yourself.