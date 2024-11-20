Here is the translation of the Java code into Python:

```Python
class LabelMgrPlugin:
    def __init__(self):
        self.operand_dialog = None
        self.add_edit_dialog = None
        self.edit_field_dialog = None

    def setup_actions(self, tool):
        add_label_action = AddLabelAction(self)
        tool.addAction(add_label_action)

        edit_label_action = EditLabelAction(self)
        tool.addAction(edit_label_action)

        edit_external_label_action = EditExternalLabelAction(self)
        tool.addAction(edit_external_label_action)

        remove_label_action = RemoveLabelAction(self)
        tool.addAction(remove_label_action)

        set_operand_label_action = SetOperandLabelAction(self)
        tool.addAction(set_operand_label_action)

        label_history_action = LabelHistoryAction(tool, self.get_name())
        tool.addAction(label_history_action)

    def get_add_edit_dialog(self):
        if not self.add_edit_dialog:
            self.add_edit_dialog = AddEditDialog("", None)
        return self.add_edit_dialog

    def get_edit_field_dialog(self):
        if not self.edit_field_dialog:
            self.edit_field_dialog = EditFieldNameDialog("", None)
        return self.edit_field_dialog

    def get_operand_label_dialog(self):
        if not self.operand_dialog:
            self.operand_dialog = OperandLabelDialog(self)
        return self.operand_dialog

    def remove_label_callback(self, context):
        symbol = self.get_symbol(context)
        if symbol:
            cmd = DeleteLabelCmd(symbol.getAddress(), symbol.getName(), symbol.getParentNamespace())
            if not tool.execute(cmd, context.get_program()):
                tool.setStatusInfo(cmd.getStatusMsg())

    def add_label_callback(self, context):
        self.get_add_edit_dialog().add_label(context.getAddress(), context.get_program())

    def edit_label_callback(self, context):
        symbol = self.get_symbol(context)
        if symbol:
            if symbol.getSource() == SourceType.DEFAULT and symbol.getSymbolType() == SymbolType.LABEL:
                self.get_add_edit_dialog().add_label(symbol.getAddress(), context.get_program())
            else:
                self.get_add_edit_dialog().edit_label(symbol, context.get_program())

    def set_operand_label_callback(self, context):
        self.get_operand_label_dialog().set_operand_label(context)

    def get_symbol(self, context):
        location = context.getLocation()
        if isinstance(location, LabelFieldLocation):
            return location.getSymbol()
        elif isinstance(location, OperandFieldLocation):
            variable_offset = ((OperandFieldLocation)location).getVariableOffset()
            if variable_offset:
                var = variable_offset.getVariable()
                if var:
                    return var.get_symbol()
            ref = self.get_operand_reference(context)
            if ref:
                return context.get_program().getSymbolTable().getSymbol(ref)

    def get_operand_reference(self, context):
        location = context.getLocation()
        if not isinstance(location, OperandFieldLocation):
            return None
        op_loc = (OperandFieldLocation)location
        address = op_loc.getAddress()
        op_index = op_loc.getOperandIndex()
        data_comp = self.get_data_component(context)
        if data_comp:
            if isInUnion(data_comp):
                return None
            address = data_comp.getMinAddress()

    def get_data_component(self, context):
        location = context.getLocation()
        component_path = location.getComponentPath()
        if not component_path or len(component_path) == 0:
            return None

        data = context.get_program().getListing().getDataContaining(location.getAddress())
        if not data or not data.isDefined():
            return None
        dt = data.getDataType()

    def is_on_symbol(self, context):
        return self.get_symbol(context)

    def is_on_function(self, context):
        location = context.getLocation()
        return isinstance(location, FunctionLocation)

    def is_on_variable_reference(self, context):
        symbol = self.get_symbol(context)
        if not symbol:
            return False
        type = symbol.getSymbolType()
        return type == SymbolType.PARAMETER or type == SymbolType.LOCAL_VAR

    def has_label_history(self, context):
        location = context.getLocation()
        address = None
        if isinstance(location, CodeUnitLocation):
            loc = (CodeUnitLocation)location
            address = loc.getAddress()

    class AddLabelAction:
        pass

    class EditLabelAction:
        pass

    class RemoveLabelAction:
        pass

    class SetOperandLabelAction:
        pass

    class LabelHistoryAction:
        pass

class OperandLabelDialog:
    def __init__(self, plugin):
        self.plugin = plugin

    def set_operand_label(self, context):
        # implementation
        pass

class AddEditDialog:
    def __init__(self, initial_value, tool):
        self.initial_value = initial_value
        self.tool = tool

    def add_label(self, address, program):
        # implementation
        pass

    def edit_label(self, symbol, program):
        # implementation
        pass

class EditFieldNameDialog:
    def __init__(self, initial_value, tool):
        self.initial_value = initial_value
        self.tool = tool

    def edit_field(self, dt_comp, program):
        # implementation
        pass