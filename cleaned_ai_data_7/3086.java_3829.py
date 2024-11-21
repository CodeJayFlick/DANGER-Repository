import ghidra.app.script.GhidraScript
from ghidra.program.model.data import *

class PrintStructureScript(GhidraScript):
    def run(self):
        dt_name = "/crtdefs.h/_struct_9"
        data_type = self.find_data_type_by_name(dt_name)
        
        if data_type is None:
            print("Could not find data type by name: " + dt_name)
            return
        
        tooltip_text = ToolTipUtils.get_tooltip_text(data_type)
        print("Data type tooltip (HTML): " + tooltip_text)

        print("Data type text (non-HTML): " + str(data_type))

        self.print_structure(data_type)

    def find_data_type_by_name(self, name):
        tool = state.get_tool()
        service = tool.getService(DataTypeManagerService)
        data_type_managers = service.getDataTypeManagers()

        for manager in data_type_managers:
            data_type = manager.getDataType(name)
            
            if data_type is not None:
                return data_type
        
        return None

    def print_structure(self, data_type):
        buffer = ""
        
        self.print_structure_recursively(data_type, buffer, 0)

        print("\n" + buffer)

    def print_structure_recursively(self, data_type, buffer, level):
        if not isinstance(data_type, Structure):
            print("Data type is not a structure: " + str(data_type))
            return
        
        structure = data_type
        self.tabs(buffer, level - 1)
        
        buffer += "Structure " + structure.getName() + " {\n"
        
        components = structure.getComponents()
        
        for component in components:
            child_data_type = component.getDataType()

            if isinstance(child_data_type, Structure):
                self.print_structure_recursively(child_data_type, buffer, level + 1)
            
            else:
                self.tabs(buffer, level)

                buffer += str(child_data_type.getName()) + "\t" + str(child_data_type.getLength()) + "\n"
        
        self.tabs(buffer, level - 1)
        
        buffer += "}\n"

        self.tabs(buffer, level - 1)
        
        buffer += "Size=" + str(structure.getLength()) + " Actual Alignment=" + str(structure.getAlignment())
    
    def tabs(self, buffer, level):
        for _ in range(level + 1):
            buffer += "\t"
