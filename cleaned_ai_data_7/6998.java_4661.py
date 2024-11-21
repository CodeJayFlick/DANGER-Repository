import ghidra.app.script.GhidraScript
from ghidra.program.model import Program, FunctionDefinitionDataType, GenericCallingConvention
from ghidra.program.model.address import AddressSpace
from ghidra.program.model.data import Register
from ghidra.program.model.lang import Language

class UpgradeDexToGhidra71Script(GhidraScript):
    def run(self) -> None:
        if self.current_program is not None:
            self.process_program(self.current_program)
            return
        
        tool = state.get_tool()
        project = tool.get_project()
        project_data = project.get_project_data()
        root_folder = project_data.get_root_folder()
        self.recurse_project_folder(root_folder)

    def recurse_project_folder(self, domain_folder: DomainFolder) -> None:
        files = domain_folder.get_files()
        for file in files:
            try:
                self.process_domain_file(file)
            except Exception as e:
                print(f"Error processing {file}: {e}")
        
        folders = domain_folder.get_folders()
        for folder in folders:
            self.recurse_project_folder(folder)

    def process_domain_file(self, domain_file: DomainFile) -> None:
        metadata = domain_file.get_metadata()
        if metadata is None or "Executable Format" not in metadata:
            return
        
        format_string = metadata["Executable Format"]
        if format_string != "Dalvik Executable (DEX)":
            return
        
        domain_object = domain_file.get_domain_object(self, True, True)
        program = Program(domain_object)
        self.process_program(program)
        self.save_program(program)

    def process_program(self, program: Program) -> None:
        print(f"Updating program: {program.name}")
        
        for func in program.get_functions(True):
            try:
                self.process_function(func)
            except CancelledException as e:
                raise e
            finally:
                pass
        
    def process_function(self, func: Function) -> None:
        sig = FunctionDefinitionDataType(func, False)
        sig.set_generic_calling_convention(GenericCallingConvention.stdcall)
        func.set_custom_variable_storage(False)
        
        cmd = ApplyFunctionSignatureCmd(func.get_entry_point(), sig, SourceType.ANALYSIS)
        cmd.apply_to(func.get_program())
        
        program = func.get_program()
        language = program.get_language()
        register_space = program.get_address_factory().get_register_space()
        local_variables = func.get_local_variables()
        
        for var in local_variables:
            if not var.is_register():
                continue
            
            offset = var.get_first_storage_varnode().get_offset() + 0x1000 - 8
            size = var.get_size()
            register = language.get_register(register_space, offset, size)
            
            try:
                new_local = LocalVariableImpl(var.name, 0, var.data_type(), register, func.get_program())
                func.remove_variable(var)
                func.add_local_variable(new_local, SourceType.ANALYSIS)
            except (InvalidInputException, DuplicateNameException):
                pass
