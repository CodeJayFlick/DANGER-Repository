Here is a translation of the provided Java code into equivalent Python:

```Python
class AbstractJavaAnalyzer:
    def __init__(self):
        pass

    def added(self, program: 'ghidra.program.model.Program', set_view: 'ghidra.program.model.address.AddressSetView',
              monitor: 'ghidra.util.task.TaskMonitor', log: 'ghidra.app.util.importer.MessageLog') -> bool:
        try:
            return self.analyze(program, set_view, monitor, log)
        except Exception as e:
            log.appendException(e)
            e.printStackTrace()
        return False

    def analysisEnded(self, program: 'ghidra.program.model.Program'):
        pass

    def registerOptions(self, options: 'ghidra.framework.options.Options', program: 'ghidra.program.model.Program'):
        pass

    def optionsChanged(self, property_list: 'ghidra.framework.options.PropertyList', program: 'ghidra.program.model.Program'):
        pass

    def removed(self, program: 'ghidra.program.model.Program', set_view: 'ghidra.program.model.address.AddressSetView',
                monitor: 'ghidra.util.task.TaskMonitor', log: 'ghidra.app.util.importer.MessageLog') -> bool:
        return False

    def restoreDefaultOptions(self, property_list: 'ghidra.framework.options.PropertyList', program: 'ghidra.program.model.Program'):
        pass

    def supportsOneTimeAnalysis(self) -> bool:
        return False

    def analyze(self, program: 'ghidra.program.model.Program', set_view: 'ghidra.program.model.address.AddressSetView',
                monitor: 'ghidra.util.task.TaskMonitor', log: 'ghidra.app.util.importer.MessageLog') -> bool:
        pass  # abstract method, should be implemented in subclasses

    def changeDataSettings(self, program: 'ghidra.program.model.Program', monitor: 'ghidra.util.task.TaskMonitor'):
        address = program.getMinAddress()
        while not monitor.isCancelled():
            data = self.getDataAt(program, address)
            if data is None:
                break
            num_components = data.getNumComponents()
            for i in range(num_components):
                component = data.getComponent(i)
                bytes = bytearray(component.getLength())
                try:
                    program.getMemory().getBytes(component.getAddress(), bytes)
                except MemoryAccessException as e:
                    pass

                is_ascii = True
                for byte in bytes:
                    if not (0 <= byte < 32 or 126 >= byte):
                        is_ascii = False
                if is_ascii and len(bytes) > 1:
                    self.changeFormatToString(component)

            address += data.getLength()

    def removeEmptyFragments(self, program: 'ghidra.program.model.Program'):
        root_module = program.getListing().getRootModule("Program Tree")
        children = root_module.getChildren()
        for child in children:
            if isinstance(child, ProgramFragment):
                fragment = child
                if fragment.isEmpty():
                    root_module.removeChild(fragment.getName())

    def changeFormatToString(self, data: 'ghidra.program.model.data.Data'):
        settings_impl = SettingsImpl(data)
        settings_impl.setDefaultSettings(settings_impl)
        settings_definitions = data.getDataType().getSettingsDefinitions()
        for setting_definition in settings_definitions:
            if isinstance(setting_definition, FormatSettingsDefinition):
                format_settings_definition = setting_definition
                format_settings_definition.setChoice(data, FormatSettingsDefinition.CHAR)

    def createFragment(self, program: 'ghidra.program.model.Program', fragment_name: str,
                       start_address: 'ghidra.program.model.address.Address',
                       end_address: 'ghidra.program.model.address.Address') -> ProgramFragment:
        module = program.getListing().getDefaultRootModule()
        fragment = self.getFragment(module, fragment_name)
        if fragment is None:
            fragment = module.createFragment(fragment_name)

        try:
            fragment.move(start_address, end_address.subtract(1))
        except Exception as e:
            pass

        return fragment

    def getFragment(self, program_module: 'ghidra.program.model.ProgramModule', name: str) -> ProgramFragment:
        children = program_module.getChildren()
        for child in children:
            if isinstance(child, ProgramFragment):
                if child.getName() == name:
                    return child
        return None

    def getDataAt(self, program: 'ghidra.program.model.Program', address: 'ghidra.program.model.address.Address') -> Data:
        return program.getListing().getDefinedDataAt(address)

    def getDataAfter(self, program: 'ghidra.program.model.Program', data: 'ghidra.program.model.data.Data') -> Data:
        return self.getDataAfter(program, data.getMaxAddress())

    def getDataAfter(self, program: 'ghidra.program.model.Program', address: 'ghidra.program.model.address.Address') -> Data:
        return program.getListing().getDefinedDataAfter(address)

    def toAddr(self, program: 'ghidra.program.model.Program', offset: int) -> Address:
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def toCpAddr(self, program: 'ghidra.program.model.Program', offset: int) -> Address:
        return program.getAddressFactory().getAddressSpace("constantPool").getAddress(offset)

    def createData(self, program: 'ghidra.program.model.Program', address: 'ghidra.program.model.address.Address',
                   data_type: 'ghidra.program.model.data.DataType') -> Data:
        if isinstance(data_type, StringDataType):
            cmd = CreateStringCmd(address)
            try:
                cmd.applyTo(program)
            except Exception as e:
                raise RuntimeException(cmd.getStatusMsg())

        else:
            cmd = CreateDataCmd(address, data_type)
            try:
                cmd.applyTo(program)
            except Exception as e:
                raise RuntimeException(cmd.getStatusMsg())

        return program.getListing().getDefinedDataAt(address)

    def setPlateComment(self, program: 'ghidra.program.model.Program', address: 'ghidra.program.model.address.Address',
                         comment: str) -> bool:
        cmd = SetCommentCmd(address, CodeUnit.PLATE_COMMENT, comment)
        try:
            return cmd.applyTo(program)
        except Exception as e:
            pass

    def createFunction(self, program: 'ghidra.program.model.Program', entry_point: 'ghidra.program.model.address.Address') -> Function:
        cmd = CreateFunctionCmd(entry_point)
        try:
            cmd.applyTo(program)
        except Exception as e:
            raise RuntimeException(cmd.getStatusMsg())

        return program.getListing().getFunctionAt(entry_point)

    def find(self, program: 'ghidra.program.model.Program', start_address: 'ghidra.program.model.address.Address',
             values: bytearray, monitor: 'ghidra.util.task.TaskMonitor') -> Address:
        try:
            return program.getMemory().findBytes(start_address, values, None, True, monitor)
        except Exception as e:
            pass

```

Please note that this is a direct translation of the provided Java code into equivalent Python. The resulting Python code may not be perfect or idiomatic Python due to differences in syntax and semantics between the two languages.