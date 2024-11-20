class InVmModelForDbgmodelScenarioMemoryTest:
    def model_host(self):
        return InVmDbgmodelModelHost()

    def get_address_to_write(self, process: 'TargetProcess') -> Address:
        module_path = PathUtils.extend(process.get_path(), ['Modules'])
        modules = m.find_all(TargetModule, module_path, True)
        values = list(modules.values())
        test_module = TargetModule(values[0])
        range_ = test_module.fetch_attribute('RANGE_ATTRIBUTE_NAME').get()
        return Address(range_.min_address().add(0x15000))

class InVmDbgmodelModelHost:
    pass

from ghidra.dbg.target import TargetProcess, TargetModule
from ghidra.program.model.address import AddressRange, Address
import PathUtils
