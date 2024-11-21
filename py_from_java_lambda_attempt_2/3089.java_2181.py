Here is the translation of the Java code into Python:

```Python
import ghidra.app.script.GhidraScript
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.data import DataType
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import Listing, CodeUnitIterator
from ghidra.program.model.symbol import SymbolTable

class PropagateExternalParametersScript(GhidraScript):
    def __init__(self):
        self.results = []

    def run(self):
        listing = currentProgram.getListing()
        function_manager = currentProgram.getFunctionManager()

        for ext_sym in sym_tab.getExternalSymbols():
            if ext_sym.getSymbolType() == SymbolType.FUNCTION:
                func = function_manager.getFunctionAt(ext_sym.getAddress())
                params = func.getParameters()
                refs = ext_sym.getReferences()
                process_external_function(listing, ref_man, refs, func, params, ext_sym.getName())

        for ppi in self.results:
            instr = listing.getInstructionAt(ppi.getAddress())
            op_type = instr.getOperandType(0)

            if not instr.getOperandRefType(0).isData():
                continue

            # If operand of pushed parameter points to data make a symbol and comment at that location
            refs = listing.getCodeUnitAt(ppi.getAddress()).getOperandReferences(0)
            if len(refs) > 0 and refs[0].isMemoryReference():
                addr = refs[0].getToAddress()
                dt = ppi.getDataType()
                data = getDataAt(addr)
                is_string = False
                if data.hasStringValue():
                    is_string = True

                symbol_name = f"{ppi.getName()}_{addr.toString()}"
                new_comment = f"{ppi.getName()} parameter of {ppi.getCalledFunctionName()}\n"
                symbols = get_symbols(symbol_name, None)
                if not symbols and not is_string:
                    create_label(addr, symbol_name, True, SourceType.USER_DEFINED)

                current_comment = get_plate_comment(addr)
                if current_comment is None:
                    set_plate_comment(addr, new_comment)
                elif not current_comment.contains(ppi.getCalledFunctionName()):
                    set_plate_comment(addr, f"{current_comment}{new_comment}")

                if data and listing.getCodeUnitAt(data).getMnemonicString().startswith("undefined"):
                    clear_listing(data)

    def process_external_function(self, listing, ref_man, refs, func, params, ext_func_name):
        for ref in refs:
            addr = ref.getFromAddress()
            mnemonic = listing.getCodeUnitAt(addr).getMnemonicString()
            called_from_func = listing.getFunctionContaining(addr)
            if called_from_func is None:
                continue

            if mnemonic == "JMP" and called_from_func.isThunk():
                temp_iter = ref_man.getReferencesTo(called_from_func.getEntryPoint())
                while temp_iter.hasNext():
                    thunk_ref = temp_iter.next()
                    addr = thunk_ref.getFromAddress()
                    mnemonic = listing.getCodeUnitAt(addr).getMnemonicString()
                    func = listing.getFunctionContaining(addr)
                    if mnemonic == "CALL" and func is not None:
                        code_units_to_ref = getCodeUnitsFromFunctionStartToRef(func, thunk_refAddr)
                        propagate_params(params, code_units_to_ref, ext_func_name)

    def num_params(self, cu):
        function_manager = currentProgram.getFunctionManager()
        opref = cu.getReferencesFrom()

        to_addr = None
        func = None
        if len(opref) > 0:
            to_addr = opref[0].getToAddress()
            func = function_manager.getReferencedFunction(to_addr)
            if func is not None:
                prms = func.getParameters()
                return len(prms)

    def getCodeUnitsFromFunctionStartToRef(self, func, ref_addr):
        listing = currentProgram.getListing()
        addr_set_view = func.getBody()
        reference_code_unit = listing.getCodeUnitAt(ref_addr)
        min_address = reference_code_unit.getMinAddress()

        previous_code_unit = listing.getCodeUnitBefore(min_address)
        prev_min_address = previous_code_unit.getMinAddress()
        it = addr_set_view.getAddresses(prev_min_address, False)
        addr_set = set()
        while it.hasNext():
            addr = it.next()
            addr_set.addRange(addr, addr)

        return listing.getCodeUnits(addr_set, False)

    def checkEnoughPushes(self, cu_iterator, num_params):
        if cu_iterator is None:
            return False

        num_pushes = 0
        num_skips = 0
        while cu_iterator.hasNext() and num_pushes < num_params:
            cu = cu_iterator.next()
            if num_skips > 0:
                num_skips -= 1
            elif cu.getMnemonicString() == "CALL":
                num_params += self.num_params(cu)
            elif cu.getMnemonicString() == "PUSH":
                if num_skips > 0:
                    num_skips -= 1
                else:
                    num_pushes += 1

        return num_pushes >= num_params

    def propagateParams(self, params, cu_it, ext_func_name):
        index = 0
        num_skips = 0
        has_branch = False

        while cu_it.hasNext() and index < len(params) and not has_branch:
            cu = cu_it.next()

            # need to take into account calls between the pushes and skip the pushes for those calls
            # skip pushes that are used for another call

            if cu.getLabel() is None:
                has_branch = True
            elif cu.getMnemonicString() == "CALL":
                num_skips += self.num_params(cu)
            else:  # PUSH
                if num_skips > 0:
                    num_skips -= 1
                else:
                    set_EOL_comment(cu.getMinAddress(), params[index].getDataType().getName() + f" {params[index].getName()} for {ext_func_name}")
                    add_result(params[index].getName(), params[index].getDataType(), cu.getMinAddress(), ext_func_name)
                    index += 1

    def addResult(self, name, dataType, addr, calledFunctionName):
        self.results.append(PushedParamInfo(name, dataType, addr, calledFunctionName))

class PushedParamInfo:
    def __init__(self, name, dataType, addr, called_function_name):
        self.name = name
        self.dataType = dataType
        self.addr = addr
        self.calledFunctionName = called_function_name

    def getName(self):
        return self.name

    def getDataType(self):
        return self.dataType

    def getAddress(self):
        return self.addr

    def getCalledFunctionName(self):
        return self.calledFunctionName