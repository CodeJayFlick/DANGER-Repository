import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction, Listing
from ghidra.program.model.reloc import Relocation, RelocationTable
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.symbol import *

class CreateRelocationBasedOperandReferences(GhidraScript):
    def run(self):
        if self.currentProgram is None:
            print("No active Program to analyze")
            return

        listing = self.currentProgram.getListing()
        ref_mgr = self.currentProgram.getReferenceManager()
        equate_table = self.currentProgram.getEquateTable()
        symbol_table = self.currentProgram.getSymbolTable()

        relocation_table = self.currentProgram.getRelocationTable()
        if relocation_table.getSize() == 0:
            print("Program does not have relocations")
            return

        for r in relocation_table.getRelocations():
            monitor.incrementProgress(1)

            instruction = listing.getInstructionAt(r.getAddress())
            if instruction is None:
                continue

            equate = None
            symbol = None
            value = 0

            symbols = symbol_table.getLabelOrFunctionSymbols(r.getSymbolName(), None)
            if len(symbols) == 0:
                # check for possible equate definition
                equate = equate_table.getEquate(r.getSymbolName())
                if equate is None:
                    continue
                value = equate.getValue()
            elif len(symbols) == 1:
                symbol = symbols[0]
                address = symbol.getAddress()
                if address.getAddressSpace().getAddressableUnitSize() != 1:
                    continue
                value = address.getOffset()
            else:
                continue

            references_from = None

            op_count = instruction.getNumOperands()
            for i in range(op_count):
                scalar = self.get_scalar_operand(instruction.getDefaultOperandRepresentationList(i))
                if scalar is None or scalar.getUnsignedValue() != value:
                    continue
                if references_from is None:
                    references_from = ref_mgr.getReferencesFrom(instruction.getAddress())
                if self.has_reference(references_from, i):
                    continue  # reference exists on operand

                if equate_table.getEquates(instruction.getAddress(), i).size() > 0:
                    continue  # equate reference exists on operand
                if symbol is not None:
                    ref = ref_mgr.addMemoryReference(instruction.getAddress(),
                        symbol.getAddress(), RefType.DATA, SourceType.ANALYSIS, i)
                    ref_mgr.setAssociation(symbol, ref)
                else:
                    equate.addReference(instruction.getAddress(), i)

            print("Added " + str(ref_count) + " relocation-based references")

    def get_scalar_operand(self, default_operand_representation_list):
        s = None
        for obj in default_operand_representation_list:
            if isinstance(obj, str):
                continue
            elif isinstance(obj, int):
                continue
            elif isinstance(obj, Scalar):
                if s is not None:
                    return None  # more than one scalar found
                s = obj
            else:
                return None  # non-scalar found
        return s

    def has_reference(self, references_from, op_index):
        for r in references_from:
            if r.getOperandIndex() == op_index:
                return True
        return False


# Usage example:
script = CreateRelocationBasedOperandReferences()
script.run()
