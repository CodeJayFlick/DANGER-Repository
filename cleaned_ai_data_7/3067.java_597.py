import ghidra.app.script.GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import Memory
from ghidra.program.model.symbol import SymbolTable

class LabelIndirectStringReferencesScript(GhidraScript):
    def run(self) -> None:
        listing = self.currentProgram.getListing()
        memory = self.currentProgram.getMemory()
        symbol_table = self.currentProgram.getSymbolTable()

        print("Labeling indirect references to strings")

        str_addr_set = set()  # Use a set for faster lookups
        data_iterator = listing.getDefinedData(True)
        while data_iterator.hasNext():
            next_data = data_iterator.next()
            if "unicode" in next_data.getDataType().getName().lower() or "string" in next_data.getDataType().getName().lower():
                str_addr_set.add(next_data.getMinAddress())

        if not str_addr_set:
            print("No strings found. Try running 'Search -> For Strings...' first.")
            return

        print(f"Number of strings found: {len(str_addr_set)}")

        for i, addr in enumerate(str_addr_set):
            all_ref_addrs = self.find_all_references(addr)

            for j, ref_from_addr in enumerate(all_ref_addrs):
                if listing.getInstructionContaining(ref_from_addr) is None:
                    refs_to_refs = [ref.getFromAddress() for ref in self.get_references_to(ref_from_addr)]
                    if refs_to_refs:
                        new_label = f"ptr_{listing.getDataAt(addr).getLabel()}_{all_ref_addrs[j]}"
                        print(new_label)
                        symbol_table.createLabel(all_ref_addrs[j], new_label, GhidraScript.SourceType.ANALYSIS)

    def find_all_references(self, addr: Address) -> set:
        direct_reference_list = set()
        results = {addr}
        to_addr = listing.getCodeUnitContaining(addr).getMinAddress()

        try:
            ProgramMemoryUtil.loadDirectReferenceList(current_program, 1, to_addr, None, direct_reference_list)
        except CancelledException:
            return set()

        for rap in direct_reference_list:
            from_addr = current_program.getListing().getCodeUnitContaining(rap.getSource()).getMinAddress()
            if from_addr not in results:
                results.add(from_addr)

        reference_iterator = current_program.getReferenceManager().getReferencesTo(to_addr)
        while reference_iterator.hasNext():
            r = reference_iterator.next()
            from_addr = r.getFromAddress()
            if from_addr not in results:
                results.add(from_addr)

        return results

    def get_references_to(self, addr: Address) -> list:
        # This method is equivalent to the Java code
        pass  # Implement this method as needed
