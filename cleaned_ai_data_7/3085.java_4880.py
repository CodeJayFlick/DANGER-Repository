import ghidra.app.script.GhidraScript
from typing import Set, List

class PrintFunctionCallTreesScript(GhidraScript):
    def run(self) -> None:
        function = self.get_current_function()
        if function is None:
            print("Cursor is not in or on a function")
            return
        
        self.print_incoming_calls(function)
        print("\n")
        self.print_outgoing_calls(function)

    def print_incoming_calls(self, function: 'Function') -> None:
        addresses = ReferenceUtils.get_reference_addresses(FunctionSignatureFieldLocation(function.get_program(), function.get_entry_point()), monitor=self.monitor)
        calling_functions = set()
        for address in addresses:
            caller_function = function_manager.get_function_containing(address)
            if caller_function is not None:
                calling_functions.add(caller_function)

        list_of_calling_functions = sorted(list(calling_functions), key=lambda f: f.get_entry_point())
        
        for f in list_of_calling_functions:
            print(f"Incoming Function Call: {f.name} @ {f.entry_point}")

    def print_outgoing_calls(self, function: 'Function') -> None:
        addresses = set()
        references = self.get_references_from(current_program, function.body)
        outgoing_functions = set()
        
        for reference in references:
            to_address = reference.to_address
            called_function = function_manager.get_function_at(to_address)
            
            if called_function is not None:
                maybe_add_incoming_function(outgoing_functions, reference, called_function)
            else:
                print(f"Outgoing function call with no function from {reference.from_address} to {reference.to_address}")

        list_of_outgoing_functions = sorted(list(outgoing_functions), key=lambda f: f.entry_point)

        for f in list_of_outgoing_functions:
            print(f"Outgoing Function Call: {f.name} @ {f.entry_point}")

    def maybe_add_incoming_function(self, incoming_functions: set, reference: 'Reference', called_function: 'Function') -> None:
        if called_function is not None:
            incoming_functions.add(called_function)
        else:
            print(f"Outgoing function call with no function from {reference.from_address} to {reference.to_address}")

    def get_references_from(self, program: 'Program', addresses: set) -> Set['Reference']:
        references = set()
        
        for address in addresses.get_addresses():
            references.extend(program.reference_manager.get_references_from(address))
            
        return references

    def is_call_reference(self, reference: 'Reference') -> bool:
        if reference.reference_type.is_call():
            return True
        
        if reference.reference_type.is_indirect():
            listing = current_program.listing
            instruction = listing.get_instruction_at(reference.from_address)
            
            if instruction is not None:
                flow_type = instruction.flow_type
                return flow_type.is_call()
        
        return False

    def get_current_function(self) -> 'Function':
        function_manager = current_program.function_manager
        return function_manager.get_function_containing(current_address)

