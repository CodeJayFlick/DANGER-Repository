class FunctionManager:
    def __init__(self):
        pass  # Initialize any necessary attributes or data structures here.

    def get_program(self) -> 'Program':
        """Returns this manager's program"""
        raise NotImplementedError("Method not implemented")

    def get_calling_convention_names(self) -> list[str]:
        """Gets the names associated with each of the current calling conventions associated with this
           program. Within the exception of "unknown", all of these calling convention names should have
           a PrototypeModel.
        """
        raise NotImplementedError("Method not implemented")

    def get_default_calling_convention(self) -> 'PrototypeModel':
        """Gets the default calling convention's prototype model in this program"""
        raise NotImplementedError("Method not implemented")

    def get_calling_convention(self, name: str) -> 'PrototypeModel' | None:
        """Gets the prototype model of the calling convention with the specified name in this program
           @param name the calling convention name
           @return the named function calling convention prototype model or null.
        """
        raise NotImplementedError("Method not implemented")

    def get_calling_conventions(self) -> list['PrototypeModel']:
        """Gets all the calling convention prototype models in this program that have names"""
        raise NotImplementedError("Method not implemented")

    def create_function(self, name: str | None, entry_point: 'Address', body: set['Address'], source_type: 'SourceType') -> 'Function' | None:
        """Create a function with the given body at entry point within the global namespace.
           @param name the name of the new function or null for default name
           @param entryPoint entry point of function
           @param body addresses contained in the function body
           @param source the source of this function
           @return new function or null if one or more functions overlap the specified body address set.
        """
        raise NotImplementedError("Method not implemented")

    def create_function(self, name: str | None, namespace: 'Namespace', entry_point: 'Address', body: set['Address'], source_type: 'SourceType') -> 'Function' | None:
        """Create a function with the given body at entry point.
           @param name the name of the new function or null for default name
           @param nameSpace the nameSpace in which to create the function
           @param entryPoint entry point of function
           @param body addresses contained in the function body
           @param source the source of this function
        """
        raise NotImplementedError("Method not implemented")

    def create_thunk_function(self, name: str | None, namespace: 'Namespace', entry_point: 'Address', body: set['Address'], thunked_function: 'Function', source_type: 'SourceType') -> 'Function' | None:
        """Create a thunk function with the given body at entry point.
           @param name the name of the new function or null for default name
           @param nameSpace the nameSpace in which to create the function
           @param entryPoint entry point of function
           @param body addresses contained in the function body
           @param thunkedFunction referenced function (required is creating a thunk function)
        """
        raise NotImplementedError("Method not implemented")

    def get_function_count(self) -> int:
        """Returns the total number of functions in the program including external functions"""
        raise NotImplementedError("Method not implemented")

    def remove_function(self, entry_point: 'Address') -> bool:
        """Remove a function defined at entryPoint
           @param entryPoint the entry point
        """
        raise NotImplementedError("Method not implemented")

    def get_function_at(self, entry_point: 'Address') -> 'Function' | None:
        """Get the function at entryPoint
           @param entryPoint the entry point
        """
        raise NotImplementedError("Method not implemented")

    def get_referenced_function(self, address: 'Address') -> 'Function' | None:
        """Get the function which resides at the specified address or is referenced from the specified 
           address
           @param address function address or address of pointer to a function.
        """
        raise NotImplementedError("Method not implemented")

    def get_function_containing(self, addr: 'Address') -> 'Function' | None:
        """Get a function containing an address. 
           @param addr address within the function
        """
        raise NotImplementedError("Method not implemented")

    def get_functions(self, forward: bool) -> Iterator['Function']:
        """Returns an iterator over all non-external functions in address (entry point) order"""
        raise NotImplementedError("Method not implemented")

    def get_functions(self, start: 'Address', forward: bool) -> Iterator['Function']:
        """Get an iterator over non-external functions starting at an address and ordered by entry
           address
        """
        raise NotImplementedError("Method not implemented")

    def get_functions(self, asv: set['Address'], forward: bool) -> Iterator['Function']:
        """Get an iterator over functions with entry points in the specified address set. Function are 
           ordered based upon entry address.
        """
        raise NotImplementedError("Method not implemented")

    def get_functions_no_stubs(self, forward: bool) -> Iterator['Function']:
        """Returns an iterator over all REAL functions in address (entry point) order  (real functions
           have instructions, and aren't stubs)
        """
        raise NotImplementedError("Method not implemented")

    def get_functions_no_stubs(self, start: 'Address', forward: bool) -> Iterator['Function']:
        """Get an iterator over REAL functions starting at an address and ordered by entry address 
           (real functions have instructions, and aren't stubs).
        """
        raise NotImplementedError("Method not implemented")

    def get_functions_no_stubs(self, asv: set['Address'], forward: bool) -> Iterator['Function']:
        """Get an iterator over REAL functions with entry points in the specified address set 
           (real functions have instructions, and aren't stubs). Functions are ordered based upon entry
           address.
        """
        raise NotImplementedError("Method not implemented")

    def get_external_functions(self) -> Iterator['Function']:
        """Get an iterator over all external functions. Functions returned have no particular order"""
        raise NotImplementedError("Method not implemented")

    def is_in_function(self, addr: 'Address') -> bool:
        """Check if this address contains a function.
           @param addr address to check
        """
        raise NotImplementedError("Method not implemented")

    def get_functions_overlapping(self, set: set['Address']) -> Iterator['Function']:
        """Return an iterator over functions that overlap the given address set."""
        raise NotImplementedError("Method not implemented")

    def move_address_range(self, from_addr: 'Address', to_addr: 'Address', length: int, monitor: TaskMonitor) -> None:
        """Move all objects within an address range to a new location
           @param fromAddr the first address of the range to be moved
           @param toAddr the address where to the range is to be moved
           @param length the number of addresses to move
           @param monitor the task monitor to use in any upgrade operations
        """
        raise NotImplementedError("Method not implemented")

    def get_referenced_variable(self, instr_addr: 'Address', storage_addr: 'Address', size: int, is_read: bool) -> 'Variable' | None:
        """Attempts to determine which if any of the local functions variables are referenced by the 
           specified reference. In utilizing the firstUseOffset scoping model, negative offsets
           (relative to the functions entry) are shifted beyond the maximum positive offset within the
           function. While this does not account for the actual instruction flow, it is hopefully accurate enough for most situations.
        """
        raise NotImplementedError("Method not implemented")

    def get_function(self, key: int) -> 'Function' | None:
        """Get a Function object by its key"""
        raise NotImplementedError("Method not implemented")

    def get_function_tag_manager(self) -> 'FunctionTagManager':
        """Returns the function tag manager"""
        raise NotImplementedError("Method not implemented")
