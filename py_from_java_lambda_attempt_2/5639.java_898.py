Here is the translation of the Java code into Python:

```Python
class XReferenceUtil:
    EMPTY_ADDR_ARRAY = []
    EMPTY_REF_ARRAY = []

    ALL_REFS = -1

    def __init__(self):
        pass

    @staticmethod
    def get_xref_list(cu, max_number=-1):
        if cu.get_program() is None:
            return XReferenceUtil.EMPTY_ADDR_ARRAY
        
        xref_list = []
        
        # lookup the direct xrefs to the current code unit
        reference_iterator = cu.get_program().get_reference_manager().get_references_to(cu.min_address())
        while reference_iterator.has_next():
            ref = reference_iterator.next()
            xref_list.append(ref.from_address)
            
            if max_number > 0 and len(xref_list) == max_number:
                break
        
        address_array = [x for x in xref_list]
        return sorted(address_array)

    @staticmethod
    def get_xreferences(cu, max_number=-1):
        if cu.get_program() is None:
            return XReferenceUtil.EMPTY_REF_ARRAY
        
        xref_list = []
        
        # lookup the direct xrefs to the current code unit
        reference_iterator = cu.get_program().get_reference_manager().get_references_to(cu.min_address())
        while reference_iterator.has_next():
            ref = reference_iterator.next()
            xref_list.append(ref)
            
            if max_number > 0 and len(xref_list) == max_number:
                break
        
        # Check for thunk reference
        function = cu.get_program().get_function_manager().get_function_at(cu.min_address())
        
        if function is not None:
            thunk_addresses = function.function_thunk_addresses
            
            if thunk_addresses is not None:
                for addr in thunk_addresses:
                    xref_list.append(ThunkReference(addr, function.entry_point))
                    
        return sorted(xref_list)

    @staticmethod
    def get_offcut_xref_list(cu, max_number=-1):
        if cu.get_program() is None:
            return XReferenceUtil.EMPTY_ADDR_ARRAY
        
        offcut_list = []
        
        # Lookup the offcut xrefs...
        if cu.length > 1:
            reference_manager = cu.get_program().get_reference_manager()
            
            address_set = AddressSet(cu.min_address.add(1), cu.max_address)
            address_iterator = reference_manager.reference_destination_iterator(address_set, True)
            
            while address_iterator.has_next():
                addr = address_iterator.next()
                
                if addr is not None:
                    reference_iterator = reference_manager.get_references_to(addr)
                    
                    while reference_iterator.has_next():
                        ref = reference_iterator.next()
                        
                        offcut_list.append(ref.from_address)
                        
                        if max_number > 0 and len(offcut_list) == max_number:
                            break
        
        return sorted([x for x in offcut_list])

    @staticmethod
    def get_offcut_xreferences(cu, max_number=-1):
        if cu.get_program() is None:
            return XReferenceUtil.EMPTY_REF_ARRAY
        
        offcut_list = []
        
        # Lookup the offcut xrefs...
        if cu.length > 1:
            reference_manager = cu.get_program().get_reference_manager()
            
            address_set = AddressSet(cu.min_address.add(1), cu.max_address)
            address_iterator = reference_manager.reference_destination_iterator(address_set, True)
            
            while address_iterator.has_next():
                addr = address_iterator.next()
                
                if addr is not None:
                    reference_iterator = reference_manager.get_references_to(addr)
                    
                    while reference_iterator.has_next():
                        ref = reference_iterator.next()
                        
                        offcut_list.append(ref)
                        
                        if max_number > 0 and len(offcut_list) == max_number:
                            break
        
        return sorted([x for x in offcut_list])

    @staticmethod
    def get_offcut_xref_count(cu):
        if cu.get_program() is None:
            return 0
        
        ref_count = 0
        
        # Lookup the offcut xrefs...
        if cu.length > 1:
            reference_manager = cu.get_program().get_reference_manager()
            
            address_set = AddressSet(cu.min_address.add(1), cu.max_address)
            address_iterator = reference_manager.reference_destination_iterator(address_set, True)
            
            while address_iterator.has_next():
                addr = address_iterator.next()
                
                if addr is not None:
                    reference_iterator = reference_manager.get_references_to(addr)
                    
                    while reference_iterator.has_next():
                        ref_iter = reference_iterator
                        while ref_iter.has_next():
                            ref_iter.next()
                            ref_count += 1
        
        return ref_count

    @staticmethod
    def get_variable_refs(var, xrefs, offcuts):
        addr = var.min_address
        if addr is None:
            return
        
        program = var.function.get_program()
        reference_manager = program.reference_manager
        
        vrefs = reference_manager.references_to(var)
        
        for vref in vrefs:
            if addr == vref.to_address:
                xrefs.append(vref)
            else:
                offcuts.append(vref)

    @staticmethod
    def get_variable_refs_set(var):
        results = set()
        addr = var.min_address
        
        if addr is None:
            return results
        
        program = var.function.get_program()
        reference_manager = program.reference_manager
        
        vrefs = reference_manager.references_to(var)
        
        for vref in vrefs:
            results.add(vref)
        
        return results

    @staticmethod
    def show_all_xrefs(navigatable, service_provider, service, location, xrefs):
        model = ReferencesFromTableModel(list(xrefs), service_provider, location.program)
        provider = service.show_table("XRefs to " + str(location.address) + "", "XRefs", model, "XRefs", navigatable)
        provider.install_remove_items_action()

    @staticmethod
    def get_all_xrefs(location):
        cu = DataUtilities.get_data_at_location(location)
        
        if cu is None:
            addr = location.address
            listing = location.program.listing
            
            cu = listing.code_unit_containing(addr)
            
        xrefs = XReferenceUtil.get_xreferences(cu, XReferenceUtil.ALL_REFS)
        offcuts = XReferenceUtil.get_offcut_xref_list(cu, XReferenceUtil.ALL_REFS)

        # Remove duplicates
        set = set()
        
        for ref in xrefs:
            set.add(ref)
            
        for ref in offcuts:
            set.add(ref)
        
        return set

class AddressSet(set):
    def __init__(self, start_address, end_address):
        super().__init__()
        
        self.start_address = start_address
        self.end_address = end_address
        
    @staticmethod
    def from_addresses(start_address, end_address):
        return AddressSet(start_address, end_address)

class ReferenceIterator:
    def __init__(self, reference_manager, address_set):
        self.reference_manager = reference_manager
        self.address_set = address_set
        self.current_address = None

    def has_next(self):
        if self.current_address is not None and self.current_address >= self.address_set.end_address:
            return False
        
        return True

    def next(self):
        if self.has_next():
            self.current_address += 1
            return Reference.from_addresses(self.reference_manager, self.current_address)
        
        raise StopIteration()

class ThunkReference(Reference):
    def __init__(self, address, entry_point):
        super().__init__()
        self.address = address
        self.entry_point = entry_point

    @staticmethod
    def from_addresses(address, entry_point):
        return ThunkReference(address, entry_point)

class Reference:
    EMPTY_REF_ARRAY = []

    ALL_REFS = -1

    def __init__(self):
        pass

    @staticmethod
    def from_addresses(reference_manager, address):
        # TO DO: implement this method
        pass

    def get_from_address(self):
        return self.address

class Address:
    def __init__(self):
        pass

    def add(self, value):
        # TO DO: implement this method
        pass

class CodeUnit:
    def __init__(self):
        pass

    @property
    def min_address(self):
        # TO DO: implement this property
        return None

    @property
    def max_address(self):
        # TO DO: implement this property
        return None

    @property
    def length(self):
        # TO DO: implement this property
        return 0

class Variable:
    def __init__(self):
        pass

    @property
    def min_address(self):
        # TO DO: implement this property
        return None

    @property
    def function(self):
        # TO DO: implement this property
        return None

class ProgramLocation:
    def __init__(self, program):
        self.program = program

    @property
    def address(self):
        # TO DO: implement this property
        pass

    @property
    def get_program(self):
        return self.program

class ThunkReference(Reference):
    def __init__(self, address, entry_point):
        super().__init__()
        self.address = address
        self.entry_point = entry_point

    @staticmethod
    def from_addresses(address, entry_point):
        return ThunkReference(address, entry_point)

class ReferencesFromTableModel:
    def __init__(self, references, service_provider, program):
        self.references = references
        self.service_provider = service_provider
        self.program = program

    @property
    def get_references(self):
        return self.references

    @property
    def get_service_provider(self):
        return self.service_provider

    @property
    def get_program(self):
        return self.program