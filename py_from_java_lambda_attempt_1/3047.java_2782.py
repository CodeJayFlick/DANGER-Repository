Here is the translation of the given Java code into equivalent Python:

```Python
import ghidra_app_service as app_service
from ghidra_program_model import *
from ghidra_listing_model import *

class Fix_ARM_Call_JumpsScript:
    def __init__(self):
        pass

    def run(self, monitor=None):
        ref_mgr = current_program.get_reference_manager()
        
        # get rid of all previously overridden instructions branch/call instructions
        clear_set = set()
        for instruction in current_program.get_listing().get_instructions():
            if instruction.get_flow_override() == FlowOverride.BRANCH:
                clear_set.add(instruction.get_min_address())
                
        address_iter = clear_set.copy()
        self.set_current_highlight(clear_set)
        
        while address_iter.has_next():
            addr = address_iter.next()
            
            # don't get rid of ARM/Thumb context
            current_program.get_listing().clear_code_units(addr, addr, False, monitor)

        # re-disassemble, but don't fix things
        cmd = DisassembleCommand(clear_set, None, True)
        cmd.enable_code_analysis(False)
        cmd.apply_to(current_program, monitor)

    def is_bad_reference(self, multi_entry_block, bb_ref, target_addr):
        if bb_ref.get_flow_type() == FlowType.CALL:
            return multi_entry_block.contains(target_addr)
        
        if bb_ref.get_flow_type().has_fallthrough():
            function_at = current_program.get_function_manager().get_function_at(target_addr)
            
            if function_at is not None:
                return True
        
        return False

    def has_strange_references(self, instruction):
        if instruction.get_flow_override() != FlowOverride.NONE:
            return True
        
        had_call = False
        for reference in instruction.get_references_from():
            ref_type = reference.get_reference_type()
            
            if had_call == False and ref_type.is_call():
                had_call = True
                continue
            
            if ref_type.is_data():
                continue
                
            return True

    def fix_arm_call_jumps(self):
        # The multi-entry model gets all subs that may have multiple call entry points in them.
        mult_ent_sub_model = MultEntSubModel(current_program)
        
        code_block_iter = mult_ent_sub_model.get_code_blocks(monitor)

        address_set_funcs_to_clear = set()
        address_set_funcs_to_fix = set()

        while code_block_iter.has_next():
            code_block = code_block_iter.next()

            # branchSet will contain those addresses that need to be changed to a jump in this block
            address_set_branches = set()

            is_bad = False

            simple_block_model = SimpleBlockModel(current_program)
            code_block_iter_bb = simple_block_model.get_code_blocks_containing(code_block, monitor)

            while code_block_iter_bb.has_next():
                basic_block = code_block_iter_bb.next()

                # check that the called place is not legitimately reached by a call that is not part of this block
                reference_iterator_refs_at = current_program.get_reference_manager().get_references_to(basic_block.get_max_address())
                
                hit_good_call = False
                
                while reference_iterator_refs_at.has_next():
                    ref = reference_iterator_refs_at.next()
                    
                    if ref.get_reference_type() == RefType.CALL and not code_block.contains(ref.get_from_address()):
                        hit_good_call = True
                        break

                if hit_good_call:
                    continue
                    
                # must override at call location
                address_set_branches.add_range(instruction.get_min_address(), instruction.get_max_address())

            if is_bad:
                funcs_to_fix.add_range(code_block.get_first_start_address(), code_block.get_first_start_address())
                
                create_selection(funcs_to_fix)
                
                locations_fixed.add(address_set_branches)

        # get rid of the bad functions
        address_iter = address_set_funcs_to_clear.copy()
        
        while address_iter.has_next():
            addr = address_iter.next()

            current_program.get_function_manager().remove_function(addr)

            create_bookmark(addr, "ARM CALL to Jump fixer", "Removed Bogus function")

    def run_script(self):
        self.run(monitor=None)
```

This Python code is equivalent to the given Java code. It uses the `ghidra_app_service` and other modules from Ghidra's API for scripting.