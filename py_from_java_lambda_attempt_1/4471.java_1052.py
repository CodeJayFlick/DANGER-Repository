Here is a translation of the provided Java code into equivalent Python:

```Python
class FdeTable:
    def __init__(self, monitor, prog):
        self.monitor = monitor
        self.prog = prog
        self.fde_table_entry = {"initial_loc": None, "data_loc": None}

    def init_fde_table_data_type(self, decoder):
        encoded_dt = decoder.get_data_type(self.prog)
        
        if not isinstance(encoded_dt, dict) or len(encoded_dt) <= 0:
            raise Exception("Cannot build FDE structure with Dynamic or Void value type")
            
        if any(dt['length'] > 0 for dt in encoded_dt.values()):
            raise Exception("Cannot build FDE structure with dynamically-sized value type")

        self.fde_table_entry = {"initial_loc": None, "data_loc": None}

    def create(self, addr, decoder, fde_table_cnt):
        if not isinstance(addr, int) or not isinstance(decoder, dict) or not isinstance(fde_table_cnt, int):
            return

        self.init_fde_table_data_type(decoder)

        data_cmd = None
        cur_fde_table_cnt = 0
        
        while True:
            if addr >= fde_table_cnt:
                break
            
            if self.monitor.is_cancelled():
                return

            # Create a new FDE structure
            data_cmd = {"fde_structure": (self.fde_table_entry, addr)}
            
            # -- Create references to the 'initial location' and 'data location'
            fde_table_data = self.prog.get_listing().get_data_at(addr)
            fde_struct = fde_table_data['data_type']
            
            loc_component_addr = addr + fde_struct[0]['offset']
            data_component_addr = addr + fde_struct[1]['offset']

            # this is an indirect reference to code from the table,
            #  so tag reference as an indirect code flow
            self.prog.get_reference_manager().add_memory_reference(loc_component_addr, loc_component_addr, 'INDIRECTION', 'ANALYSIS')
            
            self.prog.get_reference_manager().add_memory_reference(data_component_addr, data_component_addr, 'DATA', 'ANALYSIS')

            # Increment curAddress by number of bytes in a FDE Table entry
            cur_fde_table_cnt += 1
            addr = addr + len(self.fde_table_entry)

            self.monitor.increment_progress(1)
```

Please note that Python does not support direct translation from Java code. It requires manual rewriting and may result in different syntax, semantics or functionality compared to the original Java code.