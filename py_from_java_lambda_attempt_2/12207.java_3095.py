Here is the translation of the given Java code into Python:

```Python
class DisambiguateByParent:
    ENTRY_BLOCK_HASH = 0x9a8b7c6d
    
    def calc_hashes(self, inst_hash, match_size, store):
        result = []
        block = inst_hash.get_block()
        iter = block.orig_block.get_sources(store)
        
        count = 0
        while iter.has_next():
            ref = iter.next()
            count += 1
            
            src_block = store.get_block(ref.get_source_address())
            
            if src_block is not None and src_block.match_hash != 0:
                result.append(Hash(src_block.match_hash, 1))  # Use its match hash as a disambiguator
        
        if count == 0:
            result.append(Hash(self.ENTRY_BLOCK_HASH, 1))  # Add hash indicating entry block
        return result


class Hash:
    def __init__(self, value, weight):
        self.value = value
        self.weight = weight

# Usage example:

disambiguate_strategy = DisambiguateByParent()
inst_hash = ...  # Your instance of InstructHash
match_size = ...  # Your match size
store = ...  # Your HashStore object

try:
    result = disambiguate_strategy.calc_hashes(inst_hash, match_size, store)
except CancelledException as e:
    print(f"Error: {e}")
```

Please note that this Python code is a direct translation of the given Java code. It might not be exactly what you would write in Python if you were starting from scratch, but it should work correctly for your purposes.