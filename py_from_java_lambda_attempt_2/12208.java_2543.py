Here is the translation of the given Java code to Python:

```Python
class DisambiguateByParentWithOrder:
    def calc_hashes(self, inst_hash, match_size, store):
        result = []
        block = inst_hash.get_block()
        iter = block.orig_block.get_sources(store.get_monitor())
        start_addr = block(orig_block).get_min_address()

        while(iter.has_next()):
            ref = iter.next()
            src_block = store.get_block(ref.get_source_address())

            if(src_block is not None and src_block.get_match_hash() != 0):
                src_iter = src_block.orig_block.get_destinations(store.get_monitor())
                
                total_count = 0
                count = 0

                while(src_iter.has_next()):
                    addr = src_iter.next().get_destination_address()
                    total_count += 1
                    
                    if(addr < start_addr):  # If child is earlier than block
                        count += 1                     #   increment index
                        
                if(total_count <= 1):
                    continue  # If no siblings, this does no better than ParentStrategy

                result.append(Hash(count))

        return result


class Hash:
    def __init__(self, value, size):
        self.value = value
        self.size = size

# Note: This code assumes that you have a class called 'InstructHash', 'Block' and 'Store'
```

This Python translation is based on the given Java code. The main difference between Java and Python is in their syntax and semantics, but they are both object-oriented programming languages with similar concepts like classes, objects, inheritance, polymorphism, etc.