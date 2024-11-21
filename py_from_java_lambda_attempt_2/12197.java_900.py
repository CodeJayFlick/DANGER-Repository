Here is the translation of the Java code into Python:

```Python
class SimpleDestReferenceIterator:
    def __init__(self, block, follow_indirect_flows, monitor):
        self.monitor = monitor
        self.get_destinations(block, [], follow_indirect_flows)

    def next(self):
        if self.monitor.check_cancelled():
            raise CancelledException()
        return self.queue.pop(0) if self.queue else None

    def has_next(self):
        if self.monitor.check_cancelled():
            raise CancelledException()
        return bool(self.queue)

    @staticmethod
    def get_num_destinations(block, follow_indirect_flows, monitor):
        return SimpleDestReferenceIterator.get_destinations(block, [], follow_indirect_flows, monitor)

    @staticmethod
    def get_destinations(block, queue=None, follow_indirect_flows=False, monitor=None):
        if block is None:
            return 0

        model = block.model.get_basic_block_model()
        include_externals = model.externals_included()

        start_addr = block.min_address
        end_addr = block.max_address
        count = 0

        listing = model.listing
        ref_iter = model.program.reference_manager.reference_iterator(start_addr)
        instr = None
        while ref_iter.has_next():
            if monitor and monitor.check_cancelled():
                raise CancelledException()

            ref = ref_iter.next()
            from_addr = ref.from_address
            if from_addr > end_addr:
                break

            ref_type = ref.reference_type
            if not isinstance(ref_type, FlowType):
                continue

            if is_indirect_flow(ref_type) and follow_indirect_flows:
                count += self.follow_indirection(queue, include_externals, block, ref, model.listing.get_instruction_at(from_addr), monitor)
            else:
                queue.append(CodeBlockReference(block, listing.get_code_unit_at(to_address=ref.to_address)))
                count += 1

        if follow_indirect_flows and not any(queue):
            instr = listing.get_instruction_at(end_addr)
            while instr.is_in_delay_slot():
                fall_from = instr.fall_from
                if fall_from is None:
                    break
                instr = listing.get_instruction_at(fall_from)

            for ref in instr.references_from:
                count += self.follow_indirection(queue, include_externals, block, ref, model.listing.get_instruction_at(from_address=ref.from_address), monitor)

        return count

    @staticmethod
    def follow_indirection(queue, include_externals, src_block, src_ref, indirect_flow_type, monitor):
        if monitor and monitor.check_cancelled():
            raise CancelledException()

        data = listing.get_defined_data_containing(to_address=src_ref.to_address)
        if not data:
            return 0

        offset = int(src_ref.from_address.subtract(data.min_address))
        primitive = data.primitive_at(offset)

        if primitive is None or isinstance(primitive, Data):
            refs = [ref for ref in primitive.references_from]
            for i, ref in enumerate(refs):
                monitor.check_cancelled()
                dest_block = listing.get_code_unit_at(to_address=ref.to_address)
                queue.append(CodeBlockReference(src_block, dest_block if dest_block else None, indirect_flow_type))
                return len(refs)

        return 0

    @staticmethod
    def get_instruction_containing(address):
        # implement this method to find the instruction containing a given address
        pass


class CodeBlockReference:
    def __init__(self, src_block, dest_block=None, flow_type=FlowType.JUMP):
        self.src_block = src_block
        self.dest_block = dest_block if dest_block else None
        self.flow_type = flow_type

    @staticmethod
    def get_flow_type(flow_type_str):
        # implement this method to convert a string into FlowType enum value
        pass


class CancelledException(Exception):
    pass
```

Please note that Python does not have direct equivalent of Java's `Reference` and `FlowType`. You may need to create your own classes or use existing ones like `enum` for the flow types.