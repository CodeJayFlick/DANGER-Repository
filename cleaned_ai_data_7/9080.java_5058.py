class MemoryBlocksValidator:
    def __init__(self, source_program, destination_program, existing_results):
        self.source_program = source_program
        self.destination_program = destination_program
        self.existing_results = existing_results

    def do_run(self, monitor):
        status = "Passed"
        warnings = ""

        source_prog_name = self.source_program.get_domain_file().get_name()
        dest_prog_name = self.destination_program.get_domain_file().get_name()

        source_blocks = self.source_program.get_memory().get_blocks()
        dest_blocks = self.destination_program.get_memory().get_blocks()

        num_source_blocks = len(source_blocks)
        num_dest_blocks = len(dest_blocks)

        if num_source_blocks >= num_dest_blocks:
            blocks_to_compare = num_dest_blocks
            blocks_needed_for_perfect_match = num_source_blocks
        else:
            blocks_to_compare = num_source_blocks
            blocks_needed_for_perfect_match = num_dest_blocks

        matches = 0
        matching_names = 0

        monitor.set_indeterminate(False)
        monitor.initialize(blocks_to_compare)

        for i in range(blocks_to_compare):
            block_name = dest_blocks[i].get_name()
            matching_block = self.source_program.get_memory().get_block(block_name)
            if matching_block is not None:
                matches += 1
                source_perm = matching_block.get_permissions()
                if source_perm == dest_blocks[i].get_permissions():
                    continue
                else:
                    warnings += f"Block {dest_prog_name}:{block_name} doesn't match permissions of {source_prog_name}:{block_name}\n"
                    status = "Warning"

            else:
                warnings += f"Block {dest_prog_name}:{block_name} doesn't appear in {source_prog_name}\n"
                status = "Warning"

        if matches != blocks_needed_for_perfect_match:
            if matches == blocks_to_compare and num_source_blocks > matches:
                addl = num_source_blocks - matches
                plural = "" if addl < 2 else "s"
                warnings += f"{source_prog_name} has {addl} more block{plural} than {dest_prog_name} (but the rest match)\n"

            elif dest_num_blocks > matches:
                addl = num_dest_blocks - matches
                plural = "" if addl < 2 else "s"
                warnings += f"{dest_prog_name} has {addl} more block{plural} than {source_prog_name} (but the rest match)\n"

        if matching_names == blocks_needed_for_perfect_match:
            warnings += "\nSUMMARY: Number and names of blocks match but not all permissions match."
        else:
            warnings += "\nSUMMARY: Number, names, and permissions of blocks do not all match"

        return {"status": status, "warnings": warnings}

    def get_description(self):
        return "Make sure the memory blocks in both programs match up."

    def get_name(self):
        return "Memory Blocks Validator"
