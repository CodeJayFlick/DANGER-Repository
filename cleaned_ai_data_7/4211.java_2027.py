class RelocationFixupCommand:
    def __init__(self, handler, old_image_base, new_image_base):
        self.relocation_handler = handler
        self.old_image_base = old_image_base
        self.new_image_base = new_image_base

    def apply_to(self, program, monitor=None):
        relocation_table = program.get_relocation_table()
        iterator = relocation_table.get_rellocations().get_iterator()

        while True:
            try:
                relocation = next(iterator)
                if not process_relocation(program, relocation):
                    mark_as_unhandled(program, relocation, "Unhandled relocation type")
            except StopIteration:
                break
            except MemoryAccessException as e:
                mark_as_unhandled(program, relocation, "Memory access Exception")
            except CodeUnitInsertionException as e:
                mark_as_unhandled(program, relocation, "Error re-creating instruction")

        if has_unhandled_relocations():
            print("One or more relocation fix-ups were not handled for the image rebase.")
            print("Bookmarks were created with the category \"Unhandled Image Base Relocation Fixup\"")

    def process_relocation(self, program, relocation):
        try:
            return self.relocation_handler.process_relocation(program, relocation, self.old_image_base, self.new_image_base)
        except Exception as e:
            return self.generic_handler.process_relocation(program, relocation, self.old_image_base, self.new_image_base)

    def mark_as_unhandled(self, program, relocation, reason):
        bookmark_manager = program.get_bookmark_manager()
        address = relocation.get_address()

        bookmark_manager.set_bookmark(address, "Unhandled Image Base Relocation Fixup", f"Reason: {reason}")

        global has_unhandled_relocations
        has_unhandled_relations = True

    def get_has_unhandled_relocations(self):
        return self.has_unhandled_relocations


class BookmarkManager:
    def set_bookmark(self, address, category, bookmark_name, reason):
        pass  # Implement this method as needed


class Program:
    def __init__(self):
        self.relocation_table = None
        self.bookmark_manager = BookmarkManager()

    def get_relocation_table(self):
        return self.relocation_table

    def get_bookmark_manager(self):
        return self.bookmark_manager


# Example usage:

program = Program()
relocation_handler = RelocationFixupHandler()  # Implement this class as needed
old_image_base = Address(0x10000000)
new_image_base = Address(0x20000000)

command = RelocationFixupCommand(relocation_handler, old_image_base, new_image_base)
command.apply_to(program)
