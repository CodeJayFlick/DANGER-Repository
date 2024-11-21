Here is the equivalent Python code:

```Python
import ghidra_script as script

class DeleteDeadDefaultPlatesScript(script.GhidraScript):
    DEAD_PLATE = "DEAD"

    def run(self):
        listing = self.current_program.get_listing()
        set = self.current_program.get_memory()

        if self.current_selection is not None and not self.current_selection.empty:
            set = self.current_selection
        update_count = 0

        for addr in listing.comment_address_iterator(script.CodeUnit.PLATE_COMMENT, set, True):
            cu = listing.get_code_unit_at(addr)
            if cu is not None:
                comment = cu.get_comment_as_array(script.CodeUnit.PLATE_COMMENT)
                if len(comment) == 1 and comment[0] == self.DEAD_PLATE:
                    cu.set_comment(script.CodeUnit.PLATE_COMMENT, None)
                    update_count += 1

        if update_count > 0:
            cmt = "comments" if update_count > 1 else "comment"
            print(f"Removed {update_count} default plate {cmt}.")
        else:
            print("Did not find any dead plate comments.")
```

Please note that you need to have the `ghidra_script` module installed and imported in your Python environment for this code to work.