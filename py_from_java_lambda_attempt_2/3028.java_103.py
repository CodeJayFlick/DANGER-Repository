Here is the translation of the given Java code into Python:

```Python
import ghidra

class FindAndReplaceCommentScript:
    def __init__(self):
        self.COMMENT_TYPES = ["EOL", "Pre", "Post", "Plate", "Repeatable"]

    def run(self):
        script_manager = ghidra.app.service.ScriptManager()
        current_program = script_manager.getCurrentProgram()

        listing = current_program.getListing()
        memory = current_program.getMemory()

        to_find = input("Enter Search String: ")
        to_replace = input("Enter Replace String: ")

        replaced = False

        for comment_type in self.COMMENT_TYPES:
            address_iterator = listing.getCommentAddressIterator(memory, True)

            while address_iterator.hasNext():
                address = address_iterator.next()
                comment_value = listing.getComment(comment_type, address)

                if comment_value is not None and to_find in str(comment_value):
                    replaced = True
                    new_comment_value = str(comment_value).replace(to_find, to_replace)
                    listing.setComment(address, comment_type, bytes(new_comment_value.encode()))
                    print(f"Changed {comment_type} Comment at address {address.toString()}.")

        if not replaced:
            print("No comment found with that value.")
```

Please note that you need to have the `ghidra` library installed in your Python environment.