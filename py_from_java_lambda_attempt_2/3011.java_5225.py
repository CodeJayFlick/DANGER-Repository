Here is the translation of the given Java code into Python:

```Python
import ghidra

class DeleteFunctionDefaultPlatesScript:
    DEFAULT_PLATE = " FUNCTION"

    def run(self):
        current_program = ghidra.currentProgram()
        set = None
        if hasattr(ghidra, 'currentSelection') and getattr(ghidra.currentSelection(), 'isEmpty', lambda: True)():
            set = ghidra.currentSelection()
        else:
            set = current_program.getMemory()

        update_count = 0
        for function in current_program.getFunctionManager().getFunctions(set):
            comment = function.getCommentAsArray()
            if len(comment) == 1 and comment[0].lower() == self.DEFAULT_PLATE.lower():
                function.setComment(None)
                update_count += 1

        if update_count > 0:
            cmt = "comments" if update_count > 1 else "comment"
            print(f"Removed {update_count} default plate {cmt}.")
        else:
            print("Did not find any default plate comments.")

if __name__ == "__main__":
    script = DeleteFunctionDefaultPlatesScript()
    try:
        script.run()
    except Exception as e:
        print(str(e))
```

Please note that this code is a direct translation of the given Java code into Python. It uses the `ghidra` module, which seems to be specific to Ghidra's scripting API and may not work with other Python environments or modules.