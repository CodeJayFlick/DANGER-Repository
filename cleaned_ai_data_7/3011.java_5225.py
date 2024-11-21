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
