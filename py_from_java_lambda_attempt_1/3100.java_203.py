Here is the translation of the given Java code into Python:

```Python
import ghidra_script as script
from ghidra_program import Program
from ghidra_bookmark import Bookmark
from ghidra_util import Msg

class ReportDisassemblyErrors(script.GhidraScript):
    def run(self):
        prog = self.currentProgram
        bookmark_iter = prog.getBookmarkManager().getBookmarksIterator("Error")
        count = 0
        while bookmark_iter.hasNext():
            bookmark_iter.next()
            count += 1
        
        Msg.info(self, f"REPORT DISASSEMBLY ERROR BOOKMARKS: {prog.getName()}: {count} disassembly error bookmarks.")

if __name__ == "__main__":
    script.run_script(ReportDisassemblyErrors())
```

Please note that this Python code is not a direct translation of the Java code. It's more like an equivalent implementation in Python, as there are some differences between the two languages.