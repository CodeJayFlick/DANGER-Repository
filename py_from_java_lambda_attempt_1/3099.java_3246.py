Here is the translation of the given Java code into Python:

```Python
import ghidra_app_script as script

class ReplaceInComments(script.GhidraScript):
    def run(self):
        # get target string
        tgt_str = self.ask_string("Target string", "Target String")
        if not tgt_str:
            return
        
        # get replacement string
        repl_str = self.ask_string("Replacement string", "Replacement String")
        if not repl_str:
            return

        count = 0
        blocks = self.get_memory_blocks()

        for i, m in enumerate(blocks):
            print(f"Scanning block beginning at 0x{m.start().to_hex()}")
            a = m.start()
            while True:
                try:
                    cur_comment = self.get_eol_comment(a)
                    if cur_comment is not None:
                        new_comment = cur_comment.replace(tgt_str, repl_str)
                        if cur_comment != new_comment:
                            print(f"   0x{a.to_hex()}: {new_comment}")
                            self.set_eol_comment(a, new_comment)
                            count += 1
                    a = a.add(1)
                except Exception as e:
                    print(str(e))
                    return

        funcs = self.current_program.get_listing().get_functions(True)
        while True:
            try:
                f = next(funcs)
                cur_comment = f.comment()
                if cur_comment is not None:
                    new_comment = cur_comment.replace(tgt_str, repl_str)
                    if cur_comment != new_comment:
                        print(f"    {f.name()}.comment")
                        f.set_comment(new_comment)
                        count += 1
            except StopIteration:
                break

        for v in f.get_local_variables():
            cur_comment = v.comment()
            if cur_comment is not None:
                new_comment = cur_comment.replace(tgt_str, repl_str)
                if cur_comment != new_comment:
                    print(f"    {f.name()}: {v.name()}: {new_comment}")
                    v.set_comment(new_comment)
                    count += 1

        print(f"Comments changed: {count}")

ReplaceInComments().run()
```

Please note that this Python code is based on the assumption that you have a `GhidraScript` class and methods like `ask_string`, `get_memory_blocks`, `set_eol_comment`, etc. available in your script, which are specific to Ghidra's scripting API.