Here is the translation of the given Java code into Python:

```Python
import ghidra

class AutoRenameSimpleLabels:
    def __init__(self):
        self.modified_count = 0

    def run(self):
        print("Script: AutoRenameSimpleLabels()")

        # Get listing of symbols
        symbol_table = current_program.get_symbol_table()
        iter = symbol_table.get_all_symbols(True)

        while iter.has_next():
            s = iter.next()

            if not monitor.is_cancelled():
                start_addr = s.get_address()

                inst = get_instruction_at(start_addr)
                flow_type = inst.get_flow_type()
                operand = " "

                try:
                    operand = inst.get_default_operand_representation(0)
                except NullPointerException as excp:
                    continue

                print(f"Instruction @ {start_addr.to_upper_string()} type={flow_type} operand={operand}")

                if flow_type.is_fallthrough():
                    continue
                elif flow_type.is_conditional():
                    continue
                elif flow_type.is_terminal():
                    new_name = f"ret_{start_addr.to_upper_string()}"
                    if s.get_name().casefold() == new_name.casefold():
                        continue
                    elif not is_default_name(s):
                        continue

                    print(f"Renaming RET @ {start_addr.to_upper_string()} : {s.get_name()} to {new_name}")
                    s.set_name(new_name, SourceType.ANALYSIS)
                    self.modified_count += 1
                else:
                    new_name = f"branch_{start_addr.to_upper_string()}_{" + operand + "}"
                    ref = inst.get_operand_references(0)[0]
                    operand_sym = current_program.get_symbol_table().get_symbol(ref)

                    if s.get_name().casefold() != new_name.casefold():
                        print(f"Renaming BR @ {start_addr.to_upper_string()} : {s.get_name()} to {new_name}")
                        s.set_name(new_name, SourceType.ANALYSIS)
                        self.modified_count += 1

                    # now also propogate the repeatable comment up as well
                    if operand_sym is not None:
                        start_addr = operand_sym.get_address()
                        print(f"Updating comment for {operand} to {comment}")
                        current_program.get_listing().set_comment(start_addr, CodeUnit.REPEATABLE_COMMENT, comment)

        print(f"Modified a total of {self.modified_count} entries")

    def is_default_name(self, symbol):
        return symbol.get_source() == SourceType.DEFAULT or symbol.get_source() == SourceType.ANALYSIS

# Usage
script = AutoRenameSimpleLabels()
script.run()
```

Please note that this Python code assumes you have the `ghidra` module available.