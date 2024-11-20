Here is the translation of the provided Java code into Python:

```Python
import ghidra.app.script.GhidraScript;
from ghidra.program.model.address import Address;
from ghidra.program.model.listing.Function;
from ghidra.program.model.mem.MemoryBlock;

class MakeFunctionsScript(GhidraScript):
    def run(self) -> None:
        memory = self.currentProgram.getMemory();
        function_bytes = ask_bytes("Enter Byte Pattern", "Please enter your function byte pattern separated by spaces");

        while not monitor.is_cancelled() and (function_bytes is None or len(function_bytes) == 0):
            function_bytes = ask_bytes("Invalid Byte Pattern", "Please re-enter your function byte pattern in separated by spaces")

        text_bytes = "";
        for i, b in enumerate(function_bytes):
            text_bytes += to_hex_string(b, True, False);
            text_bytes += " ";

        print(f"Searching for {text_bytes}. . .");

        memory_blocks = self.currentProgram.getMemory().getBlocks();
        if len(memory_blocks) == 1:
            data_address = ask_address("Create data block", "Please enter the start address of the data section.");
            memory.split(memory_blocks[0], data_address);
            # get the blocks again to get new split one
            memory_blocks = self.currentProgram.getMemory().getBlocks();
            if memory_blocks[1].contains(data_address):
                memory_blocks[1].set_name("Data");
                memory_blocks[1].set_execute(False);
            else:
                if memory_blocks[0].contains(data_address):
                    memory_blocks[0].set_name("Data");
                    memory_blocks[0].set_execute(False);

        found_count = 0;
        made_count = 0;

        for i, block in enumerate(memory_blocks):
            if block.is_execute():
                keep_searching = True;
                start = block.get_start();
                end = block.get_end();

                while keep_searching and not monitor.is_cancelled():
                    found = memory.find_bytes(start, end, function_bytes, None, True, monitor);
                    if found is not None and block.contains(found):
                        found_count += 1;
                        test_func = get_function_containing(found);
                        if test_func is None:
                            did_disassemble = disassemble(found);
                            if did_dissemble:
                                func = create_function(found, None);
                                if func is not None:
                                    print(f"Made function at address: {found.to_string()}");
                                    made_count += 1;
                                else:
                                    print(f"***Function could not be made at address: {found.to_string()}");

                            else:
                                print("Function already exists at address:", found.to_string());

                        start = found.add(4);

                    else:
                        keep_searching = False;

        if found_count == 0:
            print("No functions found with given byte pattern.");
            return;
        elif made_count == 0:
            print("No new functions made with given byte pattern.");

```

Please note that this is a direct translation of the provided Java code into Python, and it may not be perfect. The original code might have some specific requirements or constraints that are not directly applicable to Python.