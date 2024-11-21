Here is the translation of the given Java code into Python:

```Python
import ghidra


class GenerateMaskedBitStringScript:
    def run(self):
        mem = current_program.get_memory()

        end_address = current_program.max_address()
        start_address = current_program.min_address()

        values = input("Enter byte values: ")
        masks = input("Enter byte masks: ")

        create_masked_bit_string(values, masks)

        count = 0
        while start_address < end_address:
            if ghidra.monitor.is_cancelled():
                return

            position = mem.find_bytes(start_address, end_address, bytes.fromhex(values), bytes.fromhex(masks), True)
            if position is None:
                break

            print(position.to_string())
            count += 1
            start_address += 1

        print(f"\nTotal count: {count}")


    def create_masked_bit_string(self, values, masks):
        bit_string = ""

        if len(values) != len(masks):
            print("values and masks are different lengths")
            return None

        for i in range(len(values)):
            for j in range(8):
                if (masks[i] >> (7 - j)) & 1 == 0:
                    bit_string += "."
                elif (values[i] >> (7 - j)) & 1 == 0:
                    bit_string += "0"
                else:
                    bit_string += "1"

            bit_string += " "

        print(bit_string)
        return bit_string


# Initialize the script
script = GenerateMaskedBitStringScript()
try:
    script.run()
except Exception as e:
    print(f"An error occurred: {e}")
```

Please note that you need to have `ghidra` installed and imported in your Python environment for this code to work.