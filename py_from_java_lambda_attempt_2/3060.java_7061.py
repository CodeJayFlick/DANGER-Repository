Here is the translation of the given Java code into Python:

```Python
import ghidra_script as script

class IterateDataScript(script.GhidraScript):
    def run(self):
        data = self.getFirstData()

        while True:
            if self.monitor.is_cancelled():
                break

            if data is None:
                break

            buffer = StringBuffer()
            buffer.append(str(data.get_min_address()))
            buffer.append('  ')
            buffer.append(str(data.get_mnemonic_string()))
            buffer.append('  ')
            buffer.append(str(data.get_value()))

            print(buffer.toString())

            data = self.data_after(data)

if __name__ == "__main__":
    script.run_script(IterateDataScript())
```

Please note that this code is not a direct translation, but rather an equivalent Python implementation. The `GhidraScript` class and its methods are specific to the Ghidra framework and may require additional setup or imports in your Python environment.