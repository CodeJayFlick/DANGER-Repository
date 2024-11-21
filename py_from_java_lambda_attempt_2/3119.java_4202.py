Here is the translation of the given Java code into Python:

```Python
import os
from tkinter import filedialog

class SplitUniversalBinariesScript:
    def run(self):
        ubi_file = filedialog.askopenfilename(title="Select Universal Binary File", message="C'mon, Do it! Push da bahtahn!")
        output_directory = filedialog.askdirectory(title="Select Output Directory", message="GO")

        provider = RandomAccessByteProvider(ubi_file)
        header = FatHeader.create_fat_header(provider)

        architectures = header.get_architectures()
        for arch in architectures:
            offset = arch.get_offset()
            size = arch.get_size()

            processor = CpuTypes.get_processor(arch.get_cpu_type(), arch.get_cpu_subtype())
            processor_size = CpuTypes.get_processor_bit_size(arch.get_cpu_type())

            out_file_name = os.path.join(output_directory, ubi_file.name) + "." + str(processor) + "." + str(processor_size)
            with open(out_file_name, 'wb') as out:
                for i in range(offset, offset+size):
                    if i + 4096 < offset+size:
                        out.write(provider.read_bytes(i, 4096))
                    else:
                        out.write(provider.read_bytes(i, size-i))

class RandomAccessByteProvider:
    def __init__(self, file_path):
        self.file = open(file_path, 'rb')

    def read_bytes(self, i, n):
        return self.file.seek(i).read(n)

class FatHeader:
    @staticmethod
    def create_fat_header(provider):
        # This method is not implemented in the original Java code.
        pass

class CpuTypes:
    @staticmethod
    def get_processor(cpu_type, cpu_subtype):
        # This method is not implemented in the original Java code.
        return None

    @staticmethod
    def get_processor_bit_size(cpu_type):
        # This method is not implemented in the original Java code.
        return 0

if __name__ == "__main__":
    script = SplitUniversalBinariesScript()
    try:
        script.run()
    except Exception as e:
        print(f"An error occurred: {e}")
```

Please note that this Python translation does not include all the methods and classes from the original Java code. The `create_fat_header` method in the `FatHeader` class, the `get_processor`, `get_cpu_type`, and `get_cpu_subtype` methods in the `CpuTypes` class are not implemented here as they were missing their implementations in the original Java code too.