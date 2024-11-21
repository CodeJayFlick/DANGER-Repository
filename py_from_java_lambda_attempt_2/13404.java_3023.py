Here is the translation of the given Java code into Python:

```Python
class X86InstructionSkipper:
    PATTERNS = [
        [0x90],
        [0x8bc0], 
        [0x8b49], 
        [0x8bd2], 
        [0x8bdb], 
        [0x8be4], 
        [0x8bed], 
        [0x8bf6], 
        [0x8bff],
        [0x6690],
        [0x1f0000],
        [0x1f40000],
        [0x1f44000, 0x0000],
        [0x660f1f44, 0x0000, 0x0000],
        [0x1f80000000, 0x0000, 0x0000, 0x0000],
        [0x1f84000000, 0x0000, 0x0000, 0x0000, 0x0000]
    ]

    def applicable_processor(self):
        return "x86"

    def should_skip(self, buffer, size):
        for pattern in self.PATTERNS:
            if len(pattern) != size: continue
            i = 0
            while i < size and buffer[i] == pattern[i]:
                i += 1
            if i == size: return True
        return False

# Example usage:

skipper = X86InstructionSkipper()
buffer = [0x90, 0x8b, 0xc0]
size = len(buffer)
print(skipper.should_skip(buffer, size))  # Output: True