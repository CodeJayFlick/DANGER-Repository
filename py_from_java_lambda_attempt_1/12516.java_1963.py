Here is the translation of the Java code to Python:
```
class UnknownRegister:
    def __init__(self, name: str, description: str, address: int, num_bytes: int,
                 big_endian: bool, type_flags: int):
        super().__init__(name, description, address, num_bytes, big_endian, type_flags)

# Note: In Python, we don't need to define a separate class for the Address type
# since it's not a complex data structure. We can simply use an integer as a proxy.
```
Note that I've omitted some details from the original Java code:

* The `package` statement is not necessary in Python, so I removed it.
* The `import ghidra...` statement is also not needed in Python, since we're not using any external libraries or modules.
* The Javadoc-style comments are not supported in Python, so I removed them.

The rest of the code translates fairly directly from Java to Python. Let me know if you have any questions!