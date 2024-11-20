Here is the translation of the Java code to Python:
```
class DisassemblerMessageListener:
    IGNORE = lambda x: None  # equivalent to public final static DisassemblerMessageListener IGNORE ...

    CONSOLE = lambda msg: print(f"DisassemblerMessageListener: {msg}")  # equivalent to public final static DisassemblerMessageListener CONSOLE ...

    def disassemble_message_reported(self, msg):
        pass  # equivalent to void disassembleMessageReported(String msg)

# Note: In Python, we don't need a separate class for the "method" (i.e., `disassemble_message_reported`), as it's just an ordinary method.
```
Here are some key differences between Java and Python:

* In Python, we use classes to define custom types, but they're not necessarily equivalent to Java classes. We can also define functions inside a class, which is what I did here for the `disassemble_message_reported` method.
* The `lambda` syntax in Python allows us to define small anonymous functions (equivalent to Java's inner classes). In this case, we use them to implement the `IGNORE` and `CONSOLE` constants as simple function objects that do nothing or print a message, respectively.

Note that I didn't translate the Apache License boilerplate code at the top of your original file. If you want me to include it in the Python translation, just let me know!