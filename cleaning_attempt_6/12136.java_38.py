class DisassemblerMessageListener:
    IGNORE = lambda x: None  # equivalent to public final static DisassemblerMessageListener IGNORE ...

    CONSOLE = lambda msg: print(f"DisassemblerMessageListener: {msg}")  # equivalent to public final static DisassemblerMessageListener CONSOLE ...

    def disassemble_message_reported(self, msg):
        pass  # equivalent to void disassembleMessageReported(String msg)

# Note: In Python, we don't need a separate class for the "method" (i.e., `disassemble_message_reported`), as it's just an ordinary method.
