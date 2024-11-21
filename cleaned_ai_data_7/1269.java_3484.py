import asyncio

class GdbBreakpointInsertions:
    async def insert_breakpoint(self, loc: str, type: 'GdbBreakpointType') -> 'CompletableFuture[GdbBreakpointInfo]':
        # Implement your logic here to handle the breakpoint insertion.
        pass

    @property
    def default_insert_breakpoint(self):
        return self.insert_breakpoint

    async def insert_breakpoint_address_range(self, addr: int, len: int, type: 'GdbBreakpointType') -> 'CompletableFuture[GdbBreakpointInfo]':
        if len != 1 and type.is_watchpoint():
            # Implement your logic here to handle the watchpoint insertion.
            pass
        return self.insert_breakpoint(f"*((char(*)[{len}])0x{addr})", type)

    async def insert_breakpoint_address_offset(self, addr: int) -> 'CompletableFuture[GdbBreakpointInfo]':
        return self.insert_breakpoint(f"*0x{addr}")

class GdbBreakpointType:
    BREAKPOINT = 1
    WATCHPOINT = 2

# Example usage:

async def main():
    gdb_breakpoint_insertions = GdbBreakpointInsertions()
    breakpoint_info = await gdb_breakpoint_insertions.insert_breakpoint("main", GdbBreakpointType.BREAKPOINT)
    print(breakpoint_info)

if __name__ == "__main__":
    asyncio.run(main())
