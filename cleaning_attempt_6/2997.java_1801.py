import ghidra

class CountSymbolsScript:
    def run(self):
        print("Counting symbols...")
        st = self.state.getCurrentProgram().getSymbolTable()
        iter = st.getSymbolIterator(True)
        count = 0
        while iter.hasNext() and not self.monitor.isCancelled():
            sym = iter.next()
            if sym is not None:
                print(sym.getName())
                count += 1
        print(f"{count} symbols")

# Usage: 
script = CountSymbolsScript()
script.run()
