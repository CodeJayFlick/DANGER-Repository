import ghidra.app.script.GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import Symbol
from mdemangler.MDException import MDException
from mdemangler.MDMangParseInfo import MDMangParseInfo

class DeveloperDumpMDMangParseInfoScript(GhidraScript):
    def run(self) -> None:
        window_manager = DockingWindowManager.getActiveInstance()
        provider = window_manager.getActiveComponentProvider()
        action_context = provider.getActionContext(None)
        
        if isinstance(action_context, ProgramSymbolActionContext):
            symbol_context = action_context
            for s in symbol_context.getSymbols():
                self.demangle(s.getAddress(), s.getName())
                
        elif current_location is FunctionSignatureFieldLocation:
            function = get_function_at(current_address)
            if function is not None:
                self.demangle(current_address, function.getName())

        elif current_location is LabelFieldLocation:
            lfl = current_location
            self.demangle(current_address, lfl.getName())
            
        elif current_location is OperandFieldLocation:
            data = get_data_at(current_address)
            if data is not None:
                value = data.getValue()
                if isinstance(value, Address):
                    symbol_addr = value
                    sym = get_symbol_at(symbol_addr)
                    if sym is not None:
                        self.demangle(symbol_addr, sym.getName())
                    
        else:
            sym = get_symbol_at(current_address)
            if sym is not None:
                self.demangle(current_address, sym.getName())
            else:
                print(f"Nothing to demangle at {current_address}")

    def demangle(self, address: Address, name: str) -> None:
        if name is None or len(name) == 0:
            Msg.info(self, "Invalid name.\n")
            return

        builder = StringBuilder()
        builder.append("\nName: " + name + "\n")

        try:
            demangler = MDMangParseInfo()
            demangler.demangle(name, False)
            parse_info = demangler.get_parse_info_incremental()
            builder.append(parse_info)
            builder.append(f"Num remaining chars: {demangler.getNumCharsRemaining()} \n")
        except MDException as e:
            builder.append("Demangler failure: " + str(e) + "\n")

        Msg.info(self, builder.toString())
