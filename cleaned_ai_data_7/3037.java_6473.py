import ghidra

class FindTextScript:
    def run(self):
        if not hasattr(ghidra.currentProgram(), 'currentAddress'):
            print("NO CURRENT ADDRESS")
            return
        
        search_string = input("Enter search string: ")
        
        addr = None
        for segment in ghidra.currentProgram().getLanguage().getSegments():
            for address in segment.getAddresses():
                if str(address).find(search_string) != -1:
                    addr = address
                    break
            
        if addr is not None:
            print(f"Search match found at {addr}")
            #goTo(addr)
        else:
            print("No search matched found.")

FindTextScript().run()
