class SymbolTable:
    def __init__(self):
        self.symbollist = []
        self.table = []
        self.curscope = None

    def get_current_scope(self):
        return self.curscope

    def get_global_scope(self):
        if not self.table:
            return None
        return self.table[0]

    def set_current_scope(self, scope):
        self.curscope = scope

    def get_unsought_symbols(self):
        result = []
        for symbol in self.symbollist:
            if not symbol.was_sought():
                result.append(symbol)
        return result

    def find_symbol(self, name):
        return self.find_symbol_internal(self.curscope, name)

    def find_symbol(self, id):
        try:
            return self.symbollist[id]
        except IndexError:
            raise SleighError("Symbol not found", None)

    def add_global_symbol(self, symbol):
        if len(self.table) > 0 and isinstance(symbol.scopeid, int):
            scope = self.get_global_scope()
            if scope.add_symbol(symbol):
                return
        raise SleighError(f"Duplicate global symbol: {symbol.name}", symbol.location)

    def find_symbol_internal(self, scope, name):
        while scope:
            result = scope.find_symbol(name)
            if result is not None:
                result.was_sought(True)
                return result
            scope = scope.parent
        return None

    def replace_symbol(self, a, b):
        for i in range(len(self.table) - 1, -1, -1):
            symbol = self.table[i].find_symbol(a.name)
            if symbol == a:
                self.table[i].remove_symbol(a)
                b.id = a.id
                b.scopeid = a.scopeid
                self.symbollist[a.id] = b
                a.dispose()
                return

    def save_xml(self, s):
        s.write("<symbol_table scopesize=\"{}\" symbolsize=\"{}\">\n".format(len(self.table), len(self.symbollist)))
        for i in range(len(self.table)):
            scope = self.table[i]
            if isinstance(scope.id, int):
                s.write("<scope id=\"0x{:X}\" parent=\"0x{:X}\"\n>".format(scope.id, scope.parent_id))
            else:
                s.write("<scope>\n")
        for i in range(len(self.symbollist)):
            symbol = self.symbollist[i]
            if isinstance(symbol.id, int):
                s.write("<symbol id=\"{}\">\n".format(symbol.id))
            else:
                s.write("<symbol>\n")
            try:
                symbol.save_xml(s)
            except Exception as e:
                print(f"Error saving {symbol.name}: {e}")
        s.write("</symbol_table>\n")

    def restore_xml(self, el):
        self.symbollist = []
        for child in el.children():
            if isinstance(child.tag, str) and child.tag.startswith("scope"):
                scope_id = int.from_bytes(bytes.fromhex(child.get("id")[3:]), "big")
                parent_scope_id = int.from_bytes(bytes.fromhex(child.get("parent")[5:]), "big") if child.get("parent").startswith("0x") else None
            elif isinstance(child.tag, str) and child.tag.startswith("symbol"):
                symbol_id = int.from_bytes(bytes.fromhex(child.get("id")[3:]), "big")
            try:
                self.symbollist.append(SleighSymbol().restore_xml_header(child))
                if scope_id is not None:
                    self.table.append(SymbolScope(None, scope_id))
                    self.curscope = self.table[-1]
                elif parent_scope_id is not None and len(self.table) > 0:
                    for i in range(len(self.table)):
                        if self.table[i].id == parent_scope_id:
                            self.curscope = self.table[i]
            except Exception as e:
                print(f"Error restoring {child.tag}: {e}")

    def purge(self):
        for symbol_index, symbol in enumerate(self.symbollist):
            if symbol is None or isinstance(symbol.id, int) and not 0 <= symbol.id < len(self.table):
                continue
            try:
                self.table[symbol.scopeid].remove_symbol(symbol)
                self.symbollist[symbol_index] = None
                symbol.dispose()
            except Exception as e:
                print(f"Error purging {symbol.name}: {e}")
        for table_index in range(1, len(self.table)):
            if isinstance(self.table[table_index], SymbolScope) and not self.table[table_index].tree.is_empty():
                break
        else:
            del self.table[1:]
        renumber()

    def renumber(self):
        new_table = []
        newsymbol = []
        for i in range(len(self.table)):
            scope = self.table[i]
            if isinstance(scope.id, int) and not 0 <= scope.id < len(new_table):
                continue
            scope.id = len(new_table)
            new_table.append(scope)
        for i in range(len(self.symbollist)):
            symbol = self.symbollist[i]
            if isinstance(symbol.scopeid, int) and not 0 <= symbol.scopeid < len(new_table):
                continue
            symbol.scopeid = scope.id
            newsymbol.append(symbol)
        self.table = new_table
        self.symbollist = newsymbol

class SleighSymbol:
    def __init__(self):
        pass

    def was_sought(self):
        return False

    def set_was_sought(self, value):
        pass

    @property
    def id(self):
        raise NotImplementedError("Must be implemented by subclass")

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def scopeid(self):
        return None

    @scopeid.setter
    def scopeid(self, value):
        pass

    def save_xml_header(self, s):
        raise NotImplementedError("Must be implemented by subclass")

    def restore_xml_header(self, el):
        raise NotImplementedError("Must be implemented by subclass")
