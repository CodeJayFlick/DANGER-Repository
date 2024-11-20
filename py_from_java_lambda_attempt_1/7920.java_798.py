Here is the translation of the Java code into Python:

```Python
class MDTypeInfoParser:
    def parse(self, dmang: 'MDMang', rtti_num: int) -> 'MDTypeInfo':
        type_info = None
        is_based = False
        if dmang.peek() == '_':
            is_based = True
            dmang.increment()
        
        code = dmang.peek()
        switcher = {
            '$': self.parse_special_handling_function,
            '0': lambda: MDVariableInfo(dmang, private=True, static=True),
            '1': lambda: MDVariableInfo(dmang, protected=True, static=True),
            '2': lambda: MDVariableInfo(dmang, public=True, static=True),
            '3': lambda: MDVariableInfo(dmang),  # global
            '4': lambda: MDVariableInfo(dmang),  # static local
            '5': lambda: MDGuard(dmang),
            '6':
                if rtti_num == 4:
                    return MDRTTI4(dmang)
                else:
                    return MDVFTable(dmang),
            '7': return MDVBTable(dmang),
            '8':
                switcher = {
                    0: lambda: MDRTTI0(dmang),
                    1: lambda: MDRTTI1(dmang),
                    2: lambda: MDRTTI2(dmang),
                    3: lambda: MDRTTI3(dmang)
                }
                return next(value for key, value in switcher.items() if rtti_num == key),
            '9': return MDTypeInfo(dmang),  # vcall
        }

        type_info = switcher.get(code, lambda: self.default_type_info)(dmang)

        if is_based and isinstance(type_info, MDFunctionInfo):
            based = MDBasedAttribute(dmang)
            based.parse()
            (type_info).set_based(based)

        return type_info

    def parse_special_handling_function(self, dmang: 'MDMang', rtti_num: int) -> 'MDTypeInfo':
        ch = dmang.get_and_increment()

        switcher = {
            '0': lambda: MDVtordisp(dmang),
            '1': lambda: MDVtordisp(dmang),  # private
            '2': lambda: MDVtordisp(dmang),  # protected
            '3': lambda: MDVtordisp(dmang),  # public
        }

        type_info = switcher.get(ch, self.default_type_info)(dmang)

        if ch == '$':
            ch2 = dmang.get_and_increment()
            switcher = {
                'J': lambda: CManagedILFunction(dmang),
                'N': lambda: CManagedILDLLImportData(dmang),
                'O': lambda: CManagedNativeDLLImportData(dmang)
            }

            type_info = next(value for key, value in switcher.items() if ch2 == key)(dmang)

        return type_info

    def default_type_info(self):
        raise MDException("Invalid MDTypeInfo")
```

Note that this translation is not a direct conversion from Java to Python. The original code has been modified and simplified to better fit the style of Python programming.