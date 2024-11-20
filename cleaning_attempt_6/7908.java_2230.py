class MDTemplateConstant:
    def __init__(self):
        self.name = None
        self.address_maybe = None

    def get_address_maybe(self):
        return self.address_maybe

    def parse_internal(self, dmang):
        if not isinstance(dmang, str):
            raise ValueError("dmang must be a string")

        code = dmang[0]
        dmang = dmang[1:]
        
        if code == '$':
            code = dmang[0]
            dmang = dmang[1:]

            if code in ['0', '1']:
                name_num = MDSignedEncodedNumber(dmang)
                name_num.parse()
                self.name = str(name_num)

            elif code == '2':
                a = MDSignedEncodedNumber(dmang)
                b = MDSignedEncodedNumber(dmang)
                
                if self.name[0] == '-':
                    self.name = '-' + self.name[1:]
                else:
                    self.name += '.'
                    
                self.name += str(a) + '.' + str(b)

            elif code in ['D', 'E']:
                a = MDSignedEncodedNumber(dmang)
                a.parse()
                
                if code == 'D':
                    self.name = '`template-parameter' + str(a) + "'"
                else:
                    object_cpp = MDObjectCPP(dmang)
                    object_cpp.parse()
                    builder = StringBuilder()
                    object_cpp.insert(builder)
                    self.name = str(builder)

            elif code in ['F', 'G']:
                a = MDSignedEncodedNumber(dmang)
                b = MDSignedEncodedNumber(dmang)
                
                if code == 'F':
                    self.name = '{' + str(a) + ',' + str(b) + '}'
                else:
                    c = MDSignedEncodedNumber(dmang)
                    c.parse()
                    self.name = '{' + str(a) + ',' + str(b) + ',' + str(c) + '}'

            elif code == 'H':
                object_cpp = MDObjectCPP(dmang)
                object_cpp.parse()
                builder = StringBuilder()
                object_cpp.insert(builder)
                
                a = MDSignedEncodedNumber(dmang)
                a.parse()

                dmang.append('{')
                dmang.append(',')
                dmang.append(str(a))
                dmang.append('}')
                self.name = str(builder)

            elif code == 'I':
                object_cpp = MDObjectCPP(dmang)
                object_cpp.parse()
                builder = StringBuilder()
                object_cpp.insert(builder)
                
                a = MDSignedEncodedNumber(dmang)
                b = MDSignedEncodedNumber(dmang)
                c = MDSignedEncodedNumber(dmang)

                dmang.append('{')
                dmang.append(',')
                dmang.append(str(a))
                dmang.append(',')
                dmang.append(str(b))
                dmang.append(',')
                dmang.append(str(c))
                dmang.append('}')
                self.name = str(builder)

            elif code == 'J':
                object_cpp = MDObjectCPP(dmang)
                object_cpp.parse()
                builder = StringBuilder()
                object_cpp.insert(builder)
                
                a = MDSignedEncodedNumber(dmang)
                b = MDSignedEncodedNumber(dmang)
                c = MDSignedEncodedNumber(dmang)

                dmang.append('{')
                dmang.append(',')
                dmang.append(str(a))
                dmang.append(',')
                dmang.append(str(b))
                dmang.append(',')
                dmang.append(str(c))
                dmang.append('}')
                self.name = str(builder)

            elif code == 'Q':
                a = MDSignedEncodedNumber(dmang)
                a.parse()
                
                self.name = '`non-type-template-parameter' + str(a) + "'"

            elif code == 'R':
                fragment_name = MDFragmentName(dmang)
                fragment_name.parse()

                address_maybe_num = MDSignedEncodedNumber(dmang)
                address_maybe_num.parse()

                self.address_maybe = str(address_maybe_num)

                builder = StringBuilder()
                fragment_name.insert(builder)
                
                self.name = str(builder)

            elif code == 'S':
                self.name = ''

            else:
                raise ValueError("Unknown Template Constant: $" + code + " code")

        else:
            raise ValueError("Template Parameter needs work: " + code + " code")

    def insert(self, builder):
        dmang.insertString(builder, self.name)

class MDSignedEncodedNumber:
    def __init__(self, dmang):
        if not isinstance(dmang, str):
            raise ValueError("dmang must be a string")
        
        self.dmang = dmang

    def parse(self):
        pass  # This method should implement the parsing logic for signed encoded numbers.

class MDObjectCPP:
    def __init__(self, dmang):
        if not isinstance(dmang, str):
            raise ValueError("dmang must be a string")
        
        self.dmang = dmang

    def parse(self):
        pass  # This method should implement the parsing logic for object CPPs.

class MDFragmentName:
    def __init__(self, dmang):
        if not isinstance(dmang, str):
            raise ValueError("dmang must be a string")
        
        self.dmang = dmang

    def parse(self):
        pass  # This method should implement the parsing logic for fragment names.

class StringBuilder:
    def __init__(self):
        self.builder = ""

    def append(self, s):
        if not isinstance(s, str):
            raise ValueError("s must be a string")
        
        self.builder += s

    def insertString(self, builder, s):
        if not isinstance(builder, str) or not isinstance(s, str):
            raise ValueError("builder and s must both be strings")

        self.append(s)

    def toString(self):
        return self.builder
