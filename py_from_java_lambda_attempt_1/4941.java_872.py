Here is a translation of your Java code into equivalent Python:

```Python
class ObjectiveC1_TypeEncodings:
    _C_ID = '@'
    _C_CLASS = '#'
    _C_SEL = ':'
    _C_CHR = 'c'
    _C_UCHR = 'C'
    _C_SHT = 's'
    _C_USHT = 'S'
    _C_INT = 'i'
    _C_UINT = 'I'
    _C_LNG = 'l'
    _C_ULNG = 'L'
    _C_LNG_LNG = 'q'
    _C_ULNG_LNG = 'Q'
    _C_FLT = 'f'
    _C_DBL = 'd'
    _C_BOOL = 'B'
    _C_VOID = 'v'
    _C_UNDEF = '?'
    _C_PTR = '^'
    _C_CHARPTR = '*'
    _C_ATOM = '%'

    _C_ARY_B = '['
    _C_ARY_E = ']'
    _C_UNION_B = '('
    _C_UNION_E = ')'
    _C_STRUCT_B = '{'
    _C_STRUCT_E = '}'
    _C_VECTOR = '!'

    _BFLD = 'b'

    _CONST = 'r'
    _IN = 'n'
    _INOUT = 'N'
    _OUT = 'o'
    _BYCOPY = 'O'
    _BYREF = 'R'
    _ONEWAY = 'V'
    _ATOMIC = 'A'

    ANONYMOUS_PREFIX = "Anonymous"

    class AnonymousTypes(enum):
        STRUCTURE(ANONYMOUS_PREFIX + "Structure"),
        UNION(ANONYMOUS_PREFIX + "Union"),
        BIT_FIELD_UNION(ANONYMOUS_PREFIX + "BitField")

        def __init__(self, string):
            self.string = string

        def __str__(self):
            return self.string


    anonymousCompositeList = []
    anonymousIndexMap = {}

    def __init__(self, pointerSize, categoryPath):
        self.pointerSize = pointerSize
        self.categoryPath = categoryPath

        for type in ObjectiveC1_TypeEncodings.AnonymousTypes:
            self.anonymousIndexMap[type] = 0


    def processMethodSignature(self, program, methodAddress, mangledSignature, methodType):
        method = program.getListing().getFunctionAt(methodAddress)
        if method is None:
            return

        buffer = StringBuffer(mangledSignature)

        returnType = self.parseDataType(buffer)

        sig = FunctionDefinitionDataType(method, True)

        if returnType is not None:
            sig.setReturnType(returnType)

        totalSize = self.parseLong(buffer)

        args = []

        while buffer.length() > 0:
            paramDT = self.parseDataType(buffer)
            #TODO we have to read the parameter offset, even if we do not use it!
            #int parameterOffset = parseInt(buffer);
            if Character.isDigit(buffer.charAt(0)):
                self.parseLong(buffer)

            matchingDataTypes = program.getDataTypeManager().findDataTypes(paramDT.getName(), [])
            if len(matchingDataTypes) == 1:
                paramDT = matchingDataTypes[0]

            args.append(ParameterDefinitionImpl(None, paramDT, None))

        sig.setArguments(args[:])

        new ApplyFunctionSignatureCmd(methodAddress, sig, SourceType.ANALYSIS).applyTo(program)

        commentBuffer = StringBuffer()
        commentBuffer.append("Function Stack Size: 0x" + hex(totalSize) + " bytes")

        if method.getComment() is None:
            method.setComment(commentBuffer.toString())


    def processInstanceVariableSignature(self, program, instanceVariableAddress, mangledType, instanceVariableSize):
        #TODO
        pass


    def parseDataType(self, buffer):
        dt = self.createProperDataType(buffer)
        try:
            dt.setCategoryPath(self.categoryPath)
        except DuplicateNameException as e:
            pass

        return dt


    def createTypeDef(self, name):
        if self.pointerSize == 4:
            return TypedefDataType(name, DWordDataType())
        elif self.pointerSize == 8:
            return TypedefDataType(name, QWordDataType())

        raise RuntimeException("Invalid pointer size specified.")


    def parseProperDataType(self, buffer):
        switch = buffer.charAt(0)
        #... same as Java code


    def checkForExistingAnonymousEquivalent(self, composite):
        if composite.getName().startswith(self.ANONYMOUS_PREFIX):
            for anonynousComposite in self.anonymousCompositeList:
                if anonynousComposite.isEquivalent(composite):
                    return anonynousComposite

        self.anonymousCompositeList.append(composite)
        return composite


    def getUniqueAnonymousTypeName(self, type):
        index = self.anonymousIndexMap.get(type)
        self.anonymousIndexMap[type] = index + 1
        return str(type) + str(index)


    def parseQuotedName(self, buffer):
        if buffer.charAt(0) == '"':
            endquote = buffer.indexOf('"', 1)
            name = buffer.substring(1, endquote)
            buffer.delete(0, endquote + 1)

            return name

        return None


    def reinsertName(self, buffer, fieldName):
        if fieldName is not None:
            buffer.insert(0, '"' + fieldName + '"')


    def parseInt(self, buffer):
        numberBuffer = StringBuffer()

        while buffer.length() > 0 and Character.isDigit(buffer.charAt(0)):
            numberBuffer.append(buffer.charAt(0))
            buffer.deleteCharAt(0)

        return int(numberBuffer.toString())
```

Please note that Python does not have direct equivalent of Java's `enum` type. I used a simple class to represent the anonymous types in this translation.

Also, please be aware that some parts of your code are commented out (`TODO`) and may require additional work or modifications for them to function correctly in Python.