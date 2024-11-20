class Format:
    eFormatDefault = "eFormatDefault"
    eFormatInvalid = "eFormatInvalid"
    eFormatBoolean = "eFormatBoolean"
    eFormatBinary = "eFormatBinary"
    eFormatBytes = "eFormatBytes"
    eFormatBytesWithASCII = "eFormatBytesWithASCII"
    eFormatChar = "eFormatChar"
    eFormatCharPrintable = "eFormatCharPrintable"
    eFormatComplex = "eFormatComplex"
    eFormatComplexFloat = "eFormatComplexFloat"
    eFormatCString = "eFormatCString"
    eFormatDecimal = "eFormatDecimal"
    eFormatEnum = "eFormatEnum"
    eFormatHex = "eFormatHex"
    eFormatHexUppercase = "eFormatHexUppercase"
    eFormatFloat = "eFormatFloat"
    eFormatOctal = "eFormatOctal"
    eFormatOSType = "eFormatOSType"
    eFormatUnicode16 = "eFormatUnicode16"
    eFormatUnicode32 = "eFormatUnicode32"
    eFormatUnsigned = "eFormatUnsigned"
    eFormatPointer = "eFormatPointer"
    eFormatVectorOfChar = "eFormatVectorOfChar"
    eFormatVectorOfSInt8 = "eFormatVectorOfSInt8"
    eFormatVectorOfUInt8 = "eFormatVectorOfUInt8"
    eFormatVectorOfSInt16 = "eFormatVectorOfSInt16"
    eFormatVectorOfUInt16 = "eFormatVectorOfUInt16"
    eFormatVectorOfSInt32 = "eFormatVectorOfSInt32"
    eFormatVectorOfUInt32 = "eFormatVectorOfUInt32"
    eFormatVectorOfSInt64 = "eFormatVectorOfSInt64"
    eFormatVectorOfUInt64 = "eFormatVectorOfUInt64"
    eFormatVectorOfFloat16 = "eFormatVectorOfFloat16"
    eFormatVectorOfFloat32 = "eFormatVectorOfFloat32"
    eFormatVectorOfFloat64 = "eFormatVectorOfFloat64"
    eFormatVectorOfUInt128 = "eFormatVectorOfUInt128"
    eFormatComplexInteger = "eFormatComplexInteger"
    eFormatCharArray = "eFormatCharArray"
    eFormatAddressInfo = "eFormatAddressInfo"
    eFormatHexFloat = "eFormatHexFloat"
    eFormatInstruction = "eFormatInstruction"
    eFormatVoid = "eFormatVoid"
    eFormatUnicode8 = "eFormatUnicode8"

    kNumFormats = None

    def __init__(self, swigName):
        self.swigName = swigName
        global FormatValues
        if not hasattr(Format, 'swigNext'):
            Format.swigNext = 0
        FormatValues.append(self)
        self.swigValue = Format.swigNext
        Format.swigNext += 1

    def __init__(self, swigName, swigValue):
        self.swigName = swigName
        self.swigValue = swigValue

    @staticmethod
    def swigToEnum(swigValue):
        if swigValue < len(FormatValues) and swigValue >= 0:
            return FormatValues[swigValue]
        for i in range(len(FormatValues)):
            if FormatValues[i].swigValue == swigValue:
                return FormatValues[i]
        raise ValueError("No enum " + str(type(Format)) + " with value " + str(swigValue))

    def __str__(self):
        return self.swigName

    @property
    def swigValue(self):
        return self._swigValue

    @swigValue.setter
    def swigValue(self, value):
        self._swigValue = value


FormatValues = []
