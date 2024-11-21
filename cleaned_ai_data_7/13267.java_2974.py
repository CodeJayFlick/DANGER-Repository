class ConstantPoolFactory:
    @staticmethod
    def get(reader):
        tag = reader.peek_next_byte()
        if tag == 5:  # CONSTANT_Class
            return ConstantPoolClassInfo(reader)
        elif tag == 6:  # CONSTANT_Double
            return ConstantPoolDoubleInfo(reader)
        elif tag == 7:  # CONSTANT_Fieldref
            return ConstantPoolFieldReferenceInfo(reader)
        elif tag == 4:  # CONSTANT_Float
            return ConstantPoolFloatInfo(reader)
        elif tag == 3:  # CONSTANT_Integer
            return ConstantPoolIntegerInfo(reader)
        elif tag == 12:  # CONSTANT_InterfaceMethodref
            return ConstantPoolInterfaceMethodReferenceInfo(reader)
        elif tag == 15:  # CONSTANT_InvokeDynamic
            return ConstantPoolInvokeDynamicInfo(reader)
        elif tag == 9:  # CONSTANT_Long
            return ConstantPoolLongInfo(reader)
        elif tag == 16:  # CONSTANT_MethodHandle
            return ConstantPoolMethodHandleInfo(reader)
        elif tag == 11:  # CONSTANT_Methodref
            return ConstantPoolMethodReferenceInfo(reader)
        elif tag == 14:  # CONSTANT_MethodType
            return ConstantPoolMethodTypeInfo(reader)
        elif tag == 10:  # CONSTANT_NameAndType
            return ConstantPoolNameAndTypeInfo(reader)
        elif tag == 1:  # CONSTANT_String
            return ConstantPoolStringInfo(reader)
        elif tag == 3:  # CONSTANT_Utf8
            return ConstantPoolUtf8Info(reader)
        elif tag == 18:  # CONSTANT_Dynamic
            return ConstantPoolDynamicInfo(reader)
        elif tag == 19:  # CONSTANT_Module
            return ConstantPoolModuleInfo(reader)
        elif tag == 0:
            return None
        else:
            raise ValueError(f"Unsupported constant pool entry type: {tag}")
