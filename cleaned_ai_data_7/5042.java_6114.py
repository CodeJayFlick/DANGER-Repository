class CliFlags:
    PATH = "/PE/CLI/Flags"

    class CliEnumAssemblyFlags(EnumDataType):
        dataType = CliEnumAssemblyFlags()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "AssemblyFlags", 4)
            self.add("PublicKey", 0x00000001)
            self.add("Retargetable", 0x00000100)
            self.add("DisableJITcompileOptimizer", 0x00004000)
            self.add("EnableJITcompileTracking", 0x00008000)

    class CliEnumAssemblyHashAlgorithm(EnumDataType):
        dataType = CliEnumAssemblyHashAlgorithm()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "AssemblyHash", 4)
            self.add("", 0x00000000)
            self.add("Reserved (MD5)", 0x00008003)
            self.add("SHA1", 0x00008004)

    class CliEnumEventAttributes(EnumDataType):
        dataType = CliEnumEventAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "EventAttributes", 2)
            self.add("", 0x0200)
            self.add("RTSpecialName", 0x0400)

    class CliEnumFieldAttributes(EnumDataType):
        dataType = CliEnumFieldAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "FieldAttributes", 2)
            self.add("Access_CompilerControlled", 0x0000)
            self.add("Access_Private", 0x0001)
            self.add("Access_FamANDAssem", 0x0002)
            self.add("Access_Assembly", 0x0003)
            self.add("Access_Family", 0x0004)
            self.add("Access_FamORAssem", 0x0005)
            self.add("Access_Public", 0x0006)
            self.add("Static", 0x0010)
            self.add("InitOnly", 0x0020)
            self.add("Literal", 0x0040)
            self.add("NotSerialized", 0x0080)
            self.add("SpecialName", 0x0200)
            self.add("PInvokeImpl", 0x2000)
            self.add("RTSpecialName", 0x0400)
            self.add("HasFieldMarshal", 0x1000)
            self.add("HasDefault", 0x8000)
            self.add("HasFieldRVA", 0x0100)

    class CliEnumFileAttributes(EnumDataType):
        dataType = CliEnumFileAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "FileAttributes", 4)
            self.add("", 0x0000)
            self.add("ContainsMetaData", 0x0001)

    class CliEnumGenericParamAttributes(EnumDataType):
        dataType = CliEnumGenericParamAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "GenericParamAttributes", 2)
            self.add("Variance_None", 0x0000)
            self.add("Covariant", 0x0001)
            self.add("Contravariant", 0x0002)
            self.add("ReferenceTypeConstraint", 0x0004)
            self.add("NotNullableValueTypeConstraint", 0x0008)
            self.add("DefaultConstructorContstraint", 0x0010)

    class CliEnumPInvokeAttributes(EnumDataType):
        dataType = CliEnumPInvokeAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "PInvokeAttributes", 2)
            self.add("", 0x0001)
            self.add("CharSetNotSpec", 0x0002)
            self.add("CharSetUnicode", 0x0004)
            self.add("CharSetAuto", 0x0006)
            self.add("SupportsLastError", 0x0040)
            self.add("CallConvPlatformapi", 0x0100)
            self.add("CallConvCdecl", 0x0200)
            self.add("CallConvStdcall", 0x0300)
            self.add("CallConvThiscall", 0x0400)
            self.add("CallConvFastcall", 0x0500)

    class CliEnumManifestResourceAttributes(EnumDataType):
        dataType = CliEnumManifestResourceAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "ManifestResourceAttributes", 4)
            self.add("", 0x0001)
            self.add("Private", 0x0002)

    class CliEnumMethodAttributes(EnumDataType):
        dataType = CliEnumMethodAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "MethodAttributes", 2)
            prefix = "MAccess_"
            self.add(prefix + "CompilerControlled", 0x0000)
            self.add(prefix + "Private", 0x0001)
            self.add(prefix + "FamANDAssem", 0x0002)
            self.add(prefix + "Assem", 0x0003)
            self.add(prefix + "Family", 0x0004)
            self.add(prefix + "FamORAssem", 0x0005)
            self.add(prefix + "Public", 0x0006)

            prefix = ""
            self.add(prefix + "Static", 0x0010)
            self.add(prefix + "Final", 0x0020)
            self.add(prefix + "Virtual", 0x0040)
            self.add(prefix + "HideBySig", 0x0080)

            prefix = "VtableLayout_"
            #self.add(prefix+"ReuseSlot", 0x0000)  # TODO: this will not work (it will conflict with CompilerControlled)
            self.add(prefix + "NewSlot", 0x0100)

            prefix = ""
            self.add(prefix + "Strict", 0x0200)
            self.add(prefix + "Abstract", 0x0400)
            self.add(prefix + "SpecialName", 0x0800)

            self.add(prefix + "PInvokeImpl", 0x2000)
            self.add(prefix + "UnmanagedExport", 0x0008)

            self.add(prefix + "RTSpecialName", 0x1000)
            self.add(prefix + "HasSecurity", 0x4000)
            self.add(prefix + "RequireSecObject", 0x8000)

    class CliEnumMethodImplAttributes(EnumDataType):
        dataType = CliEnumMethodImplAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "MethodImplAttributes", 2)
            prefix = "CodeType_"
            self.add(prefix + "IL", 0x0000)
            self.add(prefix + "Native", 0x0001)
            self.add(prefix + "OPTIL", 0x0002)
            self.add(prefix + "Runtime", 0x0003)

            prefix = ""
            #self.add(prefix+"Managed", 0x0000)  # TODO: This will not work (Will conflict with IL)
            self.add(prefix + "Unmanaged", 0x0004)
            self.add(prefix + "ForwardRef", 0x0010)
            self.add(prefix + "PreserveSig", 0x0080)
            self.add(prefix + "InternalCall", 0x1000)
            self.add(prefix + "Synchronized", 0x0020)
            self.add(prefix + "NoInlining", 0x0008)
            self.add(prefix + "MaxMethodImplVal", 0xffff)
            self.add(prefix + "NoOptimization", 0x0040)

    class CliEnumMethodSemanticsAttributes(EnumDataType):
        dataType = CliEnumMethodSemanticsAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "MethodSemanticsAttributes", 2)
            prefix = ""
            self.add(prefix + "Setter", 0x0001)
            self.add(prefix + "Getter", 0x0002)
            self.add(prefix + "Other", 0x0004)
            self.add(prefix + "AddOn", 0x0008)
            self.add(prefix + "RemoveOn", 0x0010)
            self.add(prefix + "Fire", 0x0020)

    class CliEnumParamAttributes(EnumDataType):
        dataType = CliEnumParamAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "ParamAttributes", 2)
            prefix = ""
            self.add(prefix + "In", 0x0001)
            self.add(prefix + "Out", 0x0002)
            self.add(prefix + "Optional", 0x0010)
            self.add(prefix + "HasDefault", 0x1000)
            self.add(prefix + "HasFieldMarshal", 0x2000)

    class CliEnumPropertyAttributes(EnumDataType):
        dataType = CliEnumPropertyAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "PropertyAttributes", 2)
            prefix = ""
            self.add(prefix + "SpecialName", 0x0200)
            self.add(prefix + "RTSpecialName", 0x0400)

    class CliEnumTypeAttributes(EnumDataType):
        dataType = CliEnumTypeAttributes()

        def __init__(self):
            super().__init__(CategoryPath(PATH), "TypeAttributes", 4)
            prefix = "Visibility_"
            self.add(prefix + "NotPublic", 0x00000000)
            self.add(prefix + "Public", 0x00000001)
            self.add(prefix + "NestedPublic", 0x00000002)
            self.add(prefix + "NestedPrivate", 0x00000003)
            self.add(prefix + "NestedFamily", 0x00000004)
            self.add(prefix + "NestedAssembly", 0x00000005)
            self.add(prefix + "NestedFamANDAssem", 0x00000006)
            self.add(prefix + "NestedFamORAssem", 0x00000007)

            prefix = ""
            #self.add(prefix+"AutoLayout", 0x00000000)  # TODO: Will not work, will conflict with Visibility_NotPublic
            self.add(prefix + "SequentialLayout", 0x00000008)
            self.add(prefix + "ExplicitLayout", 0x00000010)

            prefix = ""
            #self.add(prefix+"Class", 0x00000000)  # TODO: Will not work, will conflict with Visibility_NotPublic
            self.add(prefix + "Interface", 0x00000020)

            self.add(prefix + "Abstract", 0x00000080)
            self.add(prefix + "Sealed", 0x00000100)
            self.add(prefix + "SpecialName", 0x00000400)

            self.add(prefix + "Import", 0x00001000)
            self.add(prefix + "Serializable", 0x00002000)

            #self.add(prefix+"AnsiClass", 0x00000000)  # TODO: Will not work, will conflict with Visibility_NotPublic
            self.add(prefix + "UnicodeClass", 0x00010000)
            self.add(prefix + "AutoClass", 0x00020000)
            self.add(prefix + "CustomFormatClass", 0x00030000)

            self.add(prefix + "CustomStringFormatMask", 0x00C00000)

            self.add(prefix + "BeforeFieldInit", 0x00100000)

            self.add(prefix + "RTSpecialName", 0x00000800)
            self.add(prefix + "HasSecurity", 0x00040000)
            self.add(prefix + "IsTypeForwarder", 0x00200000)


class EnumDataType:
    def __init__(self, category_path, name, size):
        pass

    def add(self, value_name, value):
        pass


class CategoryPath:
    def __init__(self, path):
        self.path = path
