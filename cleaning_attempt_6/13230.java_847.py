class AttributeFactory:
    @staticmethod
    def get(reader, constant_pool):
        try:
            attribute_name_index = reader.read_short()
            if 1 > attribute_name_index or attribute_name_index >= len(constant_pool):
                raise RuntimeError("invalid index")
            
            if not isinstance(constant_pool[attribute_name_index], ConstantPoolUtf8Info):
                raise RuntimeError()

            utf8_info = constant_pool[attribute_name_index]
            attribute_type = utf8_info.get_string()
            
            if attribute_type == "AnnotationDefault":
                return AnnotationDefaultAttribute(reader)
            elif attribute_type == "BootstrapMethods":
                return BootstrapMethodsAttribute(reader)
            elif attribute_type == "Code":
                return CodeAttribute(reader, constant_pool)
            elif attribute_type == "ConstantValue":
                return ConstantValueAttribute(reader)
            elif attribute_type == "Deprecated":
                return DeprecatedAttribute(reader)
            elif attribute_type == "EnclosingMethod":
                return EnclosingMethodAttribute(reader)
            elif attribute_type == "Exceptions":
                return ExceptionsAttribute(reader)
            elif attribute_type == "InnerClasses":
                return InnerClassesAttribute(reader)
            elif attribute_type == "LineNumberTable":
                return LineNumberTableAttribute(reader)
            elif attribute_type == "LocalVariableTable":
                return LocalVariableTableAttribute(reader, constant_pool)
            elif attribute_type == "LocalVariableTypeTable":
                return LocalVariableTypeTableAttribute(reader)
            elif attribute_type == "ModuleMainClass":
                return ModuleMainClassAttribute(reader)
            elif attribute_type == "ModulePackages":
                return ModulePackagesAttribute(reader)
            elif attribute_type == "NestHost":
                return NestHostAttribute(reader)
            elif attribute_type == "NestMembers":
                return NestMembersAttribute(reader)
            elif attribute_type == "RuntimeInvisibleAnnotations":
                return RuntimeInvisibleAnnotationsAttribute(reader)
            elif attribute_type == "RuntimeInvisibleParameterAnnotations":
                return RuntimeParameterAnnotationsAttribute(reader, False)  # invisible
            elif attribute_type == "RuntimeVisibleAnnotations":
                return RuntimeVisibleAnnotationsAttribute(reader)
            elif attribute_type == "RuntimeVisibleParameterAnnotations":
                return RuntimeParameterAnnotationsAttribute(reader, True)   # visible
            elif attribute_type == "Signature":
                return SignatureAttribute(reader)
            elif attribute_type == "SourceDebugExtension":
                return SourceDebugExtensionAttribute(reader)
            elif attribute_type == "SourceFile":
                return SourceFileAttribute(reader)
            elif attribute_type == "StackMapTable":
                return StackMapTableAttribute(reader)
            elif attribute_type == "Synthetic":
                return SyntheticAttribute(reader)
            elif attribute_type == "Module":
                return ModuleAttribute(reader)
            else:
                raise RuntimeError(f"Unknown attribute type: {attribute_type}")
        except Exception as e:
            print(str(e))
