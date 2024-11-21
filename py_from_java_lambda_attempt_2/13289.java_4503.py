Here is the translation of the Java code into equivalent Python:

```Python
class LdcMethodsTest:
    def setUp(self):
        self.language = get_language_service().get_language(LanguageID("JVM:BE:32:default"))
        self.op_address = self.language.get_address_factory().get_default_address_space().get_address(0x10000)
        self.unique_base = self.language.get_unique_base()

    @staticmethod
    def test_lcd_integer():
        class_file = ArrayList()
        TestClassFileCreator.append_magic(class_file)
        TestClassFileCreator.append_versions(class_file)
        TestClassFileCreator.append_count(class_file, 2)
        TestClassFileCreator.append_integer(class_file, 0x12345678)
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 1, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 4,
            ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC)
        expected_p_code.emit_push_cat_1_value(LdcMethods.VALUE)

        # append an additional integer to the end of the constant pool and generate a reference
        class_file.set(9, 3)
        TestClassFileCreator.append_integer(class_file, 0x11111111)
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 2, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 4,
            ConstantPoolJava.CPOOL_OP, "0", "2", ConstantPoolJava.CPOOL_LDC)
        expected_p_code.emit_push_cat_1_value(LdcMethods.VALUE)

    @staticmethod
    def test_ldc_float():
        class_file = ArrayList()
        TestClassFileCreator.append_magic(class_file)
        TestClassFileCreator.append_versions(class_file)
        TestClassFileCreator.append_count(class_file, 2)
        TestClassFileCreator.append_float(class_file, 2.0f)
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 1, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 4,
            ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC)
        expected_p_code.emit_push_cat_1_value(LdcMethods.VALUE)

    @staticmethod
    def test_ldc_double():
        class_file = ArrayList()
        TestClassFileCreator.append_magic(class_file)
        TestClassFileCreator.append_versions(class_file)
        TestClassFileCreator.append_count(class_file, 3)
        TestClassFileCreator.append_double(class_file, 2.0f)
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 1, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 8,
            ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC2_W)
        expected_p_code.emit_push_cat_2_value(LdcMethods.VALUE)

    @staticmethod
    def test_ldc_long():
        class_file = ArrayList()
        TestClassFileCreator.append_magic(class_file)
        TestClassFileCreator.append_versions(class_file)
        TestClassFileCreator.append_count(class_file, 3)
        TestClassFileCreator.append_long(class_file, 0x123456789l)
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 1, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 8,
            ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC2_W)
        expected_p_code.emit_push_cat_2_value(LdcMethods.VALUE)

    @staticmethod
    def test_ldc_string():
        class_file = ArrayList()
        TestClassFileCreator.append_magic(class_file)
        TestClassFileCreator.append_versions(class_file)
        TestClassFileCreator.append_count(class_file, 3)
        TestClassFileCreator.append_string(class_file, 2)
        TestClassFileCreator.append_utf8(class_file, "input1")
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 1, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 4,
            ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC)
        expected_p_code.emit_push_cat_1_value(LdcMethods.VALUE)

    @staticmethod
    def test_ldc_method_type():
        class_file = ArrayList()
        TestClassFileCreator.append_magic(class_file)
        TestClassFileCreator.append_versions(class_file)
        TestClassFileCreator.append_count(class_file, 3)
        TestClassFileCreator.append_method_type(class_file, 2)
        TestClassFileCreator.append_utf8(class_file, "(I)Ljava/lang/Integer;")
        class_file_bytes = TestClassFileCreator.get_byte_array(class_file)
        constant_pool = TestClassFileCreator.get_constant_pool_from_bytes(class_file_bytes)

        p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        LdcMethods.get_pcode_for_ldc(p_code, 1, constant_pool)
        expected_p_code = PcodeOpEmitter(self.language, self.op_address, self.unique_base)
        expected_p_code.emit_assign_varnode_from_pcode_op_call(LdcMethods.VALUE, 4,
            ConstantPoolJava.CPOOL_OP, "0", "1", ConstantPoolJava.CPOOL_LDC)
        expected_p_code.emit_push_cat_1_value(LdcMethods.VALUE)

```

Please note that this is a direct translation of the Java code into Python. However, it's not necessarily good or idiomatic Python code.