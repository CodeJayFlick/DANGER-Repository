class SleighLanguageValidator:
    ldefs_relax_schema_file = None
    pspec_relax_schema_file = None
    cspec_relax_schema_file = None
    
    CSPEC_TYPE = 1
    PSPEC_TYPE = 2
    LDEFS_TYPE = 3
    CSPECTAG_TYPE = 4

    LANGUAGE_ TYPESTRING = "language definitions"
    COMPILER_ TYPESTRING = "compiler specification"
    PROCESSOR_ TYPESTRING = "processor specification"

    def __init__(self, type):
        self.verifier_type = type
        if type in [SleighLanguageValidator.CSPEC_TYPE, SleighLanguageValidator.CSPECTAG_TYPE]:
            schema_file = SleighLanguageValidator.cspec_relax_schema_file
        elif type == SleighLanguageValidator.PSPEC_TYPE:
            schema_file = SleighLanguageValidator.pspec_relax_schema_file
        else:
            schema_file = SleighLanguageValidator.ldefs_relax_schema_file
        
        self.verifier = None
        try:
            self.verifier = get_verifier(schema_file)
        except Exception as e:
            raise SleighException("Error creating verifier", e)

    def verify(self, spec_file):
        if not FileUtilities.exists_and_is_case_dependent(spec_file):
            raise SleighException(f"{spec_file} is not properly case dependent")
        
        try:
            in = spec_file.get_input_stream()
            self.verifier.set_error_handler(VerifierErrorHandler(spec_file))
            self.verifier.verify(InputSource(in))
            in.close()
        except Exception as e:
            raise SleighException(f"Invalid {self.get_type_string()} file: {spec_file}", e)

    def verify_xml(self, title, document):
        if self.verifier_type != SleighLanguageValidator.CSPECTAG_TYPE:
            raise SleighException("Only cspec tag verification is supported")
        
        buffer = StringBuilder()
        buffer.append("<compiler_spec>\n")
        buffer.append("<default_proto>\n")
        buffer.append("<prototype name=\"a\" extrapop=\"0\" stackshift=\"0\">\n")
        buffer.append("<input/><output/>\n")
        buffer.append("</prototype>\n")
        buffer.append("</default_proto>\n")
        buffer.append(document)
        buffer.append("</compiler_spec>\n")

        reader = StringReader(buffer.toString())
        
        self.verifier.set_error_handler(VerifierErrorHandler(title, 6))
        try:
            self.verifier.verify(InputSource(reader))
        except Exception as e:
            raise SleighException(f"Invalid {self.get_type_string()} file: {title}", e)

    def get_type_string(self):
        if self.verifier_type == SleighLanguageValidator.PSPEC_TYPE:
            return SleighLanguageValidator.PROCESSOR_ TYPESTRING
        elif self.verifier_type == SleighLanguageValidator.LDEFS_TYPE:
            return SleighLanguageValidator.LANGUAGE_ TYPESTRING
        else:
            return SleighLanguageValidator.COMPILER_ TYPESTRING

    @staticmethod
    def validate_ldefs_file(ldefs_file):
        if not FileUtilities.exists_and_is_case_dependent(ldefs_file):
            raise SleighException(f"{ldefs_file} is not properly case dependent")
        
        try:
            in = ldfs_file.get_input_stream()
            verifier = get_verifier(SleighLanguageValidator.ldefs_relax_schema_file)
            verifier.set_error_handler(VerifierErrorHandler(ldfs_file))
            verifier.verify(InputSource(in))
            in.close()
        except Exception as e:
            raise SleighException(f"Invalid language definitions file: {ldfs_file}", e)

    @staticmethod
    def validate_pspec_file(pspec_file):
        if not FileUtilities.exists_and_is_case_dependent(pspec_file):
            raise SleighException(f"{pspec_file} is not properly case dependent")
        
        try:
            in = pspec_file.get_input_stream()
            verifier = get_verifier(SleighLanguageValidator.pspec_relax_schema_file)
            verifier.set_error_handler(VerifierErrorHandler(pspec_file))
            verifier.verify(InputSource(in))
            in.close()
        except Exception as e:
            raise SleighException(f"Invalid processor specification file: {pspec_file}", e)

    @staticmethod
    def validate_cspec_file(cspec_file):
        if not FileUtilities.exists_and_is_case_dependent(cspec_file):
            raise SleighException(f"{cspec_file} is not properly case dependent")
        
        try:
            in = cspec_file.get_input_stream()
            verifier = get_verifier(SleighLanguageValidator.cspec_relax_schema_file)
            verifier.set_error_handler(VerifierErrorHandler(cspec_file))
            verifier.verify(InputSource(in))
            in.close()
        except Exception as e:
            raise SleighException(f"Invalid compiler specification file: {cspec_file}", e)

    @staticmethod
    def get_verifier(relax_schema_file):
        factory = TheFactoryImpl()
        schema = factory.compile_schema(relax_schema_file)
        verifier = schema.new_verifier()
        return verifier

class VerifierErrorHandler:
    document_title = None
    line_number_base = 0

    def __init__(self, file):
        self.document_title = str(file)
        self.line_number_base = 0
    
    @staticmethod
    def __new__(cls, title, base):
        instance = cls.__dict__.get('__dict__', {}).setdefault(cls.__name__, lambda: None)()
        return instance

    def fatalError(self, e):
        error(e)

    def error(self, e):
        lineno = e.get_line_number() - self.line_number_base
        Msg.error(SleighLanguageValidator, f"Error validating {self.document_title} at {lineno}:{e.get_column_number()}, {str(e)}")

    @staticmethod
    def error(e):
        print(f"Error: {str(e)}")
