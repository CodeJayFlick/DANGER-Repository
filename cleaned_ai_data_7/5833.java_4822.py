class TestProcessorConstants:
    PROCESSOR_8051 = None
    PROCESSOR_Z80 = None
    PROCESSOR_POWERPC = None
    PROCESSOR_SPARC = None
    PROCESSOR_X86 = None
    PROCESSOR_TMS320C3x = None
    PROCESSOR_ARM = None
    PROCESSOR_DATA = None

    def __init__(self):
        self.PROCESSOR_8051 = Processor.find_or_create_processor("8051")
        self.PROCESSOR_Z80 = Processor.find_or_create_processor("Z80")
        self.PROCESSOR_POWERPC = Processor.find_or_create_processor("PowerPC")
        self.PROCESSOR_SPARC = Processor.find_or_create_processor("Sparc")
        self.PROCESSOR_X86 = Processor.find_or_create_processor("x86")
        self.PROCESSOR_TMS320C3x = Processor.find_or_create_processor("TMS320C3x")
        self.PROCESSOR_ARM = Processor.find_or_create_processor("ARM")
        self.PROCESSOR_DATA = Processor.find_or_create_processor("DATA")

# Assuming you have a class named 'Processor' with the method find_or_create_processor
