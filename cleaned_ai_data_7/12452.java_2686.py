class ExternalLanguageCompilerSpecQuery:
    def __init__(self, external_processor_name: str, external_tool: str,
                 endian: int, size: int, compiler_spec_id: object):
        self.external_processor_name = external_processor_name
        self.external_tool = external_tool
        self.endian = endian
        self.size = size
        self.compiler_spec_id = compiler_spec_id

    def __str__(self) -> str:
        return f"externalProcessorName={self.external_processor_name}; " \
               f"externalTool={self.external_tool}; " \
               f"endian={self.endian}; " \
               f"size={self.size}; " \
               f"compiler={self.compiler_spec_id}"
