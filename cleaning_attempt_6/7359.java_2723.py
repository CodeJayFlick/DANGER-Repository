import ghidra_file_formats_ios_img2 as img2_util
from ghidra_app_util_bin import *
from ghidra_app_util_importer_message_log import MessageLog
from ghidra_file_analyzers import FileFormatAnalyzer
from ghidra_program_model_address import Address
from ghidra_program_model_data import DataType
from ghidra_program_model_listing import Data, Program

class Img2Analyzer(FileFormatAnalyzer):
    def canAnalyze(self, program):
        try:
            return img2_util.is_img2(program)
        except Exception as e:
            # ignore exceptions
            pass
        return False

    def getDefaultEnablement(self, program):
        return img2_util.is_img2(program)

    def getDescription(self):
        return "Annotates an IMG2 file."

    def getName(self):
        return "IMG2 Annotation"

    def isPrototype(self):
        return True

    def analyze(self, program, set, monitor, log):
        try:
            provider = MemoryByteProvider(program.memory(), program.address_factory().default_address_space())
            reader = BinaryReader(provider, True)

            header = Img2(reader)

            if not header.signature == img2_util.IMG2_SIGNATURE:
                log.append_msg("Invalid Img2 file!")
                return False

            header_data_type = header.to_data_type()
            data = create_data(program, program.address(0), header_data_type)
            create_fragment(program, header_data_type.name, data.min_address(), data.max_address().add(1))

            change_format_to_string(data.component(0))
            change_format_to_string(data.component(1))

            data_start_address = data.max_address().add(1)
            data_end_address = data_start_address.add(header.data_len())
            create_fragment(program, "DATA", data_start_address, data_end_address)

        except Exception as e:
            # handle exceptions
            pass

        if header.data_len() != header.data_len_padded():
            padding_start_address = data_end_address.add(1)
            padding_end_address = padding_start_address.add(header.data_len_padded() - header.data_len())
            create_fragment(program, "PADDING", padding_start_address, padding_end_address)

        remove_empty_fragments(program)

        return True

def to_addr(program, addr):
    # implement this function
    pass

def create_data(program, address, data_type):
    # implement this function
    pass

def change_format_to_string(data):
    # implement this function
    pass

def create_fragment(program, name, start_address, end_address):
    # implement this function
    pass

def remove_empty_fragments(program):
    # implement this function
    pass
