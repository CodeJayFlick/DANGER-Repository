import os
import logging
from typing import Dict, List

class Config:
    def __init__(self):
        self.library = None
        self.package_name = None
        self.output_dir = None
        self.header_files = []
        self.mapping_file = None

    @classmethod
    def get_options(cls) -> Dict[str, str]:
        options = {}
        for option in ["library", "package", "output", "header", "mappingFile"]:
            options[f"--{option}"] = f"set {option}"
        return options

    def set_library(self, library: str):
        self.library = library

    def get_library(self) -> str:
        return self.library

    def set_package_name(self, package_name: str):
        self.package_name = package_name

    def get_package_name(self) -> str:
        return self.package_name

    def set_output_dir(self, output_dir: str):
        self.output_dir = output_dir

    def get_output_dir(self) -> str:
        return self.output_dir

    def add_header_file(self, header_file: str):
        self.header_files.append(header_file)

    def get_header_files(self) -> List[str]:
        return self.header_files

    def set_mapping_file(self, mapping_file: str):
        self.mapping_file = mapping_file

    def get_mapping_file(self) -> str:
        return self.mapping_file


def main(args: List[str]):
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    config = Config()
    try:
        for arg in args[1:]:
            if "--library" == arg[:9]:
                config.set_library(arg[10:])
            elif "--package" == arg[:8]:
                config.set_package_name(arg[9:])
            elif "--output" == arg[:7]:
                config.set_output_dir(arg[8:])
            elif "--header" in arg:
                config.add_header_file(arg.split("=")[1])
            elif "--mappingFile" == arg[:13]:
                config.set_mapping_file(arg[14:])

        if not all([config.library, config.package_name, config.output_dir]):
            logger.error("Required options are missing")
            return -1

        os.makedirs(config.get_output_dir(), exist_ok=True)

        jna_parser = JnaParser()
        typedef_map = jna_parser.get_typedef_map()
        struct_map = jna_parser.get_struct_map()

        generator = JnaGenerator(
            library=config.library,
            package_name=config.package_name,
            typedef_map=typedef_map,
            structs=list(struct_map.keys()),
            mapping_file=config.get_mapping_file(),
        )
        generator.init(config.get_output_dir())

        for header_file in config.get_header_files():
            jna_parser.parse(header_file)

        generator.write_native_size()
        generator.write_structure(struct_map)
        generator.write_library(jna_parser.get_functions(), jna_parser.get_enum_map())
    except Exception as e:
        logger.error("", e)
        return -1


if __name__ == "__main__":
    main(sys.argv)
