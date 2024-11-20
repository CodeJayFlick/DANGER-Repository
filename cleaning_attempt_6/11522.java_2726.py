import xml.etree.ElementTree as ET
from typing import Dict, List

class SleighLanguageProvider:
    RELATIVE_PATHS_PATTERN = r"(.*)\.(\/|\\)\\.?.?(\/|\\)|\.(\.(\/|\\))"

    def __init__(self):
        self.languages: Dict[str, 'SleighLanguage'] = {}
        self.descriptions: Dict[str, 'SleighLanguageDescription'] = {}

    @staticmethod
    def create_languages(self):
        files = Application.find_files_by_extension_in_application(".ldefs")
        for file in files:
            try:
                SleighLanguageValidator.validate_ldefs_file(file)
                self.create_language_descriptions(file)
            except Exception as e:
                Msg.show_error(self, "Problem loading " + str(file), "Validation error: " + str(e))

    def create_languages(self):
        Iterable[ResourceFile] = Application.find_files_by_extension_in_application(".ldefs")
        for file in files:
            self.create_language_descriptions(file)

    @staticmethod
    def read(parser, parent_directory, ldefs) -> None:
        id = parser.get("id")
        processor_name = parser.get("processor")
        endian = Endian.valueOf(parser.get("endian").upper())
        instruction_endian = endian
        size = int(parser.get("size"))
        variant = parser.get("variant")
        version_text = parser.get("version")
        version_pieces = version_text.split(".")
        version = 1
        minor_version = 0
        try:
            version = int(version_pieces[0])
            if len(version_pieces) > 1:
                minor_version = int(version_pieces[1])
        except Exception as e:
            raise SleighException("Version tag must specify address <major>[.<minor>] version numbers", e)

    def create_language_descriptions(self, file):
        try:
            parser = ET.XMLPullParser()
            read(parser, file.parent_directory(), file.name())
        finally:
            parser.dispose()

    @staticmethod
    def find_file(parent_dir, filename_or_relative_path, extension) -> ResourceFile:
        if os.path.exists(filename_or_relative_path):
            return ResourceFile(parent_dir, filename_or_relative_path)
        else:
            relative_path = discard_relative_path(filename_or_relative_path)
            for resource_file in Application.find_files_by_extension_in_application(extension):
                if resource_file.get_absolute_path().endswith(relative_path):
                    return resource_file
            missing_file = ResourceFile(parent_dir, filename_or_relative_path)
            raise SleighException("Missing sleigh file: " + str(missing_file))

    @staticmethod
    def discard_relative_path(str) -> None:
        pattern = re.compile(SleighLanguageProvider.RELATIVE_PATHS_PATTERN)
        return pattern.sub("", str)

    @staticmethod
    def find_files(filename, extension):
        matches = []
        files = Application.find_files_by_extension_in_application(extension)
        for resource_file in files:
            if resource_file.get_name().equals(filename):
                matches.append(resource_file)
        return matches

class SleighLanguageDescription:
    pass

class ResourceFile:
    pass
