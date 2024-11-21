import os
import sys
from collections import defaultdict

class GHelpBuilder:
    TOC_OUTPUT_FILE_APPENDIX = "_TOC.xml"
    MAP_OUTPUT_FILE_APPENDIX = "_map.xml"
    HELP_SET_OUTPUT_FILE_APPENDIX = "_HelpSet.hs"
    HELP_SEARCH_DIRECTORY_APPENDIX = "_JavaHelpSearch"

    OUTPUT_DIRECTORY_OPTION = "-o"
    MODULE_NAME_OPTION = "-n"
    HELP_PATHS_OPTION = "-hp"
    DEBUG_SWITCH = "-debug"
    IGNORE_INVALID_SWITCH = "-ignoreinvalid"

    def __init__(self):
        self.output_directory_name = None
        self.module_name = None
        self.dependency_help_paths = defaultdict(set)
        self.help_input_directories = set()
        self.debug_enabled = False
        self.ignore_invalid = False

    @staticmethod
    def main(args):
        builder = GHelpBuilder()
        builder.exit_on_error = True

        config = ApplicationConfiguration()
        Application.initialize_application(GhidraApplicationLayout(), config)

        builder.build(args)

    def build(self, args):
        self.parse_arguments(args)
        all_help = self.collect_all_help()
        link_database = LinkDatabase(all_help)

        if not self.debug_enabled:
            print("Validating help directories...")
        results = self.validate_help_directories(all_help, link_database)
        if results.failed():
            message = "Found invalid help:\n" + results.message
            if self.ignore_invalid:
                print(message)
            else:
                exitWithError(message)

        print("\tfinished validating help directories")

        print("Building JavaHelp output files...")
        self.build_java_help_files(link_database)
        print("\tfinished building output files")

    def collect_all_help(self):
        all_help = set()
        for file in self.help_input_directories:
            all_help.add(file)
        for file in self.dependency_help_paths:
            all_help.add(file)
        return HelpModuleCollection.from_files(all_help)

    def validate_help_directories(self, help, link_database):
        validator = JavaHelpValidator(self.module_name, help)
        validator.set_debug_enabled(self.debug_enabled)

        invalid_links = validator.validate(link_database)
        duplicate_anchors = link_database.get_duplicate_anchors()

        if not self.debug_enabled:
            print("Finished validating help files--all valid!")

        results = Results(f"Found {len(invalid_links)} invalid links and {len(duplicate_anchors)} duplicate anchors", True)

        return results

    def build_java_help_files(self, link_database):
        output_directory = os.path.join(os.getcwd(), self.output_directory_name)
        file_builder = JavaHelpFilesBuilder(output_directory, self.module_name, link_database)

        help_module_collection = HelpModuleCollection.from_files(self.help_input_directories)

        try:
            file_builder.generate_help_files(help_module_collection)
        except Exception as e:
            exitWithError("Unexpected error building help module files:", e)

        help_set_file = os.path.join(output_directory, self.module_name + self.HELP_SET_OUTPUT_FILE_APPENDIX)
        map_file = os.path.join(output_directory, self.module_name + self.MAP_OUTPUT_FILE_APPENDIX)
        toc_file = os.path.join(output_directory, self.module_name + self.TOC_OUTPUT_FILE_APPENDIX)

        indexer_output_directory = os.path.join(output_directory, self.module_name + self.HELP_SEARCH_DIRECTORY_APPENDIX)

        help_set_builder = JavaHelpSetBuilder(self.module_name, map_file, toc_file, indexer_output_directory, help_set_file)
        try:
            help_set_builder.write_help_set_file()
        except IOException as e:
            exitWithError("Error building helpset for module: " + self.module_name, e)

    def parse_arguments(self, args):
        i = 0
        while i < len(args):
            opt = args[i]
            if opt == self.OUTPUT_DIRECTORY_OPTION:
                i += 1
                if i >= len(args):
                    print("Missing output directory: " + self.OUTPUT_DIRECTORY_OPTION)
                    printUsage()
                    sys.exit(1)

                self.output_directory_name = args[i]

            elif opt == self.MODULE_NAME_OPTION:
                i += 1
                if i >= len(args):
                    print("Missing module name: " + self.MODULE_NAME_OPTION)
                    printUsage()
                    sys.exit(1)

                self.module_name = args[i]

            elif opt == self.HELP_PATHS_OPTION:
                i += 1
                if i >= len(args):
                    print("Must specify at least one input directory")
                    printUsage()
                    sys.exit(1)

                hp = args[i]
                for p in hp.split(os.path.sep):
                    file_path = os.path.join(p)
                    self.dependency_help_paths.add(file_path)

            elif opt == self.DEBUG_SWITCH:
                self.debug_enabled = True

            elif opt == self.IGNORE_INVALID_SWITCH:
                self.ignore_invalid = True
            else:
                if not args[i].startswith("-"):
                    self.help_input_directories.add(args[i])
                i += 1

        if len(self.help_input_directories) == 0:
            print("Must specify at least one input directory")
            printUsage()
            sys.exit(1)

    def exitWithError(self, message):
        try:
            # give the output thread a chance to finish it's output (this is a workaround for
            # the Eclipse editor, and its use of two threads in its console).
            time.sleep(0.25)
        except Exception as e:
            pass

        print("[" + self.__class__.__name__ + "] " + message)

    def flush(self):
        sys.stdout.flush()
        sys.stderr.flush()

    @staticmethod
    def debug(message):
        if GHelpBuilder.debug_enabled:
            print("\t" + message)
            GHelpBuilder.flush()


# Inner Classes

class Results:
    def __init__(self, message, failed):
        self.message = message
        self.failed = failed

    def getMessage(self):
        return self.message

    @staticmethod
    def from_string(message):
        if "Failed to" in message or "Error:" in message:
            return True
        else:
            return False


class LinkDatabase:
    pass


def printUsage():
    print("Usage: GHelpBuilder [-options] [inputs...]")
    print("       (to build help for a Ghidra module)")
    print("where options include:")
    print(f"     {GHelpBuilder.OUTPUT_DIRECTORY_OPTION} <output directory>")
    print(f"                  REQUIRED to specify the output location of the built help")
    print(f"     {GHelpBuilder.MODULE_NAME_OPTION} [name]")
    print(f"                  REQUIRED to specify the module name for this build")
    print(f"     {GHelpBuilder.HELP_PATHS_OPTION} <help paths>")
    print("                  to specify additional help directories or files to include in the built help")
    print(f"     {GHelpBuilder.DEBUG_SWITCH}")
    print("                  to enable debugging output")
    print(f"     {GHelpBuilder.IGNORE_INVALID_SWITCH}")
    print("                  to continue despite broken links and anchors")


def exitWithError(message):
    try:
        # give the output thread a chance to finish it's output (this is a workaround for
        # the Eclipse editor, and its use of two threads in its console).
        time.sleep(0.25)
    except Exception as e:
        pass

    print("[" + GHelpBuilder.__name__ + "] " + message)


def main():
    if __name__ == "__main__":
        args = sys.argv[1:]
        builder = GHelpBuilder()
        builder.main(args)

if __name__ == "__main__":
    main()

