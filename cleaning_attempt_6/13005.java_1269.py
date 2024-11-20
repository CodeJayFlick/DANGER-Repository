import os
import re
from unittest import TestCase
from io import StringIO
from contextlib import redirect_stdout

class SleighCompileRegressionTest(TestCase):
    TOO_MANY_ERRORS = 100
    
    def setUp(self):
        self.log = logging.getLogger(__name__)

    def itsOK(self, message, condition):
        if not condition:
            self.current_lang_bad_count += 1
            if self.current_lang_bad_count <= self.TOO_MANY_ERRORS + 1:
                self.log.fatal(message)
            else:
                all_ok = False
        return condition

    def test_external(self):
        summary = StringBuffer()
        
        LoggingInitialization.initialize_logging_system()
        inputs = get_slaspec_files()
        for inputFile in inputs:
            input_name = os.path.splitext(inputFile.getName())[0].replaceFirst("\\.slaspec$", "-")
            target_file = create_temp_file("target-" + input_name, ".sla")
            actual_file = create_temp_file("actual-" + input_name, ".sla")
            self.log.info(f"Testing {inputFile} (in {target_file} and {actual_file})")

            target_retval = run_target_compiler(inputFile, target_file)
            if itsOK("non-zero target compiler return value", 0 == target_retval):
                actual_retval = run_actual_compiler(inputFile.getFile(False), actual_file)
                if itsOK("non-zero actual compiler return value", 0 == actual_retval):
                    self.current_lang_bad_count = 0
                    ok = compares_ok(actual_file, target_file)

                    if ok:
                        assertTrue(f"could not delete target output file {target_file}", os.remove(target_file))
                        assertTrue(f"could not delete actual output file {actual_file}", os.remove(actual_file))
                    else:
                        summary.append(f"Sleigh compile mismatch for: {inputFile}\n")

                else:
                    summary.append(f"Sleigh(Java) compile failed for: {inputFile}\n")
            else:
                summary.append(f"Sleigh(C) compile failed for: {inputFile}\n")

        if all_ok:
            self.log.info("SUCCESS!  Finished all tests.")
        else:
            self.log.error("FAILURE.  Look in the log above for Sleigh ERROR messages\n" + str(summary))
            self.fail("Sleigh language errors found")

    def run_target_compiler(self, inputFile, target_file):
        command = get_cpp_sleigh_compiler_for_arch()
        process_builder = ProcessBuilder(command, "-DMIPS=../../../../../../ghidra/Ghidra/Processors/MIPS", 
                                         "-D8051=../../../../../../ghidra/Ghidra/Processors/8051",
                                         inputFile.getAbsolutePath(), target_file.getAbsolutePath())
        process_builder.directory(inputFile.getParentFile().getFile(False))
        process = process_builder.start()

        new IOThread(process.getInputStream()).start()
        new IOThread(process.getErrorStream()).start()

        retval = process.waitFor()
        return retval

    def get_cpp_sleigh_compiler_for_arch(self):
        if os.name == 'nt':
            exe_name = "sleigh.exe"
        else:
            exe_name = "sleigh"

        file_path = Application.getOSFile(exe_name)
        return file_path.getAbsolutePath()

    class IOThread(threading.Thread):
        def __init__(self, input_stream):
            self.shell_output = BufferedReader(InputStreamReader(input_stream))
        
        def run(self):
            line = None
            try:
                while (line := self.shell_output.readLine()) is not None:
                    print(line)
            except Exception as e:
                # DO NOT USE LOGGING HERE  (class loader)
                sys.stderr.write(f"Unexpected Exception: {e.getMessage()}")
                e.printStackTrace(sys.stderr)

    def run_actual_compiler(self, inputFile, actual_file):
        return SleighCompileLauncher.run_main(["-DBaseDir=../../../../../../", 
                                               "-DMIPS=ghidra/Ghidra/Processors/MIPS", 
                                               "-D8051=ghidra/Ghidra/Processors/8051",
                                               inputFile.getAbsolutePath(), actual_file.getAbsolutePath()])

    def compares_ok(self, actual_file, target_file):
        ok = True
        actual_reader = PushbackEntireLine(BufferedReader(FileReader(actual_file)))
        target_reader = PushbackEntireLine(BufferedReader(FileReader(target_file)))

        while True:
            try:
                if self.current_lang_bad_count >= 100:
                    ok = itsOK("WAY TOO MANY DIFFERENCES, BAILING", False)
                    break

                actual_line = actual_reader.readLine()
                target_line = target_reader.readLine()

                if target_line is None:
                    ok &= itsOK("target has too many lines", actual_line == None)
                    break
                elif actual_line is None:
                    ok &= itsOK("actual has too few lines", False)
                    break

                actual_is_space = re.match(r'^\s*<print piece=" " />$|^$', actual_line).group()
                target_is_space = re.match(r'^\s*<print piece=" " />$|^$', target_line).group()

                if not (actual_is_space and target_is_space):
                    ok &= itsOK(f"difference on actual line {actual_reader.line_number}, target line {target_reader.line_number}:"
                               f"\nEXPECTED:\n{target_line}\nACTUAL:\n{actual_line}", 
                              target_line == actual_line)
                else:
                    if not re.match(r'^\s*<construct_tpl>$|^$', actual_line):
                        ok &= itsOK(f"difference (space!) on actual line {actual_reader.line_number},"
                                   f" target line {target_reader.line_number}:"
                                   f"\nEXPECTED:\n{target_line}\nACTUAL:\n{actual_line}", 
                                  False)

                while actual_is_space:
                    actual_line = actual_reader.readLine()
                    actual_reader.line_number += 1
                    if actual_line is None or re.match(r'^\s*<print piece=" " />$|^$', actual_line).group():
                        break

                actual_reader.putbackLine(actual_line)
                --actual_reader.line_number

                while target_is_space:
                    target_line = target_reader.readLine()
                    target_reader.line_number += 1
                    if target_line is None or re.match(r'^\s*<print piece=" " />$|^$', target_line).group():
                        break

                target_reader.putbackLine(target_line)
                --target_reader.line_number

            finally:
                ++actual_reader.line_number
                ++target_reader.line_number

        actual_reader.close()
        target_reader.close()

        return ok

    def get_slaspec_files(self):
        all_slaspec_files = Application.findFilesByExtensionInApplication(".slaspec")
        return all_slaspec_files

# printMemory();
