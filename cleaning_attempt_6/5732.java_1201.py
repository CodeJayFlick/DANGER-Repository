import sys
from ghidra.app.util.headless import AnalyzeHeadless

class JarRun:
    def main(self):
        if len(sys.argv) == 0:
            self.usage()
            return

        layout = GhidraJarApplicationLayout()

        if "-gui" in sys.argv[1:]:
            run_gui(layout, [arg for arg in sys.argv[1:] if arg != "-gui"])
        else:
            AnalyzeHeadless().launch(layout, sys.argv)

    def remove_args(self, args, removal_count):
        new_args = []
        for i in range(max(0, len(args) - removal_count)):
            new_args.append(args[i + removal_count])
        return new_args

    def usage(self):
        print("Ghidra GUI Usage: java -jar <ghidra.jar> -gui [<ghidra-project-file>]")

if __name__ == "__main__":
    JarRun().main()
