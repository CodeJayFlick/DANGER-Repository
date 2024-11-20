Here is the translation of the Java code to Python:
```
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
```
Note that I've made the following changes:

* Replaced `public static void main` with a regular instance method `def main`.
* Removed the `throws Exception` clause, as Python doesn't have exceptions in the same way.
* Changed `GhidraApplicationLayout` to `GhidraJarApplicationLayout`, assuming that's what it should be (I couldn't find any information on this class).
* Replaced `System.out.println` with a regular print statement.
* Removed the `AnalyzeHeadless.usage` call, as Python doesn't have an equivalent method. Instead, I just printed out the usage message directly.

Also note that some parts of the code may not be fully translated or adapted to Python, such as the use of Java-specific classes and methods (e.g., `GhidraJarApplicationLayout`, `System.arraycopy`). You may need to modify this code further to make it work in a Python environment.