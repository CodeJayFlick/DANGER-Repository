import logging

class UsesJarByVersionExampleScript:
    def run(self):
        print("This script shows the use of JarUtil.")
        print("  a class defined in an external jar bundle.")
        print("There are two versions of the jar in the bundle examples directory,")
        print(" since '@importpackage' declaration doesn't specify a version, either")
        print(" of the jar bundles, scripts_jar1.jar or scripts_jar2.jar works.")
        print(" Try enabling only one of the 'scripts_*' bundles and rerun this script.")

        logging.info(f"Currently using JarUtil version {JarUtil.getVersion()}")

# Usage
script = UsesJarByVersionExampleScript()
script.run()
