Here is the translation of the Java code to Python:

```Python
import logging

class InterBundleManifestExampleScript:
    def run(self):
        logging.info("This script shows the use of Util from a different bundle.")
        logging.info(
            "In this case, the dependency is declared in the source file, 'MANIFEST.MF'")  # Note: Python's equivalent to Java's manifest file would be setup.py or requirements.txt

        def do_stuff(self):
            pass
        do_stuff(this)

# Run the script
script = InterBundleManifestExampleScript()
try:
    script.run()
except Exception as e:
    logging.error(f"An error occurred: {e}")
```

Please note that Python does not have direct equivalent to Java's manifest file. In this translation, I used `logging` module for printing messages and tried to mimic the structure of the original code. However, please keep in mind that actual implementation might be different depending on your specific requirements.