Here is the translation of the Java code to Python:

```Python
import os
import urllib.request
from urllib.parse import urlparse
from io import BytesIO
from shutil import copyfileobj

class MavenWrapperDownloader:
    WRAPPER_VERSION = "0.5.6"
    DEFAULT_DOWNLOAD_URL = f"https://repo.maven.apache.org/maven2/io/takari/maven-wrapper/{WRAPPER_VERSION}/maven-wrapper-{WRAPPER_VERSION}.jar"

    MAVEN_WRAPPER_PROPERTIES_PATH = ".mvn/wrapper/maven-wrapper.properties"
    MAVEN_WRAPPER_JAR_PATH = ".mvn/wrapper/maven-wrapper.jar"
    PROPERTY_NAME_WRAPPER_URL = "wrapperUrl"

    def __init__(self, base_directory):
        self.base_directory = os.path.abspath(base_directory)

    def download(self):
        print("- Downloader started")
        print(f"- Using base directory: {self.base_directory}")

        maven_wrapper_property_file_path = os.path.join(self.base_directory, MavenWrapperDownloader.MAVEN_WRAPPER_PROPERTIES_PATH)
        url = MavenWrapperDownloader.DEFAULT_DOWNLOAD_URL
        if os.path.exists(maven_wrapper_property_file_path):
            try:
                with open(maven_wrapper_property_file_path, 'r') as file:
                    properties = dict(line.strip().split('=') for line in file.readlines())
                    url = properties.get(MavenWrapperDownloader.PROPERTY_NAME_WRAPPER_URL, MavenWrapperDownloader.DEFAULT_DOWNLOAD_URL)
            except Exception as e:
                print(f"- ERROR loading '{MavenWrapperDownloader.MAVEN_WRAPPER_PROPERTIES_PATH}'")
        print(f"- Downloading from: {url}")

        output_file_path = os.path.join(self.base_directory, MavenWrapperDownloader.MAVEN_WRAPPER_JAR_PATH)
        if not os.path.exists(os.path.dirname(output_file_path)):
            try:
                os.makedirs(os.path.dirname(output_file_path))
            except Exception as e:
                print(f"- ERROR creating output directory '{os.path.dirname(output_file_path)}'")
        print(f"- Downloading to: {output_file_path}")

        try:
            with urllib.request.urlopen(url) as response, open(output_file_path, 'wb') as file:
                copyfileobj(response, file)
            print("Done")
            exit(0)
        except Exception as e:
            print("- Error downloading")
            e.__dict__.get('response', None).read().decode()
            exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_directory>")
        sys.exit(-1)
    downloader = MavenWrapperDownloader(sys.argv[1])
    downloader.download()

```

Please note that Python does not have direct equivalent of Java's `File` class. Instead, it uses the built-in `os.path.join()` function to join path components together and `open()` function with mode 'r' or 'w' for reading and writing files respectively.