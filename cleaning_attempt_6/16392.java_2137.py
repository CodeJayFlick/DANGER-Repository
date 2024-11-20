import os
import urllib.request
from urllib.parse import urlparse
from io import BytesIO

WRAPPER_VERSION = "0.5.5"
DEFAULT_DOWNLOAD_URL = f"https://repo.maven.apache.org/maven2/io/takari/maven-wrapper/{WRAPPER_VERSION}/maven-wrapper-{WRAPPER_VERSION}.jar"

MAVEN_WRAPPER_PROPERTIES_PATH = ".mvn/wrapper/maven-wrapper.properties"
MAVEN_WRAPPER_JAR_PATH = ".mvn/wrapper/maven-wrapper.jar"
PROPERTY_NAME_WRAPPER_URL = "wrapperUrl"

def main(args):
    print("- Downloader started")
    base_directory = os.path.abspath(args[0])
    print(f"- Using base directory: {base_directory}")

    maven_wrapper_property_file_path = os.path.join(base_directory, MAVEN_WRAPPER_PROPERTIES_PATH)
    url = DEFAULT_DOWNLOAD_URL
    if os.path.exists(maven_wrapper_property_file_path):
        try:
            with open(maven_wrapper_property_file_path, "r") as f:
                properties = {}
                for line in f.readlines():
                    key, value = line.strip().split("=")
                    properties[key] = value
                url = properties.get(PROPERTY_NAME_WRAPPER_URL, url)
        except Exception as e:
            print(f"- ERROR loading '{MAVEN_WRAPPER_PROPERTIES_PATH}'")
    print(f"- Downloading from: {url}")

    output_file_path = os.path.join(base_directory, MAVEN_WRAPPER_JAR_PATH)
    if not os.path.exists(os.path.dirname(output_file_path)):
        try:
            os.makedirs(os.path.dirname(output_file_path))
        except Exception as e:
            print(f"- ERROR creating output directory '{os.path.dirname(output_file_path)}'")
    print(f"- Downloading to: {output_file_path}")

    try:
        download_file_from_url(url, output_file_path)
        print("Done")
        exit(0)
    except Exception as e:
        print("- Error downloading")
        e.print_stacktrace()
        exit(1)

def download_file_from_url(url, destination):
    if "MVNW_USERNAME" in os.environ and "MVNW_PASSWORD" in os.environ:
        username = os.environ["MVNW_USERNAME"]
        password = os.environ["MVNW_PASSWORD"].encode("utf-8")
        auth_handler = urllib.request.HTTPBasicAuthHandler()
        auth_handler.add_password(None, None, username, password)
        opener = urllib.request.build_opener(auth_handler)
        urllib.request.install_opener(opener)

    with urllib.request.urlopen(url) as response:
        with BytesIO() as output_file:
            while True:
                chunk = response.read(1024)
                if not chunk:
                    break
                output_file.write(chunk)
            destination_path = os.path.join(os.getcwd(), destination)
            with open(destination_path, "wb") as f:
                f.write(output_file.getvalue())

if __name__ == "__main__":
    main(sys.argv[1:])
