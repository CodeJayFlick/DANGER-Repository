import os
import sys
from urllib.request import urlretrieve
from getpass import getpass

class MavenWrapperDownloader:
    WRAPPER_VERSION = "0.5.6"
    DEFAULT_DOWNLOAD_URL = f"https://repo.maven.apache.org/maven2/io/takari/maven-wrapper/{WRAPPER_VERSION}/maven-wrapper-{WRAPPER_VERSION}.jar"

    MAVEN_WRAPPER_PROPERTIES_PATH = ".mvn/wrapper/maven-wrapper.properties"
    MAVEN_WRAPPER_JAR_PATH = ".mvn/wrapper/maven-wrapper.jar"
    PROPERTY_NAME_WRAPPER_URL = "wrapperUrl"

    def __init__(self):
        pass

    @staticmethod
    def main(args):
        print("- Downloader started")
        base_directory = os.path.abspath(args[0])
        print(f"- Using base directory: {base_directory}")

        maven_wrapper_property_file_path = os.path.join(base_directory, MavenWrapperDownloader.MAVEN_WRAPPER_PROPERTIES_PATH)
        url = MavenWrapperDownloader.DEFAULT_DOWNLOAD_URL
        if os.path.exists(maven_wrapper_property_file_path):
            try:
                with open(maven_wrapper_property_file_path) as f:
                    properties = dict(line.strip().split("=") for line in f.readlines())
                url = properties.get(MavenWrapperDownloader.PROPERTY_NAME_WRAPPER_URL, MavenWrapperDownloader.DEFAULT_DOWNLOAD_URL)
            except Exception as e:
                print(f"- ERROR loading '{MavenWrapperDownloader.MAVEN_WRAPPER_PROPERTIES_PATH}'")
        print(f"- Downloading from: {url}")

        output_file_path = os.path.join(base_directory, MavenWrapperDownloader.MAVEN_WRAPPER_JAR_PATH)
        if not os.path.exists(os.path.dirname(output_file_path)):
            try:
                os.makedirs(os.path.dirname(output_file_path))
            except Exception as e:
                print(f"- ERROR creating output directory '{os.path.dirname(output_file_path)}'")
        print(f"- Downloading to: {output_file_path}")

        try:
            urlretrieve(url, output_file_path)
            print("Done")
            sys.exit(0)
        except Exception as e:
            print("- Error downloading")
            e.__dict__.get('message', str(e))
            sys.exit(1)

    @staticmethod
    def download_file_from_url(url_string, destination):
        if 'MVNW_USERNAME' in os.environ and 'MVNW_PASSWORD' in os.environ:
            username = os.environ['MVNW_USERNAME']
            password = getpass().encode()
            auth_handler = urllib.request.HTTPBasicAuthHandler()
            auth_handler.add_password(None, None, username, password)
            opener = urllib.request.build_opener(auth_handler)
            urllib.request.install_open'er(opener)

        website_url = urllib.request.urlopen(url_string)
        with open(destination, 'wb') as f:
            f.write(website_url.read())
        website_url.close()

if __name__ == "__main__":
    MavenWrapperDownloader.main(sys.argv[1:])
