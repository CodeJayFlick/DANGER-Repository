import os
import urllib.request
from urllib.error import URLError, HTTPError
from io import BytesIO

class GradleWrapperDownloader:
    DEFAULT_DOWNLOAD_URL = "https://raw.githubusercontent.com/gradle/gradle/master/gradle/wrapper/gradle-wrapper.jar"
    GRADLE_WRAPPER_JAR_PATH = "gradle/wrapper/gradle-wrapper.jar"

    def __init__(self, base_directory):
        self.base_directory = os.path.abspath(base_directory)

    def download(self):
        print("- Downloader started")
        print(f"- Using base directory: {self.base_directory}")

        url = self.DEFAULT_DOWNLOAD_URL
        print(f"- Downloading from: {url}")

        output_file_path = os.path.join(self.base_directory, self.GRADLE_WRAPPER_JAR_PATH)
        if not os.path.exists(os.path.dirname(output_file_path)):
            try:
                os.makedirs(os.path.dirname(output_file_path))
            except Exception as e:
                print(f"- ERROR creating output directory: {os.path.dirname(output_file_path)}")
                return

        print(f"- Downloading to: {output_file_path}")
        try:
            response = urllib.request.urlopen(url)
            with open(output_file_path, 'wb') as f:
                while True:
                    chunk = response.read(1024)
                    if not chunk:
                        break
                    f.write(chunk)

            print("Done")
            return

        except (URLError, HTTPError) as e:
            print("- Error downloading")
            print(str(e))
            return


if __name__ == "__main__":
    base_directory = sys.argv[1]
    downloader = GradleWrapperDownloader(base_directory)
    downloader.download()
