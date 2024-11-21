import os
import logging
from urllib.request import urlopen, Request
from io import BytesIO
from gzip import GzipFile
from shutil import copyfileobj
from pathlib import Path

logging.basicConfig(level=logging.DEBUG)

LIB_NAME = "jnitensorflow"
VERSION_PATTERN = r"(\d+\.\d+\.\d+(-[a-z]+)?)(-SNAPSHOT)?(-\d+)?"

class LibUtils:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def load_library():
        lib_name = get_lib_name()
        if lib_name is not None:
            self.logger.debug("Loading TensorFlow library from: {}", lib_name)
            path = Path(lib_name).parent.absolute()
            os.environ["org.bytedeco.javacpp.platform.preloadpath"] = str(path)
            # workaround javacpp physical memory check bug
            os.environ["org.bytedeco.javacpp.maxBytes"] = "0"
            os.environ["org.bytedeco.javacpp.maxPhysicalBytes"] = "0"

    @staticmethod
    def get_lib_name():
        lib_name = find_override_library()
        if lib_name is None:
            lib_name = find_library_in_classpath()
            if lib_name is None:
                lib_name = LIB_NAME
        return lib_name

    @staticmethod
    def find_override_library():
        lib_path = os.environ.get("TENSORFLOW_LIBRARY_PATH")
        if lib_path is not None:
            lib_name = find_library_in_path(lib_path)
            if lib_name is not None:
                return lib_name

        lib_path = os.environ.get("java.library.path")
        if lib_path is not None:
            return find_library_in_path(lib_path)

        return None

    @staticmethod
    def find_library_in_classpath():
        urls = []
        try:
            for url in urlopen(Request("native/lib/tensorflow.properties")):
                urls.append(url)
        except Exception as e:
            self.logger.warn("", e)
            return None

        if not urls:
            preferred_version = None
            with BytesIO() as f:
                f.write(urlopen(Request("/tensorflow-engine.properties")).read())
                prop = Properties()
                prop.load(f)
                preferred_version = prop.get("tensorflow_version")

            platform = Platform.from_system(preferred_version)
            return download_tensorflow(platform)

        platform = Platform.from_url(urls[0])
        if platform.is_placeholder():
            placeholder = platform
        else:
            matching = None
            for url in urls:
                p = Platform.from_url(url)
                if p.matches(Platform.from_system()):
                    matching = p
                    break

            if matching is not None:
                return load_library_from_classpath(matching)

            if placeholder is not None:
                return download_tensorflow(placeholder)

        self.logger.error("Failed to read Tensorflow native library jar properties")
        raise Exception("Your Tensorflow native library jar does not match your operating system. Make sure that the Maven Dependency Classifier matches your system type.")

    @staticmethod
    def load_library_from_classpath(platform):
        tmp = None
        try:
            lib_name = os.environ["org.bytedeco.javacpp.mapLibraryName"].format(LIB_NAME)
            cache_folder = Path("tensorflow")
            version = platform.get_version()
            flavor = platform.get_flavor()
            classifier = platform.get_classifier()

            dir_path = cache_folder / (version + "-" + flavor + "-" + classifier)
            logger.debug("Using cache dir: {}", str(dir_path))

            path = dir_path / lib_name
            if os.path.exists(path):
                return str(path)

            os.makedirs(cache_folder, exist_ok=True)
            tmp = Path(tempfile.mkdtemp(prefix="tmp-", dir=str(cache_folder)))
            for file in platform.get_libraries():
                lib_path = "/native/lib/" + file
                logger.info("Extracting {} to cache ...", lib_path)
                with urlopen(Request(lib_path)) as f:
                    if not os.path.exists(path):
                        copyfileobj(f, open(str(path), "wb"))
        except Exception as e:
            self.logger.error("Failed to extract Tensorflow native library")
            raise

        finally:
            if tmp is not None:
                shutil.rmtree(tmp)

    @staticmethod
    def find_library_in_path(lib_path):
        paths = lib_path.split(os.path.sep)
        map_lib_name = os.environ["org.bytedeco.javacpp.mapLibraryName"].format(LIB_NAME)

        for path in paths:
            p = Path(path)
            if not p.exists():
                continue

            if p.is_file() and p.name.endswith(map_lib_name):
                return str(p.absolute())

            file_path = Path(paths[0], map_lib_name)
            if os.path.exists(file_path) and file_path.is_file():
                return str(file_path)

        return None

    @staticmethod
    def download_tensorflow(platform):
        version = platform.get_version()
        os_prefix = platform.get_os_prefix()
        flavor = platform.get_flavor()
        classifier = platform.get_classifier()

        lib_name = os.environ["org.bytedeco.javacpp.mapLibraryName"].format(LIB_NAME)
        cache_folder = Path("tensorflow")
        logger.debug("Using cache dir: {}", str(cache_folder))

        path = cache_folder / (version + "-" + flavor + "-" + classifier) / lib_name
        if os.path.exists(path):
            return str(path)

        matcher = re.compile(VERSION_PATTERN).match(version)
        if not matcher:
            raise Exception(f"Unexpected version: {version}")

        link = f"https://publish.djl.ai/tensorflow-{matcher.group(1)}"
        tmp = None

        try:
            with urlopen(Request(link + "/files.txt")) as f:
                lines = [line.decode("utf-8") for line in f.readlines()]

            found = False
            for line in lines:
                if line.startswith(os_prefix + "/" + flavor + "/"):
                    found = True
                    url = Request(line.replace("+", "%2B"))
                    file_name = line.split("/")[-1].replace(".gz", "")
                    logger.info("Downloading {} ...", str(url))
                    with urlopen(url) as uf:
                        with GzipFile(fileobj=BytesIO(uf.read()), mode="rb") as gf:
                            copyfileobj(gf, open(str(path), "wb"))

            if not found and classifier != "cpu":
                flavor = "cpu"
                dir_path = cache_folder / (version + "-" + flavor + "-" + classifier)
                path = dir_path / lib_name
                logger.warn("No matching CUDA flavor for {} found: {}/sm_{}. Fallback to CPU.", os_prefix, flavor, classifier)
                return str(path)

            if not found:
                raise Exception(f"TensorFlow engine does not support this platform: {os_prefix}")

            shutil.move(str(tmp), path)
            return str(path)
        except Exception as e:
            self.logger.error("Failed to download Tensorflow native library")
            raise

    @staticmethod
    def load_library():
        lib_name = get_lib_name()
        if lib_name is not None:
            logger.debug("Loading TensorFlow library from: {}", lib_name)

def main():
    LibUtils.load_library()

if __name__ == "__main__":
    main()
