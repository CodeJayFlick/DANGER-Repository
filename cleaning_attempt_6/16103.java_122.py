import os
import logging
from urllib.request import urlopen, Request
from io import BytesIO
from gzip import GzipFile
from tarfile import TarFile
from shutil import move, rmtree
from tempfile import mkdtemp

class LibUtils:
    _logger = logging.getLogger(__name__)

    LIB_NAME = "tensorflowlite_jni"
    VERSION_PATTERN = re.compile(r"(\d+\.\d+\.\d+(-[a-z]+)?)(-SNAPSHOT)?(-\d+)?")

    def __init__(self):
        pass

    @staticmethod
    def load_library():
        lib_name = LibUtils.find_library_in_classpath()
        if not lib_name:
            return  # NOPMD
        _logger.debug("Loading TFLite native library from: %s", lib_name)
        os.load(lib_name)  # NOPMD

    @staticmethod
    def find_library_in_classpath():
        try:
            urls = [urllib.request.urlopen(url) for url in urllib.request.urlopen('native/lib/tflite.properties').read().decode().splitlines()]
        except IOError as e:
            _logger.warn("", e)
            return None

        if not urls:  # No native jars
            _logger.debug("tflite.properties not found in class path.")
            return None

        system_platform = Platform.from_system()
        matching = placeholder = None
        for url in urls:
            platform = Platform.from_url(url)
            if platform.is_placeholder():
                placeholder = platform
            elif platform.matches(system_platform):
                matching = platform
                break

        if matching:
            return LibUtils.load_library_from_classpath(matching)

        if placeholder:
            try:
                return LibUtils.download_tflite(placeholder)
            except IOError as e:
                raise ValueError("Failed to download TFLite native library", e)

        _logger.error(
            "Your TFLite native library jar does not match your operating system. Make sure that the Maven Dependency Classifier matches your system type.")
        return None

    @staticmethod
    def load_library_from_classpath(platform):
        tmp = mkdtemp()
        try:
            lib_name = os.map_library_name(LibUtils.LIB_NAME)
            cache_folder = Utils.get_engine_cache_dir("tflite")
            version = platform.version
            flavor = platform.flavor
            classifier = platform.classifier
            dir_path = os.path.join(cache_folder, f"{version}-{flavor}-{classifier}")
            _logger.debug(f"Using cache dir: {dir_path}")

            path = os.path.join(dir_path, lib_name)
            if os.path.exists(path):
                return path

            os.makedirs(cache_folder)

            for file in platform.libraries:
                lib_path = "/native/lib/" + file
                _logger.info("Extracting %s to cache ...", lib_path)
                try:
                    with urllib.request.urlopen(lib_path) as is, BytesIO() as bo:
                        if not is:  # TFLite library not found
                            raise ValueError(f"TFLite library not found: {lib_path}")
                        os.copyfileobj(is, bo)

                    os.makedirs(dir_path)
                    with TarFile(bo) as tf:
                        for member in tf.getmembers():
                            file_name = os.path.join(dir_path, member.name)
                            _logger.info("Extracting %s to cache ...", lib_name)
                            try:
                                with open(file_name, "wb") as fo:
                                    tf.extractfile(member).copyto(fo)
                            except IOError as e:
                                raise ValueError(f"Failed to extract TFLite native library: {e}")

                    os.rename(tmp, dir_path)

                finally:
                    rmtree(tmp)

            return path

        except IOError as e:
            _logger.error("Failed to extract TFLite native library", e)
            if tmp:
                rmtree(tmp)
            raise ValueError(f"Failed to download TFLite native library: {e}")

    @staticmethod
    def download_tflite(platform):
        version = platform.version
        flavor = platform.flavor
        classifier = platform.classifier

        lib_name = os.map_library_name(LibUtils.LIB_NAME)

        cache_dir = Utils.get_engine_cache_dir("tflite")
        _logger.debug(f"Using cache dir: {cache_dir}")

        path = os.path.join(cache_dir, f"{version}-{flavor}-{classifier}", lib_name)
        if os.path.exists(path):
            return path

        matcher = LibUtils.VERSION_PATTERN.match(version)

        link = "https://publish.djl.ai/tflite-" + matcher.group(1)

        tmp = mkdtemp()
        try:
            with urlopen(Request(link, headers={'User-Agent': 'Mozilla/5.0'})) as is, BytesIO() as bo:
                if not is:  # No matching cuda flavor for os found
                    _logger.warn("No matching cuda flavor for %s found", platform.os_prefix)
                    flavor = "cpu"

            with GzipFile(fileobj=bo) as gz:
                lines = [line.decode().strip() for line in gz.readlines()]

            if not any(line.startswith(f"{flavor}/{classifier}/") for line in lines):
                _logger.warn("No matching cuda flavor for %s found", platform.os_prefix)
                flavor = "cpu"

            os.makedirs(cache_dir)

            for line in lines:
                if line.startswith(f"{flavor}/{classifier}/"):
                    file_name = line.split('/')[-1].strip('.gz')
                    with urllib.request.urlopen(link + '/' + line) as is, BytesIO() as bo:
                        _logger.info("Downloading %s ...", link)
                        os.copyfileobj(is, bo)

                    move(tmp, path)

            return path

        finally:
            if tmp:
                rmtree(tmp)
