import socket
from urllib.parse import urlparse, urlunparse
from abc import ABCMeta, abstractmethod


class GhidraProtocolHandler(metaclass=ABCMeta):
    @abstractmethod
    def is_extension_supported(self, extension_name: str) -> bool:
        pass

    @abstractmethod
    def get_connection(self, url: str) -> socket.socket:
        pass


class Handler:
    MY_PARENT_PACKAGE = "ghidra.framework.protocol"
    PROTOCOL_HANDLER_PKGS_PROPERTY = "java.protocol.handler.pkgs"

    @staticmethod
    def register_handler():
        pkgs = System.getProperty("java.protocol.handler.pkgs")
        if pkgs is not None:
            if pkgs.find(Handler.MY_PARENT_PACKAGE) >= 0:
                return  # avoid multiple registrations

            pkgs += "|" + Handler.MY_PARENT_PACKAGE
        else:
            pkgs = Handler.MY_PARENT_PACKAGE

        System.setProperty(Handler.PROTOCOL_HANDLER_PKGS_PROPERTY, pkgs)


    @staticmethod
    def is_supported_url(url: str) -> bool:
        if not urlparse(url).scheme == "ghidra":
            return False

        if urlparse(url).authority is None:
            # assume standard ghidra URL (ghidra://...)
            return True

        try:
            protocol_handler = Handler.get_protocol_extension_handler(url)
            return True
        except Exception as e:
            return False


    @staticmethod
    def get_protocol_extension_handler(url: str) -> GhidraProtocolHandler:
        path = urlparse(url).path
        index = path.find("://")
        if index <= 0:
            raise MalformedURLException(f"invalid ghidra URL: {url}")

        extension_name = path[:index]
        protocol_handler = Handler.find_ghidra_protocol_handler(extension_name)
        if protocol_handler is None:
            raise NotFoundException(
                f"ghidra protocol extension handler ({extension_name}) not found"
            )

        return protocol_handler


    @staticmethod
    def find_ghidra_protocol_handler(extension_name: str) -> GhidraProtocolHandler:
        if Handler.protocol_handlers is None:
            Handler.load_ghidra_protocol_handlers()

        for handler in Handler.protocol_handlers:
            if handler.is_extension_supported(extension_name):
                return handler

        return None


    @staticmethod
    def load_ghidra_protocol_handlers():
        global protocol_handlers
        protocol_handlers = []
        classes = ClassSearcher.get_classes(GhidraProtocolHandler)
        for c in classes:
            try:
                protocol_handlers.append(c.new_instance())
            except Exception as e:
                print(f"Failed to instantiate ghidra protocol extension handler: {c.name}")


    def open_connection(self, url):
        if not urlparse(url).scheme == "ghidra":
            raise ValueError("unsupported URL protocol")

        # Need to check for protocol extension if URL is of form ghidra:<extension-url>
        # Example:  ghidra:http://host/repo/folder/filename
        if urlparse(url).authority is None and not url.startswith("/"):
            try:
                protocol_handler = Handler.get_protocol_extension_handler(url)
                return GhidraURLConnection(url, protocol_handler)
            except Exception as e:
                raise IOError("unsupported ghidra URL", e)

        return GhidraURLConnection(url)


class MalformedURLException(Exception):
    pass


class NotFoundException(Exception):
    pass
