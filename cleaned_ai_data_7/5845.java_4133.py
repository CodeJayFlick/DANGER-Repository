import os
import subprocess
from urllib.parse import urlparse

class BrowserLoader:
    def __init__(self):
        pass

    @staticmethod
    def display(url, file_url=None, service_provider=None):
        if url is None:
            return
        
        # open the browser in a new thread because the call may block
        try:
            if service_provider is not None:
                BrowserLoader.display_browser(url, file_url, service_provider)
            else:
                BrowserLoader.display_browser_for_external_url(url)
        except Exception as e:
            print(f"Error loading browser for URL: {url}, error: {str(e)}")

    @staticmethod
    def display_from_browser_runner(url, file_url, service_provider):
        try:
            if service_provider is None:
                BrowserLoader.display_browser_for_external_url(url)
            else:
                BrowserLoader.display_browser(url, file_url, service_provider)
        except Exception as e:
            print(f"Error loading browser for URL: {url}, error: {str(e)}")

    @staticmethod
    def display_browser_for_external_url(url):
        arguments = BrowserLoader.generate_command_arguments(url, None, ManualViewerCommandWrappedOption.get_default_option())
        process = subprocess.Popen(arguments, stdout=subprocess.PIPE)
        output, _ = process.communicate()
        print(output.decode('utf-8'))

    @staticmethod
    def generate_command_arguments(url, file_url=None, option=ManualViewerCommandWrappedOption()):
        argument_list = []
        if not isinstance(option.get_command_string(), str):
            raise ValueError("Invalid command string")
        argument_list.append(option.get_command_string())

        for arg in option.get_command_args():
            if not isinstance(arg, str):
                raise ValueError("Invalid command arguments")
            argument_list.append(arg)

        url_string = option.get_url_replacement_string()
        if url_string == ManualViewerCommandWrappedOption.HTTP_URL_REPLACEMENT_STRING or file_url is None:
            parsed_url = urlparse(url)
            argument_list.append(parsed_url.path + ('' if parsed_url.query else '?') + parsed_url.query)
        elif url_string == ManualViewerCommandWrappedOption.FILE_URL_REPLACEMENT_STRING:
            argument_list.append(file_url)
        else:
            argument_list.append(new File(file_url).getAbsolutePath())

        return [str(arg) for arg in argument_list]

class ImmediateOptionsChangeListener:
    def __init__(self):
        self.has_changed = False

    def options_changed(self, the_options, name, old_value, new_value):
        self.has_changed = True

    def has_changed(self):
        return self.has_changed


class BrowserRunner:
    def __init__(self, url, file_url=None, service_provider=None):
        self.url = url
        self.file_url = file_url
        self.service_provider = service_provider

    def run(self):
        display_from_browser_runner(self.url, self.file_url, self.service_provider)
