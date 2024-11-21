import boto3
from botocore.exceptions import ContainerInitializationError
from enum import Enum
from typing import TypeVar, Generic

T = TypeVar('T')

class RequestStreamHandler(Generic[T]):
    def __init__(self):
        self.handler = None
        try:
            self.handler = get_aws_proxy_handler()
            define_resources()
            await_initialization()

            # we use the on_startup method of the handler to register our custom filter
            self.handler.on_startup(lambda servlet_context: 
                add_filter(servlet_context, "CognitoIdentityFilter", CognitoIdentityFilter))
        except ContainerInitializationError as e:
            print_stacktrace(e)
            raise RuntimeError("Could not initialize Spark container", e)

    def handle_request(self, input_stream, output_stream, context):
        self.handler.proxy_stream(input_stream, output_stream, context)


def get_aws_proxy_handler():
    # implement this function to return the AWS proxy handler
    pass


def define_resources():
    # implement this function to define resources
    pass


def await_initialization():
    # implement this function to wait for initialization
    pass


def add_filter(servlet_context, filter_name, filter_class):
    registration = servlet_context.add_filter(filter_name, filter_class)
    registration.add_mapping_for_url_patterns(Enum(set([DispatcherType.REQUEST])), False, "/*")


def print_stacktrace(e):
    e.print_stacktrace()
