from datetime import datetime
import logging

class ApacheCombinedServletLogFormatter:
    def __init__(self):
        self.date_format = "%Y/%m/%d %H:%M:%S"

    @staticmethod
    def format(servlet_request, servlet_response, ctx=None):
        log_line_builder = ""

        #  %h
        remote_addr = servlet_request.environ.get("REMOTE_ADDR")
        if not remote_addr:
            remote_addr = "-"
        log_line_builder += f"{remote_addr} "

        #  %l
        user_principal_name = servlet_request.user.name if servlet_request.user else "-"
        log_line_builder += f"{user_principal_name} "
        identity_user_arn = servlet_request.get("AWS_REQUEST_CONTEXT_IDENTITY_USER_ARN")
        if not identity_user_arn:
            identity_user_arn = "-"
        log_line_builder += f"{identity_user_arn} "

        #  %u
        user_principal_name = servlet_request.user.name if servlet_request.user else "-"
        log_line_builder += f"{user_principal_name} "

        #  %t
        time_epoch = int(datetime.now().timestamp())
        request_time_epoch = servlet_request.get("AWS_REQUEST_CONTEXT_TIME_EPOCH")
        if request_time_epoch:
            time_epoch = int(request_time_epoch) / 1000
        log_line_builder += datetime.utcfromtimestamp(time_epoch).strftime(self.date_format)
        log_line_builder += " "

        #  %r
        method = servlet_request.method.upper()
        uri = servlet_request.uri
        protocol = servlet_request.environ.get("SERVER_PROTOCOL")
        log_line_builder += f"\"{method} {uri} {protocol}\" "

        #  %>s
        status_code = str(servlet_response.status)
        log_line_builder += f"{status_code} "

        #  %b
        response_body_length = len(servlet_response.body) if servlet_response.body else "-"
        log_line_builder += f"{response_body_length} "
        referer_header = servlet_request.headers.get("referer")
        user_agent_header = servlet_request.headers.get("user-agent")

        log_line_builder += f\"{referer_header}\" \""
        log_line_builder += f\"{user_agent_header}\" \"

        return log_line_builder.strip()
