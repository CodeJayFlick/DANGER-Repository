import logging
from datetime import datetime
from io import StringIO
from urllib.request import urlopen
from bs4 import BeautifulSoup

class MetricsPage:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.mr = None  # MetricRegistry equivalent in python, not implemented here for simplicity.

    def render(self):
        html = ""
        try:
            url = "iotdb/ui/static/index.html"  # URL to the HTML file
            response = urlopen(url)
            soup = BeautifulSoup(response.read(), 'html.parser')
            html += str(soup)

        except Exception as e:
            self.logger.error("Response page failed", e)

        return html

    def sql_row(self):
        table = ""
        for i in range(len(sql_arguments)):
            sql_argument = sql_arguments[i]
            resp = sql_argument.get_ts_execute_statement_resp()
            err_msg = resp.status.message
            status_code = resp.status.code
            if status_code == 200:
                status = "FINISHED"
            elif status_code == 201:
                status = "EXECUTING"
            elif status_code == 202:
                status = "INVALID_HANDLE"
            else:
                status = "FAILED"

            table += """
<tr>
    <td>{}</td>
    <td>{} {}</td>
    <td>{} {}</td>
    <td>{:.0f} ms</td>
    <td class="sql">{}</td>
    <td>{}</td>
    <td>{}
        <span class="expand-details" onclick="this.parentNode.querySelector('.stacktrace-details').classList.toggle('collapsed')">+ details</span>
    </td>
    <div class="stacktrace-details collapsed">
        <pre>
            Physical Plan: {}
            OperatorType: {}
            Path: {}
        </pre>
    </div>
</tr>
""".format(
                resp.operation_type,
                datetime.fromtimestamp(sql_argument.get_start_time()).strftime("%Y/%m/%d %H:%M:%S"),
                datetime.from_timestamp(sql_argument.get_end_time()).strftime("%Y/%m/%d %H:%M:%S"),
                int((sql_argument.get_end_time() - sql_argument.get_start_time()) * 1000),
                sql_argument.statement,
                status,
                err_msg if err_msg else "Parsed Physical Plan",
                resp.operation_type,
                sql_argument.plan.class_name,
                sql_argument.plan.operator_type,
                ", ".join(sql_argument.plan.paths)
            )

        return table

# usage
metrics_page = MetricsPage()
html = metrics_page.render()
print(html)

sql_row_html = metrics_page.sql_row()
print(sql_row_html)
