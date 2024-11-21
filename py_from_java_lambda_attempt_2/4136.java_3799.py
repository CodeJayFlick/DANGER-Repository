Here is the translation of the Java code into Python:

```Python
import java.awt as awt
from typing import List

class CodeUnitPrintable:
    def __init__(self,
                 lm: 'LayoutModel',
                 startIndex: int = None,
                 endIndex: int = None,
                 scaleAmount: float = 1.0,
                 monitor: 'TaskMonitor' = None,
                 pod: 'PrintOptionsDialog' = None,
                 book: 'Book' = None,
                 job: 'PrinterJob' = None,
                 startDate: awt.Date = None):
        self.lm = lm
        self.startIndex = startIndex
        self.endIndex = endIndex
        self.scaleAmount = scaleAmount
        self.monitor = monitor
        self.pod = pod
        self.book = book
        self.job = job
        self.startDate = startDate

    def print(self, graphics: awt.Graphics,
              pageFormat: 'PageFormat',
              pageIndex: int) -> int:
        g2d = GraphicsUtils.get_graphics_2d(graphics)
        g2d.set_color(awt.Color.BLACK)

        monitor.set_message(f"Printing Page {pageIndex + 1}")
        if self.monitor.is_cancelled():
            job.cancel()
            return awt.PrinterException.NO_SUCH_PAGE

        rect = awt.Rectangle(
            int(pageFormat.get_imageable_width()),
            int(pageFormat.get_imageable_height())
        )
        if scaleAmount < 1.0:
            rect = awt.Rectangle(
                int(pageFormat.get_imageable_width() / scaleAmount),
                int(pageFormat.get_imageable_height() / scaleAmount)
            )

        ls = EmptyLayoutBackgroundColorManager(awt.Color.WHITE)

        g2d.translate(int(pageFormat.get_imageable_x()),
                      int(pageFormat.get_imageable_y()))

        # Print header/footer information
        original_font = g2d.get_font()
        g2d.set_font(pod.get_header_font())
        metrics = g2d.get_font_metrics(pod.get_header_font())
        bottom_pos = float(pageFormat.get_imageable_height()) - metrics.get_max_descent()

        if pod.get_print_title():
            GraphicsUtils.draw_string(None, g2d, job.get_job_name(), 0,
                                       int(metrics.get_max_ascent()))

        if pod.get_print_date():
            date_time = DateUtils.format_date_timestamp(startDate)
            GraphicsUtils.draw_string(None, g2d, date_time, 0, bottom_pos)

        if pod.get_print_page_num():
            page_string = f"Page {pageIndex + 1} of {book.get_number_of_pages()}"
            GraphicsUtils.draw_string(None, g2d, page_string,
                                       int(pageFormat.get_imageable_width()) - metrics.string_width(page_string),
                                       bottom_pos)
        g2d.set_font(original_font)

        if pod.show_header():
            g2d.translate(0, pod.get_header_height())

        if scaleAmount < 1.0:
            g2d.transform(awt.geomAffineTransform.scale(scaleAmount, scale_amount))

        if layouts is not None:
            # If no layouts, ignore blank page
            if len(layouts) == 0:
                return awt.PrinterException.NO_SUCH_PAGE

            for i in range(len(layouts)):
                layout = layouts[i]
                try:
                    if layout is not None:
                        layout.paint(None, g2d, PAINT_CONTEXT, rect, ls, None)
                        g2d.translate(0, layout.get_height())
                except Exception as e:
                    Msg.error(self, f"Unexpected Exception: {e.message}", e)

                monitor.set_progress((i + 1) * 100 / len(layouts))

        else:
            for i in range(startIndex, endIndex + 1):
                layout = lm.get_layout(BigInteger.valueOf(i))
                try:
                    if layout is not None:
                        layout.paint(None, g2d, PAINT_CONTEXT, rect, ls, None)
                        g2d.translate(0, layout.get_height())
                except Exception as e:
                    Msg.error(self, f"Unexpected Exception: {e.message}", e)

                monitor.set_progress((i - startIndex + 1) * 100 / (endIndex - startIndex + 1))

        return awt.PrinterException.PAGE_EXISTS
```

Please note that this is a direct translation of the Java code into Python.