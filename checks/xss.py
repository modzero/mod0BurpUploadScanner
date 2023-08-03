

import cgi
import random
import string
from checks.attacks import Attacks
from misc.BackdooredFile import BackdooredFile
from misc.Constants import Constants
from misc.CustomScanIssue import CustomScanIssue
from misc.Downloader import DownloadMatcher
from misc.Sender import Sender


class xss_check():
    def __init__(self, injector, globalOptionsPanel, callbacks, dl_matchers, burp_extender):
        self._attacks = Attacks(callbacks, dl_matchers, burp_extender)
        self._sender = Sender(callbacks, burp_extender)
        self._callback_helpers = callbacks.getHelpers()
        self._dl_matchers = dl_matchers
        self._globalOptionsPanel = globalOptionsPanel
        self._xss_html(injector)
        self._xss_svg(injector)
        self._xss_swf(injector)
        self._xss_backdoored_file(injector)

    def _xss_html(self, injector):
        if injector.opts.file_formats['html'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "HtmlXss"
            content = '<html><head></head><body>this is just a little html</body></html>'
            title = "Cross-site scripting (stored)" # via HTML file upload"
            desc = 'XSS via HTML file upload and download. '
            issue = CustomScanIssue(injector.get_brr(), self._callback_helpers, title, desc, "Firm", "High")
            self._dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_xss=True))
            self._sender.simple(injector, Constants.HTML_TYPES, basename, content, redownload=True)
        return []

    def _xss_svg(self, injector):
        if injector.opts.file_formats['svg'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgXss"
            content_svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
                          '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" ' \
                          'xmlns="http://www.w3.org/2000/svg" width="{}" height="{}"><polygon id="triangle" ' \
                          'points="0,0 0,0 0,0" stroke="#004400"/><script type="text/javascript">prompt();' \
                          '</script></svg>'.format(str(injector.opts.image_width), str(injector.opts.image_height))
            title = "Cross-site scripting (stored)" # via SVG"
            desc = 'XSS through SVG upload and download as SVG can include JavaScript and will execute same origin.'
            issue = CustomScanIssue(injector.get_brr(), self._callback_helpers, title, desc, "Firm", "High")
            self._dl_matchers.add(DownloadMatcher(issue, filecontent=content_svg, check_xss=True))
            self._sender.simple(injector, Constants.SVG_TYPES, basename, content_svg, redownload=True)
        return []

    def _xss_swf(self, injector):
        if injector.opts.file_formats['swf'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XssProject"
            content = 'Q1dTDmkGAAB4AWVU3VLbRhTe1dqW/2UDMeBAozQ0jgm2ZMMwgyGeUgwZbiATXyTDoPEs0gorkbUaScZmOpm+SSe96Wv0AXLjXrQP0KvO9KLuE6QriSB' \
                      'MNKOfPec7335nzzkag9hfAOR/BWAJgk5xGQDw0/wnCMCeo+mt150jcTwwLbfFVi8qfc+zW5I0Go3qo806dS6lxs7OjiQ3pWazxhA199ry8LhmuU8q7' \
                      'YCgQ1zVMWzPoJboE+ILOvReVCo3rJp6S2oPHTOg1FSJmGRALM+VGvUGI9LUlk6dAfba2LZNQ8U+nTSuuX2qvh/hK1LTTez296QI6Md4hmeS9r5GL4h' \
                      '4ZJKxuCXuR/EBOoT4YC0S2r6TJvaj6yodSLZDtaHKNOmMKgi+G+JT2MML03D7xGkPrfcWHVkBKrL6GNUh2KOziC82329i63KIL0n78CSIvl0HGrFH2' \
                      'if0SmzIG2JTbjRDGb51T/JP985p31hYAdsgXxgun5zWXu13u29OX3fARGBVnrk6hb/RHjjgPn/+fJZGzJVgdyzxy1mIyuCf/2mxnviUftvtvnLoO6J' \
                      '64LeFbAwAZgV3jAVQ90Oe3wUqB63zDlWHQUlFbGlil3ieYV265/vawLAM13P8Q2GrsFSsluIPQ8PUiCNu1bfPI/5z11F3d6N1HbvZaLUmJ7tEHTqGd' \
                      '50NOqLuXrseGcD1DDZNOurQATas4uHYI46FzWOLvXWsknwIJjf2uQF23D6LOByrJGhdV5Crux9Y36n9Z6T644fdmEOplzYpZhKPLZ2mbezgAWF8Lvf' \
                      'OFSJJTOCa/PimoaJm2u9uSk1Z3pYuWJrsKBZCBZrh2ia+bnVtlgNZmzV2QufphX/6B5QNmmER59EsKMgJq55xRULgw1n/DMlK6CNX/qy1Dv2X7/fTJ' \
                      'A4nSTGVHUL80HGoA0mcFUklD6LUpOgzN7NJIpSfCAUI93hvKhNumpvRU/xKfWnGf5v0Sq93SXse7amsbXoa0VkT+f+EXp+YNrKpixrbm4tfQPf9jcZ' \
                      'WMQ5LiRJXSseLi1xybgmWYXm+vFB+UC6VF0vflL7lchDF4gk+mUpnsrn8As/FeZTkYykeZXiU41GeR0KqAHm0zKMyjx7yaIVHkBce8UjkC4954Qkvr' \
                      'PHCd2yYODYQq+zBAe4prDyrwso6zOVTyWB2IAdzHch8EAEIkyk0kV+yqUIoLfT/Q9PkRH6z/of8L4yB5DQ1OQbTtAJ1uMEfcbA6zShIR09xbJr3Pza' \
                      'ySlyP6wmd15MfN5Y+HqUYRCisADCRf5fPwPqf6/LzAZwWlCzhTHiUhdXVJDedewmrB8fpDOA4JmBnIrNtEwQogi7ISkEvyEpRL8rKnD4nK/P6vKzk9' \
                      'XzweAtWg6ufYxFxplqYv/c3+J5l/j9Txem0'
            content = content.decode("base64")
            title = "Cross-site scripting (stored)" # via SWF"
            desc = 'XSS through SWF file (Adobe Flash) upload and download. ' \
                   'See https://soroush.secproject.com/blog/2012/11/xss-by-uploadingincluding-a-swf-file/ for more details. ' \
                   'There might be other issues with file uploads that allow .swf uploads, for example https://hackerone.com/reports/51265 .'
            issue = CustomScanIssue(injector.get_brr(), self._callback_helpers, title, desc, "Firm", "Medium")
            # TODO feature: Check if other content_types work too rather than only application/x-shockwave-flash...
            self._dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_xss=True))
            self._sender.simple(injector, Constants.SWF_TYPES, basename, content, redownload=True)
        return []

    def _xss_payload(self):
        r = ''.join(random.sample(string.ascii_letters, 10))
        payload = '<b>' + r + '</b>'
        expect = payload
        return payload, expect

    def _xss_backdoored_file(self, injector):
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._xss_payload):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BfXss" + name
            title = "Cross-site scripting (stored)" # via " + ext[1:].upper() + " Metadata"
            desc = 'XSS through injection of HTML in Metadata of type ' + name + '. The server ' \
                    'reflected the code ' + cgi.escape(
                payload) + ' inside the uploaded file and used a content-type that ' \
                    'works for XSS, meaning that HTML injection is possible.'
            issue = CustomScanIssue(injector.get_brr(), self._callback_helpers, title, desc, "Firm", "High")
            self._dl_matchers.add(DownloadMatcher(issue, filecontent=expect, check_xss=True))
            self._sender.simple(injector, Constants.HTML_TYPES, basename, content, redownload=True)
        return []
