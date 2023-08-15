
from php_rce import php_rce_check
from timeout_and_dos import Timeout_and_Dos
from xss import xss_check
from xxe import xxe_checks
from helpers.FloydsHelpers import FloydsHelpers
from misc.BurpCollaborator import BurpCollaborator
from misc.Misc import StopScanException


class Checks():
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender

    def do_checks(self, injector):
        burp_colab = BurpCollaborator(self.burp_extender._callbacks)
        if not burp_colab.is_available:
            burp_colab = None
            print("Warning: No Burp Collaborator will be used")
        colab_tests = []

        # We need to make sure that the global download matchers are from now on active for the URL we scan
        url = FloydsHelpers.u2s(self.burp_extender._helpers.analyzeRequest(injector.get_brr()).getUrl().toString())
        self.burp_extender.dl_matchers.add_collection(url)

        scan_was_stopped = False

        try:
            # Sanity/debug check. Simply uploads a white picture called screenshot_white.png
            print("Doing sanity check and uploading a white png file called screenshot_white.png")
            self.burp_extender._sanity_check(injector)
            # Make sure we don't active scan again a request we are active scanning right now
            # Do this by checking for redl_enabled
            if injector.opts.modules['activescan'].isSelected() and injector.opts.redl_enabled:
                brr = injector.get_brr()
                service = brr.getHttpService()
                self.burp_extender._callbacks.doActiveScan(service.getHost(), service.getPort(), 'https' in service.getProtocol(), brr.getRequest())
            # Imagetragick - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['imagetragick'].isSelected():
                print("\nDoing ImageTragick checks")
                colab_tests.extend(self.burp_extender._imagetragick_cve_2016_3718(injector, burp_colab))
                colab_tests.extend(self.burp_extender._imagetragick_cve_2016_3714_rce(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
                self.burp_extender._imagetragick_cve_2016_3714_sleep(injector)
                self.burp_extender._bad_manners_cve_2018_16323(injector)
            # Magick (ImageMagick and GraphicsMagick) - generic, as these are exploiting features
            if injector.opts.modules['magick'].isSelected():
                print("\nDoing Image-/GraphicsMagick checks")
                colab_tests.extend(self.burp_extender._magick(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Ghostscript - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['gs'].isSelected():
                print("\nDoing Ghostscript checks")
                colab_tests.extend(self.burp_extender._ghostscript(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # LibAVFormat - generic, as the file format will always support external URLs
            if injector.opts.modules['libavformat'].isSelected():
                print("\nDoing LibAVFormat checks")
                colab_tests.extend(self.burp_extender._libavformat(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # PHP RCEs - generic, as there will always be someone who screws up PHP:
            if injector.opts.modules['php'].isSelected():
                print("\nDoing PHP code checks")
                php_rce_check(injector, self.burp_extender._globalOptionsPanel, self.burp_extender._callbacks, self.burp_extender.dl_matchers, self)
            # JSP RCEs - generic, as there will always be someone who screws up JSP:
            if injector.opts.modules['jsp'].isSelected():
                print("\nDoing JSP code checks")
                self.burp_extender._jsp_rce(injector)
            # ASP RCEs - generic, as there will always be someone who screws up ASP:
            if injector.opts.modules['asp'].isSelected():
                print("\nDoing ASP code checks")
                self.burp_extender._asp_rce(injector)
            # htaccess - generic
            # we do the htaccess upload early, because if it enables "Options +Includes ..." by uploading a .htaccess
            # then we can successfully do Server Side Includes, CGI execution, etc. in a later module...
            if injector.opts.modules['htaccess'].isSelected():
                print("\nDoing htaccess/web.config checks")
                colab_tests.extend(self.burp_extender._htaccess(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CGIs - generic
            if injector.opts.modules['cgi'].isSelected():
                print("\nDoing CGIs checks")
                colab_tests.extend(self.burp_extender._cgi(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # SSI - generic
            if injector.opts.modules['ssi'].isSelected():
                print("\nDoing SSI/ESI checks")
                colab_tests.extend(self.burp_extender._ssi(injector, burp_colab))
                colab_tests.extend(self.burp_extender._esi(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # XXE - generic
            if injector.opts.modules['xxe'].isSelected():
                print("\nDoing XXE checks")
                xxe_checks(injector, burp_colab, colab_tests, self.burp_extender, self.burp_extender._callbacks)
            # XSS - generic
            if injector.opts.modules['xss'].isSelected():
                print("\nDoing XSS checks")
                xss_check(injector, self.burp_extender._globalOptionsPanel, self.burp_extender._callbacks, self.burp_extender.dl_matchers, self)
            # eicar - generic
            if injector.opts.modules['eicar'].isSelected():
                print("\nDoing eicar checks")
                self.burp_extender._eicar(injector)
            # pdf - generic
            if injector.opts.modules['pdf'].isSelected():
                print("\nDoing pdf checks")
                colab_tests.extend(self.burp_extender._pdf(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # other ssrf - generic
            if injector.opts.modules['ssrf'].isSelected():
                print("\nDoing other SSRF checks")
                colab_tests.extend(self.burp_extender._ssrf(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CSV/spreadsheet - generic
            if injector.opts.modules['csv_spreadsheet'].isSelected():
                print("\nDoing CSV/spreadsheet checks")
                colab_tests.extend(self.burp_extender._csv_spreadsheet(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # path traversal - generic
            if injector.opts.modules['path_traversal'].isSelected():
                print("\nDoing path traversal checks")
                self.burp_extender._path_traversal_archives(injector)
            # Polyglot - generic
            if injector.opts.modules['polyglot'].isSelected():
                print("\nDoing polyglot checks")
                colab_tests.extend(self.burp_extender._polyglot(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Fingerping - generic
            if injector.opts.modules['fingerping'].isSelected():
                print("\nDoing fingerping checks")
                self.burp_extender._fingerping(injector)

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
                self.burp_extender._quirks_with_passive(injector)
                self.burp_extender._quirks_without_passive(injector)
            # Generic URL replacer module - obviously generic
            if injector.opts.modules['url_replacer'].isSelected():
                print("\nDoing generic URL replacement checks")
                colab_tests.extend(self.burp_extender._generic_url_replacer(injector, burp_colab))
                self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Recursive uploader - generic
            if injector.opts.modules['recursive_uploader'].isSelected():
                print("\nDoing recursive upload checks")
                self.burp_extender._recursive_upload_files(injector, burp_colab)
            # Fuzz - generic
            if injector.opts.modules['fuzzer'].isSelected():
                print("\nDoing fuzzer checks")
                self.burp_extender._fuzz(injector)
        except StopScanException:
            scan_was_stopped = True

        # Just to make sure (maybe we write a new module above and forget this call):
        self.burp_extender.collab_monitor_thread.add_or_update(burp_colab, colab_tests)

        # DoSing the server is best done at the end when we already know about everything else...
        # Timeout and DoS - generic
        if not scan_was_stopped:
            try:
                if injector.opts.modules['dos'].isSelected():
                    print("\nDoing timeout and DoS checks")
                    Timeout_and_Dos.check(injector, self)
            except StopScanException:
                pass
        if injector.opts.redl_enabled:
            injector.opts.scan_was_stopped()
        print("\nFinished")