import random
import string
import time
from helpers.FloydsHelpers import FloydsHelpers

from misc.Constants import Constants
from misc.CustomRequestResponse import CustomRequestResponse
from misc.CustomScanIssue import CustomScanIssue
from misc.Misc import StopScanException, UploadRequestsResponses
from ui.LogEntry import LogEntry


class Sender():
    def __init__(self, callbacks, burp_extender):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.burp_extender = burp_extender

    def simple(self, injector, all_types, basename, content, redownload=False, randomize=True):
        i = 0
        types = injector.get_types(all_types)
        urrs = []
        for prefix, ext, mime_type in types:
            if randomize:
                number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
            else:
                number = ""
            sent_filename = prefix + basename + number + ext
            new_content = content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
            req = injector.get_request(sent_filename, new_content, content_type=mime_type)
            i += 1
            if req:
                x = self._filename_to_expected(sent_filename)
                if redownload:
                    urrs.append(self._make_http_request(injector, req, redownload_filename=x))
                else:
                    urrs.append(self._make_http_request(injector, req))
        return urrs
    
    def _make_http_request(self, injector, req, report_timeouts=True, throttle=True, redownload_filename=None):
        if injector.opts.redl_enabled and injector.opts.scan_controler.requesting_stop:
            print("User is requesting stop...")
            raise StopScanException()

        #sys.stdout.write(".")
        #sys.stdout.flush()

        # A little feature, allowing to randomize requests where ${RANDOMIZE} is present
        # To make sure the length of the request doesn't change, replace
        # ${RANDOMIZE}
        # with a numeric value between
        # 100000000000
        # and
        # 999999999999
        # Btw: that's a 12 digit number, and the last dash delimited number of a UUID is also 12 digits...

        req = req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
        base_request_response = injector.get_brr()
        service = base_request_response.getHttpService()
        # print("_make_http_request", service)
        attack = self._callbacks.makeHttpRequest(service, req)
        resp = attack.getResponse()
        if resp:
            resp = FloydsHelpers.jb2ps(resp)
            upload_rr = CustomRequestResponse('', '', service, req, resp)
            urr = UploadRequestsResponses(upload_rr)
            if injector.opts.create_log:
                # create a new log entry with the message details
                self.burp_extender.add_log_entry(upload_rr)
            if redownload_filename and injector.opts.redl_enabled and injector.opts.redl_configured:
                preflight_rr, download_rr = injector.opts.redownloader_try_redownload(resp, redownload_filename)
                urr.preflight_rr = preflight_rr
                urr.download_rr = download_rr
                if injector.opts.create_log:
                    # create a new log entry with the message details
                    if urr.preflight_rr:
                        self.burp_extender.add_log_entry(urr.preflight_rr)
                    if urr.download_rr:
                        self.burp_extender.add_log_entry(urr.download_rr)
        else:
            urr = None
            if report_timeouts:
                print("Adding informative for request timeout")
                desc = "A timeout occured when uploading a file. This could mean that you did memory exhaustion or " \
                       "a DoS attack on some component of the website. Or it was just a regular timeout. Check manually."
                service = base_request_response.getHttpService()
                url = self._helpers.analyzeRequest(base_request_response).getUrl()
                brr = CustomRequestResponse("", "", base_request_response.getHttpService(), req, None)
                csi = CustomScanIssue(brr, "File upload connection timeout", desc, "Certain", "Information",
                                      service, url)
                self._add_scan_issue(csi)
        if throttle and injector.opts.throttle_time > 0.0:
            time.sleep(injector.opts.throttle_time)
        return urr
        
    def _filename_to_expected(self, filename):
        # TODO feature: maybe try to download both?
        # For filenames that include %00 or \x00 we assume we require the server to truncate there
        # so we want to redownload the truncated file name:
        for nullstr in ("%00", "\x00"):
            if nullstr in filename:
                filename = filename[:filename.index(nullstr)]
        return filename