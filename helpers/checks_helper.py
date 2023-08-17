
import random
import random
import string
import time
from helpers.FloydsHelpers import FloydsHelpers
from misc.Constants import Constants
from misc.CustomRequestResponse import CustomRequestResponse
from misc.CustomScanIssue import CustomScanIssue
from misc.StopScanException import StopScanException
from misc.UploadRequestsResponses import UploadRequestsResponses


class Checks_Helper():
    def __init__(self, burp_extender):
        self.burp_extender = burp_extender
        self._callbacks = burp_extender._callbacks

    @staticmethod
    def get_sleep_commands(injector):
        if injector.opts.sleep_time > 0:
            # payloads being sent?
            # Format: name, command, factor, args
            # Unix
            yield "Sleep", "sleep", 1, ""
            # Windows
            yield "Ping", "ping -n", 2, " localhost"

    @staticmethod
    def get_rce_interaction_commands(injector, burp_colab):
        # Format: name, command, server_placeholder, replace
        # Rules for payloads regarding command injection: While a nslookup is sufficient (Windows and Unix) and we wouldn't
        # need wget or curl we also need to keep people in mind that use Burp Collaborator IP configs in internal networks.
        # There might be no option to detect DNS interactions, therefore wget and curl are still valid payloads in certain
        # scenarios. It also means that we have to handle that case.
        # configs etc. In general we would like to do:
        # inbound response based (e.g. nslookup stdout or PHP string concat stdout detection) - always
        # inbound sleep (unix) and ping -n (windows) for timeout detection - always
        # nslookup (unix and windows) for Collaborator interaction - always
        # wget and curl (unix) and rundll32 (windows) for IP Collaborators - and as UI option (disabled by default)

        # When is wget and curl better than nslookup?
        # 1. When we have a Burp Collaborator configured as an IP (no DNS Collaborator) - autodetected in this extension
        # 2. When the server is not allowed to do DNS queries, but allowed to connect to a proxy that does DNS queries
        if burp_colab.is_ip_collaborator or injector.opts.wget_curl_payloads:
            yield "Wget", "wget -O-", Constants.MARKER_COLLAB_URL, None
            yield "Curl", "curl", Constants.MARKER_COLLAB_URL, None
            yield "Rundll32", "rundll32 url.dll,FileProtocolHandler", Constants.MARKER_COLLAB_URL, None
            # yield "msiexec", "msiexec /a", Constants.MARKER_COLLAB_URL, None
        else:
            yield "Nslookup", "nslookup", "test.example.org", "test.example.org"

    @staticmethod
    def filename_to_expected(filename):
        # TODO feature: maybe try to download both?
        # For filenames that include %00 or \x00 we assume we require the server to truncate there
        # so we want to redownload the truncated file name:
        for nullstr in ("%00", "\x00"):
            if nullstr in filename:
                filename = filename[:filename.index(nullstr)]
        return filename

    @staticmethod
    def make_http_request(burp_extender, injector, req, report_timeouts=True, throttle=True, redownload_filename=None):
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
        attack = burp_extender._callbacks.makeHttpRequest(service, req)
        resp = attack.getResponse()
        if resp:
            resp = FloydsHelpers.jb2ps(resp)
            upload_rr = CustomRequestResponse('', '', service, req, resp)
            urr = UploadRequestsResponses(upload_rr)
            if injector.opts.create_log:
                # create a new log entry with the message details
                burp_extender.add_log_entry(upload_rr)
            if redownload_filename and injector.opts.redl_enabled and injector.opts.redl_configured:
                preflight_rr, download_rr = injector.opts.redownloader_try_redownload(resp, redownload_filename)
                urr.preflight_rr = preflight_rr
                urr.download_rr = download_rr
                if injector.opts.create_log:
                    # create a new log entry with the message details
                    if urr.preflight_rr:
                        burp_extender.add_log_entry(urr.preflight_rr)
                    if urr.download_rr:
                        burp_extender.add_log_entry(urr.download_rr)
        else:
            urr = None
            if report_timeouts:
                print("Adding informative for request timeout")
                desc = "A timeout occured when uploading a file. This could mean that you did memory exhaustion or " \
                       "a DoS attack on some component of the website. Or it was just a regular timeout. Check manually."
                service = base_request_response.getHttpService()
                url = burp_extender._helpers.analyzeRequest(base_request_response).getUrl()
                brr = CustomRequestResponse("", "", base_request_response.getHttpService(), req, None)
                csi = CustomScanIssue(brr, "File upload connection timeout", desc, "Certain", "Information",
                                      service, url)
                burp_extender._add_scan_issue(csi)
        if throttle and injector.opts.throttle_time > 0.0:
            time.sleep(injector.opts.throttle_time)
        return urr

    def send_sleep_based(self, injector, basename, content, types, sleep_time, issue, redownload=False, randomize=True):
        types = injector.get_types(types)
        timeout_detection_time = (float(sleep_time) / 2) + 0.5
        i = 0
        for prefix, ext, mime_type in types:
            if randomize:
                number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
            else:
                number = ""
            filename = prefix + basename + number + ext
            expected_filename = self.filename_to_expected(filename)
            new_content = content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
            req = injector.get_request(filename, new_content, content_type=mime_type)
            i += 1
            if req:
                start = time.time()
                if redownload:
                    resp = self.make_http_request(self.burp_extender, injector, req, throttle=False, redownload_filename=expected_filename)
                else:
                    resp = self.make_http_request(self.burp_extender, injector, req, throttle=False)
                if resp and time.time() - start > timeout_detection_time:
                    # found a timeout, let's confirm with a changed request so it doesn't get a cached response
                    print("TIMEOUT DETECTED! Now checking if really a timeout or just a random timeout. " \
                          "Request leading to first timeout was:")
                    print(repr(req))
                    if randomize:
                        number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
                    else:
                        number = ""
                    filename = prefix + basename + number + ext
                    expected_filename = self.filename_to_expected(filename)
                    # A feature to prevent caching of responses to identical requests
                    new_content = content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
                    req = injector.get_request(filename, new_content, content_type=mime_type)
                    i += 1
                    if req:
                        start = time.time()
                        if redownload:
                            resp = self.make_http_request(self.burp_extender, injector, req, throttle=False, redownload_filename=expected_filename)
                        else:
                            resp = self.make_http_request(self.burp_extender, injector, req, throttle=False)
                        if resp and time.time() - start > timeout_detection_time:
                            csi = issue.create_copy()
                            csi.httpMessagesPy.append(resp.upload_rr)
                            self.burp_extender._add_scan_issue(csi)
                            # Returning here is an option, but actually knowing all different kind of injections is nicer
                            # return
                        else:
                            print("Unfortunately, this seems to be a false positive... not reporting")
