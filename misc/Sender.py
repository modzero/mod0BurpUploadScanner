import random
import string
import time
from helpers.FloydsHelpers import FloydsHelpers

from misc.Constants import Constants
from misc.CustomRequestResponse import CustomRequestResponse
from misc.CustomScanIssue import CustomScanIssue
from misc.Misc import ColabTest
from misc.StopScanException import StopScanException
from misc.UploadRequestsResponses import UploadRequestsResponses


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
    
    def send_get_request(self, brr, relative_url, create_log):
        # Simply tries to send brr but as a GET request and to a different URL
        service = brr.getHttpService()
        iRequestInfo = self._helpers.analyzeRequest(brr)
        new_req = "GET " + relative_url + " HTTP/1.1" + Constants.NEWLINE
        headers = iRequestInfo.getHeaders()
        # very strange, Burp seems to include the status line in .getHeaders()...
        headers = headers[1:]
        new_headers = []
        for header in headers:
            is_bad_header = False
            for bad_header in Constants.REDL_URL_BAD_HEADERS:
                if header.lower().startswith(bad_header):
                    is_bad_header = True
                    break
            if is_bad_header:
                continue
            new_headers.append(header)
        new_headers.append("Accept: */*")

        new_headers = Constants.NEWLINE.join(new_headers)
        new_req += new_headers
        new_req += Constants.NEWLINE * 2

        new_req = new_req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
        attack = self._callbacks.makeHttpRequest(service, new_req)
        resp = attack.getResponse()
        if resp and create_log:
            # create a new log entry with the message details
            self.burp_extender.add_log_entry(attack)

    def send_collaborator(self, injector, burp_colab, all_types, basename, content, issue, redownload=False,
                           replace=None, randomize=True):
        colab_tests = []
        types = injector.get_types(all_types)
        i = 0
        for prefix, ext, mime_type in types:
            break_when_done = False
            for prot in Constants.PROTOCOLS_HTTP:
                colab_url = burp_colab.generate_payload(True)
                if callable(replace):
                    # we got a function like object we need to call with the content and collaborator URL
                    # to get the collaborator injected content
                    new_content = replace(content, prot + colab_url + "/")
                    new_basename = basename
                elif type(replace) is list or type(replace) is tuple:
                    # we got a list of string that has to be replaced with the collaborator URL
                    new_content = content
                    new_basename = basename
                    already_found = []
                    for repl in replace:
                        if not repl:
                            if Constants.MARKER_COLLAB_URL not in content and \
                            Constants.MARKER_COLLAB_URL not in new_basename and \
                            Constants.MARKER_COLLAB_URL not in already_found:
                                print("Warning: Magic marker {} (looped) not found in content or filename of " \
                                      "_send_collaborator:\n {} {}".format(Constants.MARKER_COLLAB_URL, repr(content), repr(basename)))
                            already_found.append(Constants.MARKER_COLLAB_URL)
                            new_content = new_content.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                            new_basename = new_basename.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                        else:
                            if repl not in content and repl not in new_basename and repl not in already_found:
                                print("Warning: Marker", repl, "not found in content or filename of _send_collaborator:\n", repr(content), repr(basename))
                            already_found.append(repl)
                            new_content = new_content.replace(repl, colab_url)
                            new_basename = new_basename.replace(repl, colab_url)
                    # We don't need the different prot here, so break the inner loop over the protocols once sent
                    break_when_done = True
                elif replace:
                    # we got a string that has to be replaced with the collaborator URL
                    # no protocol here!
                    if replace not in content and replace not in basename:
                        print("Warning: Magic marker (str)", replace, "not found in content or filename of _send_collaborator:\n", repr(content), repr(basename))
                    new_content = content.replace(replace, colab_url)
                    new_basename = basename.replace(replace, colab_url)
                    # We don't need the different prot here, so break the inner loop over the protocols once sent
                    break_when_done = True
                else:
                    # the default is we simply replace Constants.MARKER_COLLAB_URL with a collaborator URL
                    if Constants.MARKER_COLLAB_URL not in content and Constants.MARKER_COLLAB_URL not in basename:
                        print("Warning: Magic marker (default) {} not found in content or filename of " \
                              "_send_collaborator:\n {} {}".format(Constants.MARKER_COLLAB_URL, repr(content), repr(basename)))
                    new_content = content.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                    new_basename = basename.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                if randomize:
                    number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
                else:
                    number = ""
                new_content = new_content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
                filename = prefix + new_basename + number + ext
                req = injector.get_request(filename, new_content, content_type=mime_type)
                i += 1
                if req:
                    x = self._filename_to_expected(filename)
                    if redownload:
                        urr = self._make_http_request(injector, req, redownload_filename=x)
                    else:
                        urr = self._make_http_request(injector, req)
                    if urr:
                        colab_tests.append(ColabTest(colab_url, urr, issue))
                if break_when_done:
                    break
        return colab_tests

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