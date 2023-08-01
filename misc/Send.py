import random
import string

from misc.Constants import Constants
from misc.Misc import StopScanException


class Send():
    
    @staticmethod
    def simple(injector, all_types, basename, content, redownload=False, randomize=True):
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
                x = Send()._filename_to_expected(sent_filename)
                if redownload:
                    urrs.append(Send()._make_http_request(injector, req, redownload_filename=x))
                else:
                    urrs.append(Send()._make_http_request(injector, req))
        return urrs
    
    @staticmethod
    def _make_http_request(injector, req, report_timeouts=True, throttle=True, redownload_filename=None):
        if injector.opts.redl_enabled and injector.opts.scan_controler.requesting_stop:
            print("User is requesting stop...")
            raise StopScanException()
        
    @staticmethod
    def _filename_to_expected(filename):
        # TODO feature: maybe try to download both?
        # For filenames that include %00 or \x00 we assume we require the server to truncate there
        # so we want to redownload the truncated file name:
        for nullstr in ("%00", "\x00"):
            if nullstr in filename:
                filename = filename[:filename.index(nullstr)]
        return filename