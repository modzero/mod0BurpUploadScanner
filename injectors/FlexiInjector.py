
import os
import urllib
from helpers.FloydsHelpers import FloydsHelpers
from injectors.Injector import Injector


class FlexiInjector(Injector):
    # Can be used for any insertionPoint, as we simply globaly change stuff
    # with search/replace in the request.
    def __init__(self, base_request_response, options, helpers, newline):
        self._brr = base_request_response
        self.opts = options
        self._req = FloydsHelpers.jb2ps(base_request_response.getRequest())
        self._helpers = helpers
        self._newline = newline
        self._encoders = [
            lambda x: x,
            lambda x: x.encode("hex"),
            urllib.quote,
            lambda x: urllib.quote(x, ''),
            urllib.quote_plus,
            lambda x: urllib.quote_plus(x, '/'),

            lambda x: x.encode("base64").strip(),  # multiline MIME base64: alphanum, +, /, \n (after every 76 chars)
            lambda x: urllib.quote(x.encode("base64").strip(), ''),
            # multiline MIME base64: alphanum, %2B, %2F, %0A (after every 76 chars)
            lambda x: urllib.quote(x.encode("base64").strip()),
            # multiline MIME base64: alphanum, %2B, /, %0A (after every 76 chars)

            lambda x: x.encode("base64").replace('\n', '').replace('\r', '').strip(),  # one line base64: alphanum, +, /
            lambda x: urllib.quote(x.encode("base64").replace('\n', '').replace('\r', '').strip(), ''),
            # one line base64: alphanum, %2B, %2F
            lambda x: urllib.quote(x.encode("base64").replace('\n', '').replace('\r', '').strip()),
            # one line base64: alphanum, %2B, /
            
            lambda x: x.encode("base64").replace('\n', '').replace('\r', '').strip().rstrip('='),  # one line base64: alphanum, +, / but missing end =
            lambda x: urllib.quote(x.encode("base64").replace('\n', '').replace('\r', '').strip().rstrip('='), ''),
            # one line base64: alphanum, %2B, %2F but missing end =
            lambda x: urllib.quote(x.encode("base64").replace('\n', '').replace('\r', '').strip().rstrip('=')),
            # one line base64: alphanum, %2B, / but missing end =
        ]
        self._default_file_extension = FloydsHelpers.u2s(os.path.splitext(self.opts.fi_ofilename)[1]) or ''

    def get_default_file_ext(self):
        return self._default_file_extension

    def get_brr(self):
        return self._brr

    def get_uploaded_content(self):
        for encoder in self._encoders:
            i = encoder(self.opts.fi_ocontent)
            # print(repr(i))
            if i in self._req:
                return self.opts.fi_ocontent

    def get_uploaded_filename(self):
        for encoder in self._encoders:
            i = encoder(self.opts.fi_ofilename)
            # print(repr(i))
            if i in self._req:
                return self.opts.fi_ofilename
        # Seems the filename is not part of the request
        # (which is actually quiet common, eg. Vimeo avatar image upload)
        # So we just return an empty string
        return ''

    def get_uploaded_content_type(self):
        for encoder in self._encoders:
            i = encoder(self.opts.fi_filemime)
            # print(repr(i))
            if i in self._req:
                return self.opts.fi_filemime
        # Seems the mime type is not part of the request
        # (which is actually quiet common, eg. Vimeo avatar image upload)
        # So we just return an empty string
        return ''

    def get_request(self, filename, content, content_type=None):
        iRequest = self._helpers.analyzeRequest(self._req)
        status_headers, body = self._req[:iRequest.getBodyOffset()], self._req[iRequest.getBodyOffset():]
        status_line = status_headers.split(self._newline)[0]
        headers = self._newline.join(status_headers.split(self._newline)[1:])
        for encoder in self._encoders:
            if not filename == self.opts.fi_ofilename and self.opts.replace_filename and self.opts.fi_ofilename and not filename is None:
                o = encoder(self.opts.fi_ofilename)
                n = encoder(filename)
                if encoder == self._encoders[0]:
                    # The no-encoder. We need to do this, otherwise HTTP messages
                    # could be turned into HTTP/0.9 message by introducing a whitespace
                    status_line = status_line.replace(o, urllib.quote(n))
                else:
                    status_line = status_line.replace(o, n)
                body = body.replace(o, n)
                headers = headers.replace(o, n)
            if not content == self.opts.fi_ocontent and self.opts.fi_ocontent:
                o = encoder(self.opts.fi_ocontent)
                n = encoder(content)
                if encoder == self._encoders[0]:
                    # The no-encoder
                    status_line = status_line.replace(o, urllib.quote(n))
                else:
                    status_line = status_line.replace(o, n)
                body = body.replace(o, n)
                headers = headers.replace(o, n)
                if self.opts.replace_filesize and o in body and len(o) > 100:
                    status_line = status_line.replace(str(len(o)), str(len(n)))
                    body = body.replace(str(len(o)), str(len(n)))
                    # But what if str(len(o)) is part of n ?
                    # Then we just destroyed our n with this replacement.
                    # But with the following hack we undo it again.
                    # A little bit ugly, but should work fine.
                    if str(len(o)) in n:
                        destroyed_content = n.replace(str(len(o)), str(len(n)))
                        body.replace(destroyed_content, n)
            if content_type and self.opts.replace_ct and self.opts.fi_filemime:
                # This is not optimal: our python code might not detect exactly the same mime type
                # as the browser/client software sends. However, the user can specify the original
                # mime type in the UI which has to be sufficient for now
                o = encoder(self.opts.fi_filemime)
                n = encoder(content_type)
                if encoder == self._encoders[0]:
                    # The no-encoder
                    status_line = status_line.replace(o, urllib.quote(n))
                else:
                    status_line = status_line.replace(o, n)
                body = body.replace(o, n)
                headers = headers.replace(o, n)
        status_headers = status_line + self._newline + headers
        return FloydsHelpers.fix_content_length(status_headers, len(body), self._newline) + body
