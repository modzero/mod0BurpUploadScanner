from burp import IScannerInsertionPoint

class CustomMultipartInsertionPoint(IScannerInsertionPoint):
    FILENAME_MARKER = '; filename='
    def __init__(self, helpers, newline, req):
        self._helpers = helpers
        self._newline = newline
        self._req = req
        self._is_multipart_filename = False
        self._status_headers = None
        self._body_before = None
        self.original_payload = None
        self._body_after = None
        self.filename_del = None
        self.payload_offset_start = None

        # Now parse the request
        self._parse()

    def _parse(self):
        iRequest = self._helpers.analyzeRequest(self._req)
        self._status_headers, body = self._req[:iRequest.getBodyOffset()], self._req[iRequest.getBodyOffset():]
        headers = self._newline.join(self._status_headers.split(self._newline)[1:])
        # Tested with Firefox, IE, Chrome and Edge and this works
        if "content-type: multipart/form-data" in headers.lower() and \
            "content-disposition: form-data" in body.lower() and \
            CustomMultipartInsertionPoint.FILENAME_MARKER in body:
            self._is_multipart_filename = True
            index = body.index(CustomMultipartInsertionPoint.FILENAME_MARKER) + len(CustomMultipartInsertionPoint.FILENAME_MARKER)
            self._body_before, self._body_after = body[:index], body[index:]
            if self._body_after.startswith('"'):
                self.filename_del = '"'
                self._body_before += self.filename_del
                self._body_after = self._body_after[len(self.filename_del):]
            elif self._body_after.startswith("'"):
                self.filename_del = "'"
                self._body_before += self.filename_del
                self._body_after = self._body_after[len(self.filename_del):]
            else:
                print("Warning: Filename parameter in multipart does not seem to be quoted... using newline as end delimiter")
                self.filename_del = "\n"

            end_index = -1
            while end_index < 0:
                end_index = self._body_after.find(self.filename_del)
                if end_index == -1:
                    print("Error: Filename parameter in multipart starts with", self.filename_del, "but does not seem to end with it.")
                    self._is_multipart_filename = False
                    return
                elif end_index > 0 and self._body_after[end_index - 1] == "\\":
                    self._body_after = self._body_after[end_index + 1:]
                    end_index = -1 # we need to go on searching for a non escaped end delimiter...
            self._body_after = self._body_after[end_index:]
            # The original payload is what is between self._body_before and self._body_after
            self.original_payload = body[len(self._body_before):body.index(self._body_after)]
            # Now calculate values for getPayloadOffsets from the original base request:
            self.payload_offset_start = self._req.index(self.original_payload + self._body_after)
        else:
            self._is_multipart_filename = False

    def buildRequest(self, payload):
        # For now we don't fix the Content-Length
        # If we do, then self.payload_offset_start will be wrong, etc.
        # For now it doesn't matter, as this extension doesn't rely on buildRequest()
        # providing a fixed Content-Length, as the calling classes will fix the content-length
        # anyway after modifying the request
        p = self._get_encoded_payload(payload)
        req = self._status_headers + self._body_before + p + self._body_after
        # I know it's a little strange, but as we are implementing the Java API here and need to return byte[]
        # we actually have to return it as a list of integers... stupid, but that's how it is.
        return [ord(x) for x in req]

    def getBaseValue(self):
        return self.original_payload

    def getInsertionPointName(self):
        return "filename"

    def getInsertionPointType(self):
        if self._is_multipart_filename:
            return IScannerInsertionPoint.INS_PARAM_MULTIPART_ATTR
        else:
            return IScannerInsertionPoint.INS_UNKNOWN

    def getPayloadOffsets(self, payload):
        end = self.payload_offset_start + len(self._get_encoded_payload(payload))
        return [self.payload_offset_start, end]

    def _get_encoded_payload(self, payload):
        return payload.replace(self.filename_del, "\\" + self.filename_del)
