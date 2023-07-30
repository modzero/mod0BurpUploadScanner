
class InsertionPointForActiveScan(IScannerInsertionPoint):
    # Where can we inject?
    # 1. Backdoored file locations (combinatoric explosion!)
    #  - All filetypes, currently: gif, png, bmp, jpeg, tiff, pdf, zip, mp4
    #  - All exiftool techniques, currently: keywords, comment, iptckeywords, xmpkeywords, exifImageDescription, thumbnailWithIptckeywords
    #  ---> Around 20 InsertionPoints

    def __init__(self, injector, upload_type, function, args, kwargs):
        self.injector = injector
        self.upload_type = upload_type
        self.function = function
        self.args = args
        self.kwargs = kwargs
        # Let's figure out the insertion point name
        self.insertion_point_name = "FileContentData"
        try:
            payload, expect, name, ext, content = self._create_content("TestWithAPayloadThatHasAGoodLength")
            if name and ext:
                self.insertion_point_name = "FileContent" + name + ext[1:]
        except StopIteration:
            print("Error: No file created in constructor of InsertionPointForActiveScan, this is probably pretty bad.")
        self.index = 0

    def _create_content(self, payload):
        payload_func = lambda: (payload, None)
        args = [payload_func]
        args.extend(self.args)
        return next(iter(self.function(*args, **self.kwargs)))

    def _create_request(self, payload):
        if len(payload) < BackdooredFile.MINIMUM_PAYLOAD_LENGTH:
            payload += " " * (BackdooredFile.MINIMUM_PAYLOAD_LENGTH - len(payload))
        payload = payload[:BackdooredFile.MAXIMUM_PAYLOAD_LENGTH]
        try:
            payload, expect, name, ext, content = self._create_content(payload)
            if content:
                prefix, ext, mime_type = self.upload_type
                random_part = str(self.index)
                self.index += 1
                filename = prefix + "ActiveScan" + self.insertion_point_name + random_part + ext
                req = self.injector.get_request(filename, content, content_type=mime_type)
                if req:
                    return req, payload
        except StopIteration:
            print("No file created")
        return None, None

    def buildRequest(self, payload):
        req, _ = self._create_request(FloydsHelpers.jb2ps(payload))
        return req

    def getBaseValue(self):
        # Would it be good to have e.g. the XMP content as base value? Probably, but then that would also come in
        # as payload to buildRequest, which we then have to alter. Let's just say the "default" base value of
        # e.g. a keyword element of XMP metadata is empty
        return ""

    def getInsertionPointName(self):
        # TODO: What's best?
        return self.insertion_point_name

    def getInsertionPointType(self):
        # TODO: What's best? Alternatives:
        # INS_PARAM_BODY
        # INS_PARAM_MULTIPART_ATTR
        # INS_UNKNOWN
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED

    def getPayloadOffsets(self, payload):
        payload = FloydsHelpers.jb2ps(payload)
        req, payload = self._create_request(payload)
        if payload in req:
            start = req.index(payload)
            return [start, start + len(payload)]
        else:
            return None
