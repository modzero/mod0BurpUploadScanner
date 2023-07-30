    
class MultipartInjector(Injector):
    # Can *ONLY* be used for IScannerInsertionPoint.INS_PARAM_MULTIPART_ATTR checks
    # where insertionPoint.getInsertionPointName() == "filename"
    # You might ask why this class is necessary, because we could always use FlexiInjector
    # That's correct, but this class can *automatically* scan without any configuration necessary!
    def __init__(self, base_request_response, options, insertionPoint, helpers, newline):
        self._brr = base_request_response
        self.opts = options
        self._req = FloydsHelpers.jb2ps(base_request_response.getRequest())
        self._insertionPoint = insertionPoint
        self._helpers = helpers
        self._newline = newline
        self._default_file_extension = FloydsHelpers.file_extension(self._insertionPoint) or ''
        # print("self._default_file_extension", self._default_file_extension)

    def get_uploaded_content(self):
        start, _ = self._insertionPoint.getPayloadOffsets(self._insertionPoint.getBaseValue())
        meant_multipart_index, multiparts, boundary, headers = self._split_multipart(self._req, start)
        # print("meant_multipart_index, multiparts, boundary, headers", [meant_multipart_index, multiparts, boundary, headers])
        if multiparts:
            content = self.get_multipart_content(multiparts[meant_multipart_index])
            # as defined in get_multipart_content this returns the content plus a self._newline at the end
            # Although that's fine for internal multipart handling, we don't want the self._newline here:
            content = content[:-len(self._newline)]
            return content

    def get_default_file_ext(self):
        return self._default_file_extension

    def get_brr(self):
        return self._brr

    def get_uploaded_content_type(self):
        start, _ = self._insertionPoint.getPayloadOffsets(self._insertionPoint.getBaseValue())
        meant_multipart_index, multiparts, boundary, headers = self._split_multipart(self._req, start)
        if multiparts:
            # print("type self.get_multipart_content_type(multiparts[meant_multipart_index])", type(self.get_multipart_content_type(multiparts[meant_multipart_index])))
            return self.get_multipart_content_type(multiparts[meant_multipart_index])

    def get_uploaded_filename(self):
        # print("type self._insertionPoint.getBaseValue()", type(self._insertionPoint.getBaseValue()))
        base_value = self._insertionPoint.getBaseValue()
        if base_value: # getBaseValue() might be None in rare cases
            return FloydsHelpers.u2s(base_value)
        else:
            return ''

    def get_request(self, filename, content, content_type=None):
        attack = FloydsHelpers.jb2ps(self._insertionPoint.buildRequest(filename))
        start, _ = self._insertionPoint.getPayloadOffsets(filename)
        meant_multipart_index, multiparts, boundary, status_headers = self._split_multipart(attack, start)
        if multiparts:
            old_size = str(len(self.get_uploaded_content()))
            new_size = str(len(content))
            old_ct = self.get_uploaded_content_type()
            new_ct = content_type
            old_filename = self.get_uploaded_filename()
            new_filename = filename
            for index, multipart in enumerate(multiparts):
                if index == meant_multipart_index:
                    # Where we will inject the content, we will only do header changes
                    multipart_headers = self.get_multipart_headers(multipart)
                    if multipart_headers and self.opts.replace_filesize and old_size in multipart_headers and old_size > 100 and old_size != new_size:
                        # print("Replacing in the multipart header with content old content size", old_size, "with new size", new_size)
                        multipart_headers = multipart_headers.replace(old_size, new_size)
                        multipart = multipart_headers + self._newline + self._newline + self.get_multipart_content(
                            multipart)
                        multiparts[index] = multipart
                    if multipart_headers and self.opts.replace_filename and old_filename and old_filename in multipart_headers and old_filename != new_filename:
                        # print("Replacing in the multipart header with content old filename", repr(old_filename), "with new filename", new_filename)
                        multipart_headers = multipart_headers.replace(old_filename, new_filename)
                        multipart = multipart_headers + self._newline + self._newline + self.get_multipart_content(
                            multipart)
                        multiparts[index] = multipart
                        # We do not need to replace the Content-Type here, it will be replaced automatically in this
                        # header multipart in the _set_multipart_content function, which will also
                        # honor self.opts.replace_ct
                else:
                    if self.opts.replace_filesize and old_size > 100 and old_size and old_size in multipart and old_size != new_size:
                        # print("Replacing old content size", old_size, "with new size", new_size, "in multipart number", index)
                        new_multipart = multipart.replace(old_size, new_size)
                        multiparts[index] = new_multipart
                    if self.opts.replace_ct and old_ct and new_ct and old_ct and old_ct in multipart and old_ct != new_ct :
                        # print("Replacing old content-type", old_ct, "with new", new_ct, "in multipart number", index)
                        new_multipart = multipart.replace(old_ct, new_ct)
                        multiparts[index] = new_multipart
                    if self.opts.replace_filename and old_filename and old_filename in multipart and old_filename != new_filename:
                        # print("Replacing old filename", old_filename, "with new", new_filename, "in multipart number", index)
                        new_multipart = multipart.replace(old_filename, new_filename)
                        multiparts[index] = new_multipart
            # A filename in the URL is replaced with the new filename
            if self.opts.replace_filename and old_filename and old_filename != new_filename:
                status_line = status_headers.split(self._newline)[0]
                headers = self._newline.join(status_headers.split(self._newline)[1:])
                status_line = status_line.replace(old_filename, urllib.quote(new_filename))
                status_line = status_line.replace(urllib.quote(old_filename), urllib.quote(new_filename))
                status_headers = status_line + self._newline + headers
            # The file size in the URL is replaced with the new filename
            if self.opts.replace_filesize and old_size > 100 and old_size and old_size != new_size:
                status_line = status_headers.split(self._newline)[0]
                if old_size in status_line:
                    headers = self._newline.join(status_headers.split(self._newline)[1:])
                    status_line = status_line.replace(old_size, new_size)
                    status_headers = status_line + self._newline + headers
            # Now finally set the file content
            new = self._set_multipart_content(multiparts[meant_multipart_index], content, content_type)
            if new:
                multiparts[meant_multipart_index] = new
                return self._join_multipart(status_headers, multiparts, boundary)
        else:
            return None

    def get_multipart_headers(self, multipart):
        double_newline = self._newline + self._newline
        header_body = multipart.split(double_newline)
        if not len(header_body) >= 2:
            print("Warning: Strange multipart that has no header and body! Assuming there is only a body.")
            return ''
        # This starts with a self._newline, but doesn't end in one
        return header_body[0]

    def get_multipart_content(self, multipart):
        double_newline = self._newline + self._newline
        header_body = multipart.split(double_newline)
        if not len(header_body) >= 2:
            print("Warning: Strange multipart that has no header and body! Assuming there is only a body.")
            return multipart
        body = header_body[1:]
        # This does not start with a self._newline, but ends in one
        return double_newline.join(body)

    def get_multipart_content_type(self, multipart):
        headers = self.get_multipart_headers(multipart)
        if headers:
            header_lines = headers.split(self._newline)
            for header in header_lines:
                if header.lower().startswith('content-type: '):
                    return header[len('content-type: '):]
        print("Error: Couldn't find Content-Type header in Multipart.")

    def _split_multipart(self, request, payload_offset):
        i_request_info = self._helpers.analyzeRequest(request)
        boundary = self._find_boundary([FloydsHelpers.u2s(x) for x in i_request_info.getHeaders()])
        if not boundary:
            print("Error: No boundary found")
            return None, None, None, None
        body_offset = i_request_info.getBodyOffset()
        headers = request[:body_offset]
        body = request[body_offset:]
        actual_boundary = "--" + boundary
        if not body.startswith(actual_boundary):
            print("Error: Body does not start with two hyphens plus boundary")
            print("First 60 chars of body:  ", repr(body[:60]))
            print("First boundary should be:", repr(actual_boundary))
            return None, None, None, None
        multiparts = body.split(actual_boundary)
        multiparts = multiparts[1:]
        if not multiparts[-1].strip() == "--":
            print("Error: Body does not end with boundary plus two hyphens!")
            print("End of multipart:  ", repr(multiparts[-1]))
            return None, None, None, None
        multiparts = multiparts[:-1]
        # so which multipart is meant with the insertionPoint?
        # first there is the boundary in the HTTP Content-Type header
        # then the first one for the first. So by counting the numbers
        # of boundaries - 1 (the one in the header) up to our insertion point
        # we know which multipart is ours
        meant_multipart_index = request[:payload_offset].count(boundary) - 1
        # but as we cut away the surrounding two-hyphen and the beginning and the end
        # it's actually even one less in our indexed multiparts list
        meant_multipart_index -= 1
        # Every multipart now starts with self._newline and ends with self._newline
        return meant_multipart_index, multiparts, boundary, headers

    def _find_boundary(self, headers):
        multipart_header = None
        for x in headers:
            if "content-type: multipart/form-data" == x[:len("content-type: multipart/form-data")].lower():
                multipart_header = x
                break
        else:
            print("Error: Although this is supposed to be a INS_PARAM_MULTIPART_ATTR we couldn't find the content-type: multipart/form-data header")
            return None
        if 'boundary=' in multipart_header:
            boundary = multipart_header.split('boundary=')[1]
            if ";" in boundary:
                boundary = boundary.split(";")[0]
            return boundary.strip()
        else:
            print("Error: Although this is supposed to be a INS_PARAM_MULTIPART_ATTR we couldn't find the boundary in the content-type: multipart/form-data header")
            return None

    def _set_multipart_content(self, multipart, content, content_type):
        header = self.get_multipart_headers(multipart)
        if not header:
            print("Warning: Strange multipart that has no header and body! Assuming there is only a body.")
            return self._newline + content + self._newline
        header_lines = header.split(self._newline)
        # header_lines is usually an empty string (newline after the beginning boundary)
        # at index 0, followed by content-disposition and content-type. So:
        # [0]:
        # [1]:Content-Disposition: form-data; name="file"; filename="example.jpeg"
        # [2]:Content-Type: image/jpeg
        if len(header_lines) < 3:
            # we simply assume that there is only a Content-Disposition header (otherwise
            # Burp wouldn't have passed a INS_PARAM_MULTIPART_ATTR)
            print("Warning: Strange multipart that has only one header (usually there is at least Content-Disposition and Content-Type)")
            print("Header:", header)
        if content_type and self.opts.replace_ct:
            # Find Content-Type header
            content_type_header_index = None
            for index, header in enumerate(header_lines):
                if header.lower().startswith('content-type: '):
                    content_type_header_index = index
                    break
            else:
                # Didn't find a Content-Type header, so we won't set it either
                print("Warning: Strange multipart that has headers, but no Content-Type header")
                return self._newline.join(header_lines) + self._newline + self._newline + content + self._newline
            name = header_lines[content_type_header_index][:len('content-type: ')]  # trick to use original capitalization of "Content-Type"
            header_lines[content_type_header_index] = name + content_type
        # Again, we end up with a multipart that starts with a self._newline and ends in a self._newline
        return self._newline.join(header_lines) + self._newline + self._newline + content + self._newline

    def _join_multipart(self, headers, parts, boundary):
        actual_boundary = "--" + boundary
        # this works as each part always starts and ends with self._newline
        new_body = actual_boundary + actual_boundary.join(parts) + actual_boundary + "--" + self._newline
        headers = FloydsHelpers.fix_content_length(headers, len(new_body), self._newline)
        return headers + new_body
