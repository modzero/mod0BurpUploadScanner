import copy
from burp import IScannerInsertionPoint

from helpers.FloydsHelpers import FloydsHelpers

class CsvInsertionPoint(IScannerInsertionPoint):
    def __init__(self, injector, new_line, delim, line_index, field_index):
        self.injector = injector
        self.new_line = new_line
        self.delim = delim
        self.line_index = line_index
        self.field_index = field_index

        self.lines = injector.get_uploaded_content().split(self.new_line)
        self.fields = self.lines[self.line_index].split(self.delim)

        self.index = 0

    def create_request(self, payload):
        fields = copy.copy(self.fields)
        if fields[self.field_index].startswith('"') and fields[self.field_index].endswith('"'):
            # Let's assume it is a quoted CSV
            # RFC-4180, "If double-quotes are used to enclose fields, then a double-quote appearing inside a
            # field must be escaped by preceding it with another double quote."
            payload = '"' + payload.replace('"', '""') + '"'
            fields[self.field_index] = payload
        else:
            fields[self.field_index] = payload
        line = self.delim.join(fields)
        lines = copy.copy(self.lines)
        lines[self.line_index] = line
        content = self.new_line.join(lines)
        req = self.injector.get_request("ActiveScanCsvAttack" + str(self.index) + self.injector.get_uploaded_filename()[-4:], content)
        self.index += 1
        return req, payload, content

    def buildRequest(self, payload):
        req, _, _ = self.create_request(FloydsHelpers.jb2ps(payload))
        return req

    def getBaseValue(self):
        return self.fields[self.field_index]

    def getInsertionPointName(self):
        return ""

    def getInsertionPointType(self):
        # TODO: What's best? Alternatives:
        # INS_PARAM_BODY
        # INS_PARAM_MULTIPART_ATTR
        # INS_UNKNOWN
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED

    def getPayloadOffsets(self, payload):
        payload = FloydsHelpers.jb2ps(payload)
        req, payload, _ = self.create_request(payload)
        if payload in req:
            start = req.index(payload)
            return [start, start + len(payload)]
        else:
            return None
