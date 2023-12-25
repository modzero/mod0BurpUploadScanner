from helpers.FloydsHelpers import FloydsHelpers
from misc.Constants import Constants

class Injector(object):
    def get_url(self):
        return FloydsHelpers.u2s(self._helpers.analyzeRequest(self._brr).getUrl().toString())

    def get_uploaded_filename(self):
        return ''

    def get_uploaded_content_type(self):
        return ''

    def get_types(self, all_types):
        new_types = set()
        for prefix, ext, mime_type in all_types:
            if Constants.MARKER_ORIG_EXT in ext:
                ext = ext.replace(Constants.MARKER_ORIG_EXT, self.get_default_file_ext())
            if not mime_type:
                # The "use original mime type" marker is an empty string
                mime_type = self.get_uploaded_content_type()
            new_types.add((prefix, ext, mime_type))
        # Further reduction if no mime or no filename is sent
        has_filename = self.get_uploaded_filename()
        has_mime = self.get_uploaded_content_type()
        if has_filename and has_mime:
            return new_types
        elif has_filename:
            return set([(x[0], x[1], '') for x in new_types])
        elif has_mime:
            return set([('', '', x[2]) for x in new_types])
        else:
            return [('', '', ''), ]
