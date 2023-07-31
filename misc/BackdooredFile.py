from helpers.ImageHelpers import ImageHelpers
from misc.Constants import Constants

import os
import re
import subprocess
import tempfile
import zipfile
from io import BytesIO


class BackdooredFile:
    """
    The goal of this class is to provide an interface that allows generating files
    that have a specific payload visible in clear when the file is viewed in a hex editor.
    If the payload is not visible in the hex dump of the file, it is not implemented
    in this class.
    """
    # This one is easy and just arbitrarily set here
    MINIMUM_PAYLOAD_LENGTH = 5
    # This one is trickier:
    # Somewhere between 131072 and 262144 we get a subprocess "Argument list too long"
    # IPTC keywords (for sure for tiff) are limited to length 64 "Warning: [Minor] IPTC:Keywords exceeds length limit (truncated)"
    # All other seem rather unlimited
    # However, this plugin can handle if an empty file is created so this is only for ActiveScanning modules...
    MAXIMUM_PAYLOAD_LENGTH = 131072
    EXTENSION_TO_MIME = {".gif": "image/gif",
                         ".png": "image/png",
                         #".bmp": "image/bmp",
                         ".jpeg": "image/jpeg",
                         ".tiff": "image/tiff",
                         ".pdf": "application/pdf",
                         ".zip": "application/zip",
                         ".mp4": "video/mp4"}

    # TODO feature: What happens when we make a thumbnail inside a JPEG but the thumbnail is eg. MVG or SVG?
    # Is GraphicsMagick etc. handling that properly?

    def __init__(self, enabled_formats, tool="exiftool"):
        # Basically enabled_formats tells us which are enabled in the options
        self._enabled_formats = enabled_formats
        self._tool = tool
        self.inputs = [
            # These are green 1 pixel images (1x1) in different formats
            (".gif",
             'GIF87a\x01\x00\x01\x00\x80\x01\x00\x05\xff\x00\xff\xff\xff,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'),
            (".png",
             '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\tpHYs\x00' \
             '\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x07tIME\x07\xe1\x02\x02\x0f\x1b9<j\xfd\xc3\x00\x00\x00\x0c' \
             'IDAT\x08\xd7c`\xfd\xcf\x00\x00\x02\x11\x01\x05\x8c\xc0y\xe5\x00\x00\x00\x00IEND\xaeB`\x82'),
            # exiftool can't write SVG, BMP or ZIP files :(
            # it's still better than any other tool out there
            # (".bmp", 'BM\x82\x00\x00\x00\x00\x00\x00\x00~\x00\x00\x00l\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00' \
            #            '\x04\x00\x00\x00\x13\x0b\x00\x00\x13\x0b\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00BGRs\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            #            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            #            '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x05\x00\x00' \
            #            '\x00\x00\x00'),
            (".jpeg",
             '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x03\x02\x02\x03\x02\x02\x03\x03\x03' \
             '\x03\x04\x03\x03\x04\x05\x08\x05\x05\x04\x04\x05\n\x07\x07\x06\x08\x0c\n\x0c\x0c\x0b\n\x0b\x0b\r\x0e\x12\x10\r\x0e' \
             '\x11\x0e\x0b\x0b\x10\x16\x10\x11\x13\x14\x15\x15\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14\xff\xdb\x00C\x01\x03' \
             '\x04\x04\x05\x04\x05\t\x05\x05\t\x14\r\x0b\r\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14' \
             '\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14' \
             '\x14\x14\x14\xff\xc2\x00\x11\x08\x00\x01\x00\x01\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x14\x00\x01\x00' \
             '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\xff\xc4\x00\x15\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00' \
             '\x00\x00\x00\x00\x00\x00\x00\x07\x08\xff\xda\x00\x0c\x03\x01\x00\x02\x10\x03\x10\x00\x00\x01x6t\xff\xc4\x00\x14\x10' \
             '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x01\x00\x01\x05\x02\x7f\xff' \
             '\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x03\x01\x01' \
             '?\x01\x7f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01' \
             '\x02\x01\x01?\x01\x7f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda' \
             '\x00\x08\x01\x01\x00\x06?\x02\x7f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
             '\x00\xff\xda\x00\x08\x01\x01\x00\x01?!\x7f\xff\xda\x00\x0c\x03\x01\x00\x02\x00\x03\x00\x00\x00\x10\xff\x00\xff\xc4\x00' \
             '\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x03\x01\x01?\x10\x7f' \
             '\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x02\x01\x01' \
             '?\x10\x7f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01' \
             '\x01\x00\x01?\x10\x7f\xff\xd9'),
            (".tiff",
             'II*\x00\x0c\x00\x00\x00\x05\xff\x00\x00\x10\x00\xfe\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x03\x00\x01\x00' \
             '\x00\x00\x01\x00\x00\x00\x01\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x01\x03\x00\x03\x00\x00\x00\xe2\x00\x00\x00' \
             '\x03\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x06\x01\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00\r\x01\x02\x00W\x00\x00' \
             '\x00\xe8\x00\x00\x00\x11\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00\x12\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x15' \
             '\x01\x03\x00\x01\x00\x00\x00\x03\x00\x00\x00\x16\x01\x03\x00\x01\x00\x00\x00@\x00\x00\x00\x17\x01\x04\x00\x01\x00\x00\x00' \
             '\x03\x00\x00\x00\x1a\x01\x05\x00\x01\x00\x00\x00\xd2\x00\x00\x00\x1b\x01\x05\x00\x01\x00\x00\x00\xda\x00\x00\x00\x1c\x01' \
             '\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00(\x01\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x01' \
             '\x00\x00\x00H\x00\x00\x00\x01\x00\x00\x00\x08\x00\x08\x00\x08\x00                                                      ' \
             '                                \x00'),
            (".pdf",
             '%PDF-1.5\n%\xb5\xed\xae\xfb\n3 0 obj\n<< /Length 4 0 R\n   /Filter /FlateDecode\n>>\nstream\nx\x9c+\xe4*\xe4\xd2O4PH/V' \
             '\xd0\xaf0Up\xc9\xe7\n\x04B\x00@\x10\x05@\nendstream\nendobj\n4 0 obj\n   28\nendobj\n2 0 obj\n<<\n   /ExtGState <<\n   ' \
             '   /a0 << /CA 1 /ca 1 >>\n   >>\n   /XObject << /x5 5 0 R >>\n>>\nendobj\n6 0 obj\n<< /Type /Page\n   /Parent 1 0 R\n   ' \
             '/MediaBox [ 0 0 1 1 ]\n   /Contents 3 0 R\n   /Group <<\n      /Type /Group\n      /S /Transparency\n      /I true\n    ' \
             '  /CS /DeviceRGB\n   >>\n   /Resources 2 0 R\n>>\nendobj\n5 0 obj\n<< /Length 8 0 R\n   /Filter /FlateDecode\n   /Type /' \
             'XObject\n   /Subtype /Form\n   /BBox [ 0 0 1 1 ]\n   /Group <<\n      /Type /Group\n      /S /Transparency\n      /I tru' \
             'e\n      /CS /DeviceRGB\n   >>\n   /Resources 7 0 R\n>>\nstream\nx\x9c+\xe4*\xe4\xd2O4PH/V\xd0\xaf\xb0Tp\xc9\xe7\n\x04B' \
             '\x00@4\x05D\nendstream\nendobj\n8 0 obj\n   28\nendobj\n7 0 obj\n<<\n   /ExtGState <<\n      /a0 << /CA 1 /ca 1 >>\n   >>' \
             '\n   /XObject << /x9 9 0 R >>\n>>\nendobj\n9 0 obj\n<< /Length 10 0 R\n   /Filter /FlateDecode\n   /Type /XObject\n   /Su' \
             'btype /Image\n   /Width 1\n   /Height 1\n   /ColorSpace /DeviceRGB\n   /Interpolate true\n   /BitsPerComponent 8\n>>\nst' \
             'ream\nx\x9cc\xfd\xcf\x00\x00\x02\x10\x01\x05\nendstream\nendobj\n10 0 obj\n   11\nendobj\n1 0 obj\n<< /Type /Pages\n   /K' \
             'ids [ 6 0 R ]\n   /Count 1\n>>\nendobj\n11 0 obj\n<< /Creator (cairo 1.12.16 (http://cairographics.org))\n   /Producer (c' \
             'airo 1.12.16 (http://cairographics.org))\n>>\nendobj\n12 0 obj\n<< /Type /Catalog\n   /Pages 1 0 R\n>>\nendobj\nxref\n0 1' \
             '3\n0000000000 65535 f \n0000001093 00000 n \n0000000141 00000 n \n0000000015 00000 n \n0000000120 00000 n \n0000000451 00' \
             '000 n \n0000000241 00000 n \n0000000750 00000 n \n0000000729 00000 n \n0000000850 00000 n \n0000001071 00000 n \n00000011' \
             '58 00000 n \n0000001288 00000 n \ntrailer\n<< /Size 13\n   /Root 12 0 R\n   /Info 11 0 R\n>>\nstartxref\n1341\n%%EOF\n'),

            (".mp4",
             'eJxjYGCQSCupLMgtMDFi1GKoA9GZxfm5DAwMHGlFqakMDIxTc1MSS4D8itSOBgeG7Px/369sP7Ppg4LSNu4V3xdlej9Ydyd8zvXNN689/yjWZmc9+VN0yWw58V'
             'WZiV0l17J0b25qOXzmzdPVzI16r9PPPP//ffJNZ9V/7g9lglLX/v1SHsez+sy0b28fb8iMjZ78cJ/i2ztdHsvsM+3kzrnMCjhYKcGk+nAC0G4mTgMgaeY4i4n3'
             'k/QLtiyGhgXX7q9R/PfVhyvorfk0TuWp/6fGX728yL/lkN+Vpc36Kz33TbDSeXx8tu63ffPB+gOAJD/jPBbWi2xm/2/cs/9yIfYAigQnugTIRj7HWSyy8Wocpt'
             'v/3VoWKQjXwO04j010mcK5+ww8OxCCjPM4BG8CTWEQMkARlFzm2LsfJggi+R1ncWhcumggAAxNVHMZ53EpIquGCaoiBBm5GBiY7XLz88uAnJzcsowUIM1woTsR'
             'jBkY4ydAMAMIIQAKB5PvwIAXMAHRqZKixGwgO6YkG2wnO9xOmGkge9EBMfaCvAXWyZSWm5IJMlAhNwXNXwwMPCAsehyszSQjJacIZkZZZkoqsplhQH6+gm8q0C'
             'gFj8S8lJxUkFImrtzMvDQgQ6QsF2w2sktUUiByMilFqWlILuUpLcpRgLAZTxWXJOUA2YuKS4pTkNRMSixLNsThW5DfJjB4AGkPmAouxzBnBed8oIXpGIrBQOL/'
             'fyBpAzTVmTHFQeT/QwaV9BQGkTU6SwytGYN4eHgagAmAAUjwFDiwX2BW/HGcPcNjWgQjA2vG6+IgUIqRKC4pKUb2BZROSEaIc0HFYJiZARzLcD0syPL//4PdxI'
             'gkj6IeKm8CDJlkqBgzVB0rlGZCMpMZSd4FqKcKyfcgt9YwQBKGJBRLALEoEpZEYoPMlykuSc5Hs'
             'lcDaLQeELcB2SJA85HDghEAcQD9FQ=='.decode("base64").decode("zlib")), #AFL's small_movie.mp4
        ]
        # TODO everybody: let me know if any other exiftool features would make sense...
        # TODO feature: Use exiftool to create video files, eg. has support for R/W for M4A, M4B, M4P, M4V
        # TODO feature: Use exiftool to create video files, eg. has support for R/W for MOV, QT
        # TODO feature: Use exiftool to create other files, eg. has support for R/W for EPS, EPSF, PS
        self.exiftool_techniques = [
            # Those that don't work because none of the formats will have the payload in them after creation:
            # ("exifcomment", "-exif:comment=", []),
            # ("exifkeywords", "-exif:keywords=", []),
            # ("iptccomment", "-iptc:comment=", []),
            # ("xmpcomment", "-xmp:comment=", []),
            # ("trailer", "-trailer=", []),
            # ("photoshop_irb", "-photoshop=", []),
            # ("iccprofile", "-ICC_Profile<='", []),
            # ("miesubfiledirectory", "-mie:SubfileDirectory=", []),

            # All these below here work
            # for gif -keywords= is the same as -xmp:keywords=
            # for jpeg and tiff -keywords= is the same as -iptc:keywords=

            ("keywords", "-keywords=", [".pdf", ".mp4" ]),
            ("comment", "-comment=", [".gif", ".jpeg", ".png"]),

            ("iptckeywords", "-iptc:keywords=", [".jpeg", ".tiff"]),
            ("xmpkeywords", "-xmp:keywords=", [".gif", ".jpeg", ".pdf", ".png", ".tiff", ".mp4"]),
            ("exifImageDescription", "-exif:ImageDescription=", [".jpeg", ".tiff"]),

            # These two were only commented out because I don't think there is any use of doing all these,
            # as they are combined with all file extensions, mime types, which is always a combinatoric explosion
            # so we rather don't have too many techniques.
            # But they work:
            # ("gpsareainformation", "-gps:GPSAreaInformation=", [".jpeg", ".tiff"]),
            # ("makernotes", "-makernotes=", [".jpeg", ".tiff"]),

            ("thumbnailWithIptckeywords", "-ThumbnailImage<=", [".jpeg"]),
        ]

        self.exiftool_techniques_thumbnail = ("thumbnailWithIptckeywords", "iccprofile")
        self.exiftool_techniques_thumbnail_file = ("iptckeywords", ".jpeg")
        self.placeholder_char = "X"
        self._exiftool_works = False
        self._checked_for_exiftool = False


    def create_zip(self, files):
        if not files:
            return None
        zipcontent = BytesIO()
        # ZIP_DEFLATED could be done too, but what for?
        # in most our exploitation scenarios ZIP_STORED perfectly fits the use case
        # as the payload will be 1:1 preserved in the zip file
        zip_file = zipfile.ZipFile(zipcontent, "w", zipfile.ZIP_STORED)
        cur_char = "0"
        placeholder_to_filename_mapping = {}
        for filename, filecontent in files:
            # The python manual specifies:
            # Note: If arcname (or filename, if arcname is not given) contains a null byte, the name of the file in the archive will be truncated at the null byte.
            # Tests show that this applies for zipfile.write and zipfile.writestr
            # However, we don't want that. Therefore if it actually has a zero byte
            # we first create the zip file with placeholders and then replace it again in the....
            filename_placeholder = filename
            if "\x00" in filename:
                # Note that we have the same problem again, eg. if the filename was only of length 1
                # this results in a short placeholder that is not unique and might therefore destroy
                # the content later on. Warn and not include this file then.
                if len(filename) < 5:
                    print("WARNING: The zip file filename", repr(filename), "is too short and includes a null byte.")
                    print("WARNING: This is not supported by the create_zip function. Skipping this file, it will not be " \
                          "included in the created zip file.")
                    continue
                filename_placeholder = cur_char * len(filename)
                placeholder_to_filename_mapping[filename_placeholder] = filename
                cur_char = chr(ord(cur_char) + 1)
            zip_file.writestr(filename_placeholder, filecontent)
        zip_file.close()
        zipcontent.seek(0)
        c = zipcontent.read()
        zipcontent.close()
        for placeholder in placeholder_to_filename_mapping:
            # ...final file.
            c = c.replace(placeholder, placeholder_to_filename_mapping[placeholder])
        return c

    def run_command(self, command):
        # print(" ".join(command))
        # os.devnull also works on Windows
        se = file(os.devnull, "w")
        so = file(os.devnull, "w")
        process = subprocess.Popen(command, stdout=so, stderr=se, shell=False)
        # Debugging:
        # process = subprocess.Popen(command, stdout=file("/tmp/stdout-test", "w"), stderr=file("/tmp/stderr-test", "w"), shell=False, close_fds=True)
        # process = subprocess.Popen(command, shell=False, close_fds=True)
        #process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
        #print(process.stderr.read())
        #print(process.stdout.read())
        process.communicate()  # blocking call
        se.close()
        so.close()
        return process.returncode

    def exiftool_present(self):
        if self._checked_for_exiftool:
            return self._exiftool_works
        self._checked_for_exiftool = True

        if not re.match('^[a-zA-Z0-9 .:/_\\\-]+$', self._tool) or len(self._tool) < 3:
            # The exiftool binary name can only consist of alphanumeric characters, space and . : / \ - _
            self._exiftool_works = False
            return self._exiftool_works
        elif self._tool.startswith("/") and not os.path.isfile(self._tool):
            # Linux/macOS absolute path, but file does not exist
            self._exiftool_works = False
            return self._exiftool_works
        elif re.match('^[a-zA-Z]{1}:', self._tool) and not os.path.isfile(self._tool):
            # Windows absolute path, but file does not exist
            self._exiftool_works = False
            return self._exiftool_works
        else:
            try:
                pipe = subprocess.PIPE
                proc = subprocess.Popen([self._tool, "BOWcSqVenrEcp-non-existent-file.jpg"], shell=False, stdout=pipe, stderr=pipe)
                proc.wait()
                err = proc.stderr.read()
                if "File not found:" in err:
                    self._exiftool_works = True
                else:
                    self._exiftool_works = False
            except Exception:
                self._exiftool_works = False
        return self._exiftool_works

    def get_zip_files(self, payload_func, techniques=None):
        if not techniques or "content" in techniques:
            payload, expect = payload_func()
            yield payload, expect, "ZipFileContent", ".zip", self.create_zip([("text.txt", payload), ])
        if not techniques or "name" in techniques:
            payload, expect = payload_func()
            yield payload, expect, "ZipFileName", ".zip", self.create_zip([(payload, "filecontent"), ])

    def get_files(self, size, payload_func, formats=None):
        # Sanity check to see if programmer didn't pass a payload_func, that includes MARKER_COLLAB_URL
        payload, _ = payload_func()
        if Constants.MARKER_COLLAB_URL in payload:
            print("Warning:", Constants.MARKER_COLLAB_URL, "found in payload for BackdooredFile, " \
                  "but this payload can not be altered after it is injected into a binary file format! Payload:", repr(payload))

        # The formats parameter specifies the formats the *module* wants to send
        # The self._enabled_formats specifies the user enabled in the UI
        # Make sure we only take the intersection between what the module wants and what is enabled in the UI
        if formats:
            formats = set(formats) & set(self._enabled_formats)
        else:
            formats = self._enabled_formats
        # .zip stuff
        if ".zip" in formats:
            for payload, expect, name, ext, c in self.get_zip_files(payload_func):
                yield payload, expect, name, ext, c
        # Exiftool stuff
        for payload, expect, name, ext, c in self.get_exiftool_images(payload_func, size, formats):
            yield payload, expect, name, ext, c

    def get_exiftool_images(self, payload_func, size, formats, techniques=None):
        # with a payload placeholder of the same length we make sure that we won't have
        # any encoding issues on the command line with exiftool. We replace it later
        # with the actual payload. This is fine as long as we handle metadata
        # AFAIK there is no format that does checksums over metadata,
        # but remember, PNG does over IDAT chunks, but we're fine as long as we don't touch IDAT
        if not self.exiftool_present():
            return
        if not techniques:
            techniques = self.exiftool_techniques
        thumb_fd, thumb_path = tempfile.mkstemp(suffix=self.exiftool_techniques_thumbnail_file[1])
        os.close(thumb_fd)
        for ext, content in self.inputs:
            # first, figure out if the caller wants this format (eg. .pdf) at all
            if formats and ext not in formats:
                continue
            # then resize the images
            # TODO feature: Is there a possibility that we could maybe resize a picture first,
            # then convert it to a PDF so the PDF has the right size?
            # If not: use a larger default pdf
            if not ext == ".pdf" and not ext == ".mp4":
                x = ImageHelpers.new_image(size[0], size[1], ext[1:])
                if x:
                    content = x
                else:
                    w = "Warning: ImageIO was not able to resize image of type '" + ext + "', using non-resized image "
                    w += "(tiff image support is supposed to be coming in JDK 1.9)"
                    print(w)

            # first handle the exiftool_techniques
            m, input_path = tempfile.mkstemp(suffix=ext)
            os.close(m)
            f = file(input_path, "wb")
            f.write(content)
            f.flush()
            f.close()
            # print("content", repr(content))
            for name, cmd_args, supported_types in techniques:
                if ext in supported_types:
                    cmd = [self._tool, ]
                    payload, expect = payload_func()
                    if len(payload) < BackdooredFile.MINIMUM_PAYLOAD_LENGTH:
                        print("Warning: Can not produce payloads with size smaller than {}, as the placeholder " \
                              "for exiftool would not be unique enough".format(BackdooredFile.MINIMUM_PAYLOAD_LENGTH))
                        print("Warning: Not creating such files")
                        return
                    payload_placeholder = self.placeholder_char * len(payload)
                    if name in self.exiftool_techniques_thumbnail:
                        cmd.append(cmd_args + thumb_path)
                    else:
                        cmd.append(cmd_args + payload_placeholder)
                    # cmd.append("-v")
                    cmd.append("-o")
                    m, output_path = tempfile.mkstemp(suffix=ext)
                    os.close(m)
                    try:
                        os.remove(output_path)
                    except OSError:
                        # Only happens on Windows usually but works anyway
                        pass
                    cmd.append(output_path)
                    cmd.append(input_path)
                    # print("output file exists:", os.path.isfile(output_path))
                    # print("input file exists:", os.path.isfile(input_path))
                    # print("input file contents:", repr(file(input_path, "rb").read()))
                    self.run_command(cmd)
                    if os.path.isfile(output_path):
                        new_content = file(output_path, "rb").read()
                        try:
                            os.remove(output_path)
                        except OSError:
                            # Only happens on Windows usually but works anyway
                            pass
                        if name == self.exiftool_techniques_thumbnail_file[0] and ext == \
                                self.exiftool_techniques_thumbnail_file[1]:
                            # save thumbnail we need later for thumbnail
                            # this little hack works as long as payload_func always
                            # returns the same length of payload. Otherwise that might
                            # not work as we might only have 5 char placeholder in the thumbnail
                            # but need 6 for the next payload or such...
                            f = file(thumb_path, "wb")
                            f.write(new_content)
                            f.flush()
                            f.close()
                        if name in self.exiftool_techniques_thumbnail:
                            # If we created a file with a thumbnail and the thumbnail has a metadata field with the payload,
                            # why not just replace the entire thumbnail image with the payload as well?
                            # Imagine if a software parses the thumbnail image and is vulnerable to ghostscript or something
                            thumbnail_image_cont = file(thumb_path, "r").read()
                            if thumbnail_image_cont in new_content:
                                if len(payload) < len(thumbnail_image_cont):
                                    padding = len(thumbnail_image_cont) - len(payload)
                                    padded_payload = payload + " " * padding
                                    c = new_content.replace(thumbnail_image_cont, padded_payload)
                                    if payload in c:
                                        yield payload, expect, "Pa" + name, ext, c
                        if payload_placeholder in new_content:
                            c = new_content.replace(payload_placeholder, payload)
                            if payload in c:
                                # print("Successfully produced image file with payload in the following metadata:", name, ext)
                                yield payload, expect, name, ext, c
                        else:
                            print("Warning: Payload missing. IPTC:Keywords has length limit of 64. " \
                                  "Technique: {}, File type: {}, Payload length: {}, Payload start: {}" \
                                  "".format(name, ext, len(payload_placeholder), repr(payload[:100])))
                            # print("Content:", repr(new_content))
                    else:
                        print("Error: The following image could not be created (exiftool didn't create a file):", name, ext)
            try:
                os.remove(input_path)
            except OSError:
                # Only happens on Windows usually but works anyway
                pass
            # handle the special cases last
            # TODO feature: test if this works with ImageIO from Java 1.9
            # If the 86 spaces are still in the tiff format when resized with ImageIO
            # yield one file with those spaces replaced, but only if the payload length is smaller than those spaces
            # we do this last, so if this does not apply, it interferes less with the implementation in InsertionPointProviderForActiveScan
            if ext == ".tiff" and " " * 86 in content:
                payload, expect = payload_func()
                if len(payload) <= 86:
                    p = payload + " " * (86 - len(payload))
                    c = content.replace(" " * 86, p)
                    yield payload, expect, "tiffFilepath", ext, c
        try:
            os.remove(thumb_path)
        except OSError:
            # Only happens on Windows usually but works anyway
            pass