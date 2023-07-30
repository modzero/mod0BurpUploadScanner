
import sys
import traceback
from FlexiInjector import FlexiInjector
from misc.Misc import BackdooredFile
from UploadScanner import BurpExtender
from helpers.FloydsHelpers import FloydsHelpers
from insertionPoints.CsvInsertionPoint import CsvInsertionPoint
from insertionPoints.CustomMultipartInsertionPoint import CustomMultipartInsertionPoint
import MultipartInjector
from burp import IScannerInsertionPointProvider

from insertionPoints.InsertionPointForActiveScan import InsertionPointForActiveScan
from insertionPoints.ReverseOcrInsertionPoint import ReverseOcrInsertionPoint

class InsertionPointProviderForActiveScan(IScannerInsertionPointProvider):
    # This class is not needed in the UploadScanner except to provide InsertionPoints as a
    # IScannerInsertionPointProvider when getInsertionPoints is called from ActiveScan
    def __init__(self, extender=None, opts=None, helpers=None, injector=None):
        if injector:
            self.burp_extender = injector.opts._burp_extender
            self._opts = injector.opts
            self._helpers = injector._helpers
        else:
            self.burp_extender = extender
            self._opts = opts
            self._helpers = helpers
        self.exiftool_techniques = [
            # See BackdooredFiles for details... we don't use the thumbnail technique.
            ("keywords", "-keywords=", [".pdf", ".mp4" ]),
            ("comment", "-comment=", [".gif", ".jpeg", ".png"]),
            # We don't do iptckeywords as it's limited to 64 characters and ActiveScan will produce longer payloads
            # and there is a Burp limitation that we can not return a "sorry, can't produce a request with this long
            # payload"
            # ("iptckeywords", "-iptc:keywords=", [".jpeg", ".tiff"]),
            ("xmpkeywords", "-xmp:keywords=", [".gif", ".jpeg", ".pdf", ".png", ".tiff", ".mp4"]),
            ("exifImageDescription", "-exif:ImageDescription=", [".jpeg", ".tiff"]),
        ]

    # This is actually from IScannerInsertionPointProvider, but no multi inheritance
    def getInsertionPoints(self, base_request_response):
        insertion_points = []
        try:
            injector = None
            req = FloydsHelpers.jb2ps(base_request_response.getRequest())
            request_lower = req.lower()
            if "content-type: multipart/form-data" in request_lower and \
                    CustomMultipartInsertionPoint.FILENAME_MARKER in req:
                print("MultipartInjector insertion point found for getInsertionPoint ActiveScan!")
                insertionPoint = CustomMultipartInsertionPoint(self._helpers, BurpExtender.NEWLINE, req)
                injector = MultipartInjector(base_request_response, self._opts, insertionPoint, self._helpers, BurpExtender.NEWLINE)
            elif self._opts.fi_ofilename:
                fi = FlexiInjector(base_request_response, self._opts, self._helpers, BurpExtender.NEWLINE)
                # We test only those requests where we find at least the content in the request as some implementations
                # might not send the filename to the server
                if fi.get_uploaded_content():
                    print("FlexiInjector insertion point found for getInsertionPoint ActiveScan!")
                    injector = fi
            if injector:
                # First the feature that we can detect CSVs
                insertion_points.extend(self.get_csv_insertion_points(injector))
                
                # Insertion provider that puts payloads into the image as text, to pwn OCR software as in
                # https://medium.com/@vishwaraj101/ocr-to-xss-42720d85f7fa
                insertion_points.extend(self.get_inverse_ocr_insertion_points(injector))

                # Then handle the zip files
                bf = BackdooredFile(None, tool=self._opts.image_exiftool)
                upload_type = ('', ".zip", BackdooredFile.EXTENSION_TO_MIME[".zip"])
                # Achieve bf.get_zip_files(payload_func, techniques=["name"])
                args = []
                kwargs = {"techniques": ["name"]}
                function = bf.get_zip_files
                insertion_points.append(InsertionPointForActiveScan(injector, upload_type, function, args, kwargs))

                # Achieve bf.get_zip_files(payload_func, techniques=["content"])
                args = []
                kwargs = {"techniques": ["content"]}
                function = bf.get_zip_files
                insertion_points.append(InsertionPointForActiveScan(injector, upload_type, function, args, kwargs))

                for format in BackdooredFile.EXTENSION_TO_MIME.keys():
                    upload_type = ('', format, BackdooredFile.EXTENSION_TO_MIME[format])
                    # Now we still have the problem, that for a format, several payloads are generated
                    # so we can't really call create_files, but we need to call get_exiftool_images
                    # directly and tell it which techniques to use
                    size = (self._opts.image_width, self._opts.image_height)
                    for name, cmd_line_args, formats in self.exiftool_techniques:
                        if format in formats:
                            # Achieve bf.get_exiftool_images(payload_func, size, formats, techniques=None)
                            args = [size, [format, ]]
                            kwargs = {"techniques": [(name, cmd_line_args, [format, ]), ]}
                            function = bf.get_exiftool_images
                            insertion_points.append(InsertionPointForActiveScan(injector, upload_type, function, args, kwargs))
                # TODO: How about we also try to download the files we created InsertionPoints payloads for...?
        except:
            self.burp_extender.show_error_popup(traceback.format_exc(), "InsertionPointProviderForActiveScan.getInsertionPoints", base_request_response)
            raise sys.exc_info()[1], None, sys.exc_info()[2]
        return insertion_points

    def get_csv_insertion_points(self, injector):
        filename = injector.get_uploaded_filename().lower()
        insertion_points = []
        if ".csv" in filename or ".txt" in filename:
            file_content = injector.get_uploaded_content()
            if "\r\n" in file_content:
                new_line = "\r\n"
            else:
                new_line = "\n"
            lines = file_content.split(new_line)
            for delim in [",", ";", "\t"]:
                if delim in file_content:
                    # The first line in a CSV can be special (header)
                    # We choose it at the beginning, but prefer actually any other line in the CSV to inject
                    # We want to inject into the line with the most delimiters
                    line_index = 0
                    no_of_delim = 0
                    for i, line in enumerate(lines[1:]):
                        if line.count(delim) > no_of_delim:
                            line_index = i + 1
                            no_of_delim = line.count(delim)

                    # This might produce *a lot* of insertion points
                    for field_index in range(0, no_of_delim + 1):
                        insertion_points.append(CsvInsertionPoint(injector, new_line, delim, line_index, field_index))
        return insertion_points

    def get_inverse_ocr_insertion_points(self, injector):
        insertion_points = []
        for file_type in ["png", "jpeg"]:
            insertion_points.append(ReverseOcrInsertionPoint(injector, file_type))
        return insertion_points
