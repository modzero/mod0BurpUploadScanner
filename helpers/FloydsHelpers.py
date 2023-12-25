
import imghdr
import mimetypes
import os


class FloydsHelpers(object):
    @staticmethod
    def fix_content_length(headers, length, newline):
        h = list(headers.split(newline))
        for index, x in enumerate(h):
            if "content-length:" == x[:len("content-length:")].lower():
                h[index] = x[:len("content-length:")] + " " + str(length)
                return newline.join(h)
        else:
            print("WARNING: Couldn't find Content-Length header in request, simply adding this header")
            h.insert(1, "Content-Length: " + str(length))
            return newline.join(h)

    @staticmethod
    def file_extension(insertionPoint):
        base_value = insertionPoint.getBaseValue()
        if base_value:  # getBaseValue() returns None in rare cases
            return FloydsHelpers.u2s(os.path.splitext(base_value)[1])
        else:
            return ''

    @staticmethod
    def mime_type_from_ext(ext):
        return mimetypes.guess_type(ext, False)[0]

    @staticmethod
    def mime_type_from_content(filepath):
        type_extension = imghdr.what(filepath)
        # Problem here is that python's magic module is not in the standard libraries
        # if not type_extension:
        #     try:
        #         import magic
        #         mime = magic.Magic(mime=True)
        #         type_extension = mime.from_file(filepath)
        #     except:
        #         pass
        # So let's instead the new Java 7 probeContentType
        if not type_extension:
            java_type = Files.probeContentType(filepath)
            if java_type:
                type_extension = java_type
        return type_extension

    @staticmethod
    def file_extension_from_mime(mime_type):
        return FloydsHelpers.u2s(mimetypes.guess_extension(mime_type, False))

    @staticmethod
    def jb2ps(arr):
        """
        Turns Java byte arrays into Python str
        :param arr: [65, 65, 65]
        :return: 'AAA'
        """
        return ''.join(map(lambda x: chr(x % 256), arr))

    @staticmethod
    def ps2jb(arr):
        """
        Turns Python str into Java byte arrays
        :param arr: 'AAA'
        :return: [65, 65, 65]
        """
        return [ord(x) if ord(x) < 128 else ord(x) - 256 for x in arr]

    @staticmethod
    def u2s(uni):
        """
        Turns unicode into str/bytes. Burp might pass invalid Unicode (e.g. Intruder Bit Flipper).
        This seems to be the only way to say "give me the raw bytes"
        :param uni: u'https://example.org/invalid_unicode/\xc1'
        :return: 'https://example.org/invalid_unicode/\xc1'
        """
        if isinstance(uni, unicode):
            return uni.encode("iso-8859-1", "ignore")
        else:
            return uni

    @staticmethod
    def between_markers(content, start, end, with_markers=False):
        if not isinstance(content, str) or not isinstance(start, str) or not isinstance(end, str):
            print("Warning: Trying to find between_markers of type {} {} {}, " \
                  "which are: {} {} {}".format(type(content), type(start), type(end), content, start, end))
        if start and end and start in content and end in content:
            try:
                if with_markers:
                    start_index = content.index(start)
                    end_index = content.index(end, start_index + len(start)) + len(end)
                else:
                    start_index = content.index(start) + len(start)
                    end_index = content.index(end, start_index)
                if end_index:
                    return content[start_index:end_index]
            except ValueError:
                return ""
        return ""
