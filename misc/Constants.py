import random
import re
import string


class Constants ():
    MARKER_ORIG_EXT = 'ORIG_EXT'
    # Internal constants/read-only:
    DOWNLOAD_ME = "Dwld"
    MARKER_URL_CONTENT = "A_FILENAME_PLACEHOLDER_FOR_THE_DESCRIPTION_NeVeR_OcCuRs_iN_ReAl_WoRlD_DaTa"
    MARKER_COLLAB_URL = "http://example.org/"
    MARKER_CACHE_DEFEAT_URL = "https://example.org/cachedefeat/"
    NEWLINE = "\r\n"
    REGEX_PASSWD = re.compile("[^:]{3,20}:[^:]{1,100}:\d{0,20}:\d{0,20}:[^:]{0,100}:[^:]{0,100}:[^:]*$")
    # TODO: If we just add \\ the extension uploads *a lot more* files... worth doing?
    PROTOCOLS_HTTP = (
        # 'ftp://',
        # 'smtp://',
        # 'mailto://',
        # The following is \\ for Windows servers...
        # '\\\\',
        'http://',
        'https://',
    )
    MAX_SERIALIZED_DOWNLOAD_MATCHERS = 500
    MAX_RESPONSE_SIZE = 300000  # 300kb

    # ReDownloader constants/read-only:
    REDL_URL_BAD_HEADERS = ("content-length:", "accept:", "content-type:", "referer:")
    REDL_FILENAME_MARKER = "${FILENAME}"
    PYTHON_STR_MARKER_START = "${PYTHONSTR:"
    PYTHON_STR_MARKER_END = "}"
    TEXTFIELD_SIZE = 20
    FILE_START = None

    # Internal vars fuzzer (read only)
    KNOWN_FUZZ_STRINGS = [
            "A" * 256,
            "A" * 1024,
            "A" * 4096,
            "A" * 20000,
            "A" * 65535,
            "%x" * 256,
            "%n" * 256,
            "%s" * 256,
            "%s%n%x%d" * 256,
            "%s" * 256,
            "%.1024d",
            "%.2048d",
            "%.4096d",
            "%.8200d",
            "%99999999999s",
            "%99999999999d",
            "%99999999999x",
            "%99999999999n",
            "%99999999999s" * 200,
            "%99999999999d" * 200,
            "%99999999999x" * 200,
            "%99999999999n" * 200,
            "%08x" * 100,
            "%%20s" * 200,
            "%%20x" * 200,
            "%%20n" * 200,
            "%%20d" * 200,
            "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x",
            "'",
            "\\",
            "<",
            "+",
            "%",
            "$",
            "`"
        ]

    # End internal vars

    # The "*_types" variables define which prefix, file extension
    # and mime type is sent for the tests:
    # prefix, file extension, mime type
    # empty prefix = don't use prefix in front of filename
    # empty file extension = don't use/cut the filename's file extension
    # file extension == _magick_original_extension, don't change whatever was there
    # empty mime type = use default mime type found in the original base request

    # The different extensions can vary in several ways:
    # - the original extension the file had that was uploaded in the base request, _marker_orig_ext, eg. .png
    # - the payload extension, for example if we upload php code it would be .php
    # - the real file extension, for example .gif if we produced a gif file that has php code in the comment

    # TODO feature: Go through all TYPES and decide if .ORIG%00.EVIL makes sense as well as .EVIL%00.ORIG
    # TODO feature: Additionally: maybe randomize casing, eg. .PdF?
    # TODO feature: Reasoning about what _TYPES we should use. Make a big table that show what combinations we
    # can send and which checks on the server side could be present. For each combination, note if the upload
    # would succeed. Then rate the server side checks for likelihood to be implemented on a server (biased). In
    # a next step, take real world samples and check manually to confirm rough likelihood... There are so many
    # factors:
    # CT whitelist (often in place)
    # EXT whitelist (often in place but surprisingly often not as well...)
    # CONTENT whitelist (eg. is it a PNG?)
    #  CONTENT transformation (convert PNG to PNG with software X)
    # Checks CT matches EXT -> I get the impression this is rarely done
    # Checks CT matches CONTENT -> I get the impression this is rarely done
    # Checks EXT matches CONTENT
    # etc.

    # The following var is a special case when we detect that the request doesn't include
    # the filename or content-type (e.g. Vimeo image avatar upload), so we don't do 30
    # identical requests with the exact same content. See the get_types function.
    NO_TYPES = {'', '', ''}

    # ImageTragick types
    IM_SVG_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', '', 'image/png'),
        ('', '.svg', 'image/svg+xml'),
        # ('', '.svg', 'text/xml'),
        ('', '.png', 'image/png'),
        # ('', '.jpeg', 'image/jpeg')
    }

    # Interesting fact: image/jpeg is not the only jpeg mime type sent by browsers::
    # image/pjpeg
    # image/x-citrix-pjpeg
    # And also:
    # image/x-citrix-gif

    IM_MVG_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', '', 'image/png'),
        ('', '.mvg', ''),
        ('', '.mvg', 'image/svg+xml'),
        ('', '.png', 'image/png'),
        # ('', '.jpeg', 'image/jpeg'),
        ('mvg:', '.mvg', ''),
        # ('mvg:', '.mvg', 'image/svg+xml'),
    }

    # Xbm black/white pictures
    XBM_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', '.xbm', ''),
        ('', '.xbm', 'image/x-xbm'),
        ('', '.xbm', 'image/png'),
        ('xbm:', MARKER_ORIG_EXT, ''),
    }

    # Ghostscript types
    GS_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', '.gs', ''),
        ('', '.eps', ''),
        ('', MARKER_ORIG_EXT, 'text/plain'),
        ('', '.jpeg', 'image/jpeg'),
        ('', '.png', 'image/png'),
    }

    # LibAvFormat types
    AV_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'audio/mpegurl'),
        ('', MARKER_ORIG_EXT, 'video/x-msvideo'),
        # ('', '.m3u8', 'application/vnd.apple.mpegurl'),
        ('', '.m3u8', 'application/mpegurl'),
        # ('', '.m3u8', 'application/x-mpegurl'),
        ('', '.m3u8', 'audio/mpegurl'),
        # ('', '.m3u8', 'audio/x-mpegurl'),
        ('', '.avi', 'video/x-msvideo'),
        ('', '.avi', ''),
    }

    EICAR_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', '.exe', ''),
        ('', '.exe', 'application/x-msdownload'),
        # ('', '.exe', 'application/octet-stream'),
        # ('', '.exe', 'application/exe'),
        # ('', '.exe', 'application/x-exe'),
        # ('', '.exe', 'application/dos-exe'),
        # ('', '.exe', 'application/msdos-windows'),
        # ('', '.exe', 'application/x-msdos-program'),
        ('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'application/x-msdownload'),
        # ('', _magick_original_extension, 'application/octet-stream'),
        # ('', _magick_original_extension, 'application/exe'),
        # ('', _magick_original_extension, 'application/x-exe'),
        # ('', _magick_original_extension, 'application/dos-exe'),
        # ('', _magick_original_extension, 'application/msdos-windows'),
        # ('', _magick_original_extension, 'application/x-msdos-program'),
    }

    PL_TYPES = {
        #('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'text/x-perl-script'),
        ('', '.pl', ''),
        ('', '.pl', 'text/x-perl-script'),
        ('', '.cgi', ''),
        #('', '.cgi', 'text/x-perl-script'),
    }

    PY_TYPES = {
        #('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'text/x-python-script'),
        ('', '.py', ''),
        ('', '.py', 'text/x-python-script'),
        ('', '.cgi', '')
    }

    RB_TYPES = {
        #('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'text/x-ruby-script'),
        ('', '.rb', ''),
        ('', '.rb', 'text/x-ruby-script'),
    }

    # .htaccess types
    HTACCESS_TYPES = {
        ('', '', ''),
        ('', '%00' + MARKER_ORIG_EXT, ''),
        ('', '\x00' + MARKER_ORIG_EXT, ''),
        ('', '', 'text/plain'),
        ('', '%00' + MARKER_ORIG_EXT, 'text/plain'),
        ('', '\x00' + MARKER_ORIG_EXT, 'text/plain'),
    }

    PDF_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'application/pdf'),
        ('', '.pdf', ''),
        ('', '.pdf', 'application/pdf'),
    }

    URL_TYPES = {
        #('', MARKER_ORIG_EXT, ''),
        #('', MARKER_ORIG_EXT, 'application/octet-stream'),
        ('', '.URL', ''),
        #('', '.URL', 'application/octet-stream'),
    }

    INI_TYPES = {
        #('', MARKER_ORIG_EXT, ''),
        #('', MARKER_ORIG_EXT, 'application/octet-stream'),
        ('', '.ini', ''),
        #('', '.URL', 'application/octet-stream'),
    }

    ZIP_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', MARKER_ORIG_EXT, 'application/zip'),
        ('', '.zip', ''),
        ('', '.zip', 'application/zip'),
    }

    CSV_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', '.csv', ''),
        ('', '.csv', 'text/csv'),
        # ('', _marker_orig_ext, ''),
        # ('', _marker_orig_ext, 'text/csv'),
    }

    EXCEL_TYPES = {
        # ('', '', ''),
        ('', MARKER_ORIG_EXT, ''),
        ('', '.xls', ''),
        ('', '.xls', 'application/vnd.ms-excel'),
        # ('', MARKER_ORIG_EXT, ''),
        # ('', MARKER_ORIG_EXT, 'text/application/vnd.ms-excel'),
    }

    IQY_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', '.iqy', ''),
        ('', '.iqy', 'application/vnd.ms-excel'),
    }

    # Server Side Include types
    # See also what file extensions the .htaccess module would enable!
    # It is unlikely that a server accepts content type text/html...
    SSI_TYPES = {
        #('', '.shtml', 'text/plain'),
        ('', '.shtml', 'text/html'),
        #('', '.stm', 'text/html'),
        #('', '.shtm', 'text/html'),
        #('', '.html', 'text/html'),
        #('', MARKER_ORIG_EXT, 'text/html'),
        ('', '.shtml', ''),
        ('', '.stm', ''),
        ('', '.shtm', ''),
        ('', '.html', ''),
        ('', MARKER_ORIG_EXT, ''),
    }

    ESI_TYPES = {
        ('', '.txt', 'text/plain'),
        #('', '.txt', ''),
        ('', MARKER_ORIG_EXT, ''),
    }

    SVG_TYPES = {
        ('', MARKER_ORIG_EXT, ''), # Server doesn't check file contents
        ('', '.svg', 'image/svg+xml'), # Server enforces matching of file ext and content type
        ('', '.svg', ''), # Server doesn't check file ext
        ('', MARKER_ORIG_EXT, 'image/svg+xml'), # Server doesn't check content-type
    }

    XML_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', '.xml', 'application/xml'),
        ('', '.xml', 'text/xml'),
        #('', '.xml', 'text/plain'),
        ('', '.xml', ''),
        ('', MARKER_ORIG_EXT, 'text/xml'),
    }

    SWF_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', '.swf', 'application/x-shockwave-flash'),
        ('', '.swf', ''),
        ('', MARKER_ORIG_EXT, 'application/x-shockwave-flash'),
    }

    HTML_TYPES = {
        ('', MARKER_ORIG_EXT, ''),
        ('', '.htm', ''),
        ('', '.html', ''),
        ('', '.htm', 'text/html'),
        #('', '.html', 'text/html'),
        ('', '.html', 'text/plain'),
        ('', '.xhtml', ''),
        #('', MARKER_ORIG_EXT, 'text/html'),
    }
