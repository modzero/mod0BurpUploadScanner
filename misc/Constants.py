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
