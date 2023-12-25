from helpers.FloydsHelpers import FloydsHelpers
from misc.Constants import Constants
import threading
from misc.CustomScanIssue import CustomScanIssue
import urlparse  # urlparser for custom HTTP services

import urllib


class DownloadMatcherCollection(object):
    # TODO feature: Due to memory consumption we do not add any upload/preflight requests to the issue as we need to keep them in
    # memory forever. We hope the original brr is kept as a reference rather than a copy in memory so not using
    # too much memory. However, the upload request for each file would be a lot different and would use a lot more
    # memory. I think this is a sane choice, but I haven't tested it.
    # Another problem there: We try to keep the amount of DownloadMatcher as small as possible by putting
    # them in a set and removing duplicates. Therefore several upload requests associate with *one* DownloadMatcher
    # therefore we can not simply match a DownloadMatcher to one upload request...
    # Working with self._callbacks.saveBuffersToTempFiles is therefore not an option
    # In Burp these original request are sometimes recreated from the payloads. However, in our case the
    # payloads are file contents, so again a lot of data we don't want to keep in memory.
    # Not keeping in memory for now.
    def __init__(self, helpers):
        self._collection = {}
        self._scope_mapping = {}
        self._global_matchers = set()
        self._helpers = helpers
        self._create_globals()
        self._thread_lock = threading.Lock()

    def add(self, dl_matcher):
        brr = dl_matcher.issue.get_base_request_response()
        iRequestInfo = self._helpers.analyzeRequest(brr)
        if iRequestInfo.getUrl():
            url = FloydsHelpers.u2s(iRequestInfo.getUrl().toString())
            host = self.add_collection(url)
            with self._thread_lock:
                self._collection[host].add(dl_matcher)

    def add_collection(self, url):
        host = self._get_host(url)
        with self._thread_lock:
            if host not in self._collection:
                print("The DownloadMatcherCollection has now passive checks (at least the global matchers) for", host)
                self._collection[host] = set()
        return host

    def _create_globals(self):
        title = "GraphicsMagick version leakage"
        desc = 'The server leaks the GraphicsMagick version used to convert uploaded pictures. Usually it will also ' \
               'leak the temporary path where the file was converted (usually /tmp/gmRANDOM).<br><br>This often ' \
               'happens with tiff files.<br><br>If you uploaded pictures that you processed with GraphicsMagick, ' \
               'make sure this is not a false positive of you uploading such pictures. <br><br>'
        issue = CustomScanIssue([], self._helpers, title, desc, "Tentative", "Low")
        # eg. /tmp/gmi7JIsA GraphicsMagick 1.4 snapshot-20160531 Q8 http://www.GraphicsMagick.org/ with null bytes in it
        dl_matcher = DownloadMatcher(issue, filecontent="\x20http://www.GraphicsMagick.org/\x00")
        self._global_matchers.add(dl_matcher)

        title = "ImageMagick version leakage"
        desc = 'The server leaks the ImageMagick version used to convert uploaded pictures. Usually it will also leak' \
               'creation date, modification date and title (usually including path on server).<br><br>This often ' \
               'happens with pdf files.<br><br>If you uploaded pictures that you processed with ImageMagick yourself, ' \
               'make sure this is not a false positive of you uploading such pictures. <br><br>'
        issue = CustomScanIssue([], self._helpers, title, desc, "Tentative", "Low")
        # eg.:
        # <<
        # /Title (/var/www/uploads/1DwldMeBFRcexmpkeywordsPHP1IiN.phtml)
        # /CreationDate (D:20170707203121)
        # /ModDate (D:20170707203121)
        # /Producer (ImageMagick 6.5.4-10 2016-12-19 Q16 http://www.imagemagick.org)
        # >>
        dl_matcher = DownloadMatcher(issue, filecontent="/Producer (ImageMagick ")
        self._global_matchers.add(dl_matcher)

        title = "ImageMagick/GraphicksMagick without strip"
        desc = 'The server might convert pictures with ImageMagick or GraphicksMagick. It does not add the -strip command ' \
               'line option while doing that. Therefore the converted image has the plaintext tEXtdate:create in them. ' \
               'at least it was possible to download a file, that looks like it was processed by one of these tools.<br><br>' \
               'Usually also tEXtdate:modify and timestamps are included. This often happens with png files.<br><br>' \
               'If you uploaded pictures that you processed with ImageMagick/GraphicksMagick yourself, make sure this ' \
               'is not a false positive of you uploading such pictures. <br><br>'
        issue = CustomScanIssue([], self._helpers, title, desc, "Tentative", "Low")
        # eg. the following with null bytes in between:
        # #tEXtdate:create2018-02-28T16:17:47+00:00O%tEXtdate:modify2018-02-28T16:17:47+00:00>
        dl_matcher = DownloadMatcher(issue, filecontent="tEXtdate:create")
        self._global_matchers.add(dl_matcher)

    def with_global(self, name, matchers):
        g = set()
        g.update(matchers)
        for m in self._global_matchers:
            if not name in m.reported_for:
                if name in self._scope_mapping:
                    for alt_name in self._scope_mapping[name]:
                        if alt_name in m.reported_for:
                            break
                    else:
                        g.add(m)
                else:
                    g.add(m)
        return g

    def add_scope(self, brr_url, url):
        brr_host = self._get_host(brr_url)
        host = self._get_host(url)
        with self._thread_lock:
            if host in self._collection:
                return
            if brr_host not in self._scope_mapping:
                self._scope_mapping[brr_host] = set()
            if host not in self._scope_mapping[brr_host]:
                print("Scope is adding", repr(host), "as part of scope of", repr(brr_host))
                self._scope_mapping[brr_host].add(host)

    def get_matchers_for_url(self, url):
        hostport = self._get_host(url)
        if not hostport:
            print("Couldn't extract hostport from the url", url)
            return []
        with self._thread_lock:
            if hostport in self._collection:
                # print("Found DownloadMatchers", hostport, "that correspond to", url)
                return self.with_global(hostport, self._collection[hostport])

            name = self.get_scope(hostport)
            if name:
                # print("Found DownloadMatchers for", name, "that can be used for", url)
                return self.with_global(name, self._collection[name])
        return []

    def get_scope(self, hostport):
        for name in self._scope_mapping:
            if hostport in self._scope_mapping[name]:
                if name in self._collection:
                    return name

    def remove_reported(self, url, matcher):
        with self._thread_lock:
            hostport = self._get_host(url)
            if matcher in self._global_matchers:
                matcher.reported_for.append(hostport)
                return
            if hostport in self._collection:
                if matcher in self._collection[hostport]:
                    self._collection[hostport].remove(matcher)
                    return
            else:
                name = self.get_scope(hostport)
                if name and name in self._collection:
                    if matcher in self._collection[name]:
                        self._collection[name].remove(matcher)
                        return

    def _get_host(self, url):
        if not url:
            return None
        try:
            x = urlparse.urlparse(url)
        except ValueError:
            # Catch errors such as the one described on https://github.com/modzero/mod0BurpUploadScanner/issues/12
            return None
        return x.hostname

    def serialize(self):
        no_of_matchers = 0
        serialized_collection = {}
        for host in self._collection:
            serialized_collection[host] = []
            for matcher in self._collection[host]:
                # print("Serialization", host, type(matcher.serialize()), repr(matcher.serialize()))
                serialized_collection[host].append(matcher.serialize())
                no_of_matchers += 1
                if no_of_matchers >= Constants.MAX_SERIALIZED_DOWNLOAD_MATCHERS:
                    print("DownloadMatcher tried to serialize more than {} matchers, which at one point would " \
                          "slow done matching. Ignoring any further DownloadMatchers." \
                          "".format(Constants.MAX_SERIALIZED_DOWNLOAD_MATCHERS))
                    return serialized_collection, self._scope_mapping
        #print(type(serialized_collection), type(self._scope_mapping))
        return serialized_collection, self._scope_mapping

    def deserialize(self, serialized_object):
        no_of_matchers = 0
        serialized_collection, self._scope_mapping = serialized_object
        for host in serialized_collection:
            print("Deserializing DownloadMatchers for", host)
            self._collection[host] = set()
            for matcher in serialized_collection[host]:
                # print("Deserialization", host, type(matcher), repr(matcher))
                temp_matcher = DownloadMatcher(None)
                temp_matcher.deserialize(matcher)
                self._collection[host].add(temp_matcher)
                no_of_matchers += 1
        print("Deserialized {} DownloadMatchers. If you think this is too much, check option to delete settings " \
              "and reload extension. Anyway, if it grows more than {}, some are discarded for performance reasons." \
              "".format(no_of_matchers, Constants.MAX_SERIALIZED_DOWNLOAD_MATCHERS))


class DownloadMatcher(object):
    # For performance reasons the currently unused features are commented out
    def __init__(self, issue,
                 url_content=None, not_in_url_content=None,
                 filename_content_disposition=None, not_in_filename_content_disposition=None,
                 filecontent=None, not_in_filecontent=None,
                 content_type=None,  # not_in_content_type=None,
                 # check_content_disposition=False,
                 check_not_content_disposition=False,
                 check_xss=False,
                 ):
        self.issue = issue

        # Attention: filename url is only a request property!
        # This means this doesn't proof anything (eg. that a file can be downloaded)
        # but just that a request was sent that includes such a filename
        # Therefore this check *must* be combined with another check
        self.url_content = url_content
        self.not_in_url_content = not_in_url_content

        self.filename_content_disposition = filename_content_disposition
        self.not_in_filename_content_dispositon = not_in_filename_content_disposition

        self.filecontent = filecontent
        self.not_in_filecontent = not_in_filecontent

        self.content_type = content_type
        # self.not_in_content_type = not_in_content_type

        # self.check_content_disposition = check_content_disposition
        self.check_not_content_disposition = check_not_content_disposition

        self.check_xss = check_xss

        # My tests show, that Content-Disposition: attachment prevents XSS...
        # However, this is not an easy question to answer. It depends on browsers, browser plugins,
        # browser bugs, which filetypes can be uploaded, if you can achieve HTTP header injection, etc.
        # See https://markitzeroday.com/xss/bypass/2018/04/17/defeating-content-disposition.html
        # So this means it is not clearly non-exploitable.
        #if self.check_xss:
            # It can't be a content-disposition: attachment header (otherwise it's downloaded instead of executed)
        #    self.check_not_content_disposition = True
        # It must be the correct content-type:
        self.xss_content_types = ["text/", "application/javascript", "image/svg", "application/x-shockwave-flash"]
        # Additionally we could easily also check if X-Content-Type-Options: nosniff is set or not...

        self.content_type_header_marker = "content-type:"
        self.content_disposition_header_marker = "content-disposition: attachment"

        # Special case to keep track where global matchers were reported already
        self.reported_for = []

    def __hash__(self):
        return hash((self.issue.name,
                     self.issue.urlPy,
                     self.url_content,
                     self.not_in_url_content,
                     self.filename_content_disposition,
                     self.not_in_filename_content_dispositon,
                     self.filecontent,
                     self.not_in_filecontent,
                     self.content_type,
                     # self.not_in_content_type,
                     # self.check_content_disposition,
                     self.check_not_content_disposition,
                     self.check_xss))

    def get_header(self, headers, marker):
        for header in headers:
            if marker == header[:len(marker)].lower():
                return header

    def matches(self, url, headers, body):
        if self.url_content:
            if self.url_content not in url and urllib.quote(self.url_content) not in url:
                return False
        if self.not_in_url_content:
            if self.not_in_url_content in url or urllib.quote(self.not_in_url_content) in url:
                return False
        if self.filecontent and self.filecontent not in body:
            return False
        if self.not_in_filecontent and self.not_in_filecontent in body:
            return False

        if self.check_xss:  # or self.content_type or self.not_in_content_type:
            content_type_header = self.get_header(headers, self.content_type_header_marker)
            # if self.content_type:
            #    if not content_type_header or self.content_type not in content_type_header:
            #        return False
            # if self.not_in_content_type and content_type_header:
            #    if self.not_in_content_type in content_type_header:
            #        return False
            if content_type_header and self.check_xss:
                for c_type in self.xss_content_types:
                    if c_type in content_type_header.lower():
                        break
                else:
                    return False

        if self.filename_content_disposition or self.check_not_content_disposition or \
                self.not_in_filename_content_dispositon:  # or self.check_content_disposition:
            content_disposition_header = self.get_header(headers, self.content_disposition_header_marker)
            # if self.check_content_disposition and not content_disposition_header:
            #    return False
            if self.check_not_content_disposition and content_disposition_header:
                return False
            if self.filename_content_disposition:
                if not content_disposition_header or self.filename_content_disposition not in content_disposition_header:
                    return False
            if self.not_in_filename_content_dispositon and content_disposition_header:
                if self.not_in_filename_content_dispositon in content_disposition_header:
                    return False
        return True

    def serialize(self):
        # print([type(x) for x in (self.issue.serialize(), self.url_content, self.not_in_url_content, self.filename_content_disposition, \)
        #                          self.not_in_filename_content_dispositon, self.filecontent, self.content_type, \
        #                          self.check_not_content_disposition, self.check_xss, self.xss_content_types, \
        #                          self.content_type_header_marker, self.content_disposition_header_marker)]
        return self.issue.serialize(), self.url_content, self.not_in_url_content, self.filename_content_disposition,\
        self.not_in_filename_content_dispositon, self.filecontent, self.not_in_filecontent, self.content_type, \
        self.check_not_content_disposition, self.check_xss, self.xss_content_types, \
        self.content_type_header_marker, self.content_disposition_header_marker

    def deserialize(self, serialized_object):
        temp_issue = CustomScanIssue(None, None, None, None, None, None)
        issue, self.url_content, self.not_in_url_content, self.filename_content_disposition, \
        self.not_in_filename_content_dispositon, self.filecontent, self.not_in_filecontent, self.content_type, \
        self.check_not_content_disposition, self.check_xss, self.xss_content_types, \
        self.content_type_header_marker, self.content_disposition_header_marker = serialized_object
        temp_issue.deserialize(issue)
        self.issue = temp_issue

