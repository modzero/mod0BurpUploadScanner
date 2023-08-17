# python stdlib imports
import os  # local paths parsing etc.
import pickle  # persisting object serialization between extension reloads
import random  # to chose randomly
import string  # ascii letters to chose random file name from
import sys  # to show detailed exception traces
import textwrap  # to wrap request texts after a certain amount of chars
import threading  # to make stuff thread safe
import traceback  # to show detailed exception traces
import urllib  # URL encode etc.

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IHttpListener
from burp import IScannerCheck
from burp import IScannerInsertionPoint
from burp import IScannerInsertionPointProvider
from burp import ITab

from java.awt import Desktop
from java.net import URI
from java.util import ArrayList
from javax.swing import JTabbedPane, JScrollPane, JLabel, JSplitPane, JMenuItem, JOptionPane
from javax.swing import SwingConstants
from javax.swing.table import AbstractTableModel

from checks.checks import Checks
from debuging.debug import DEBUG_MODE
from helpers.FloydsHelpers import FloydsHelpers
from injectors.FlexiInjector import FlexiInjector
from injectors.MultipartInjector import MultipartInjector
from insertionPoints.InsertionPointProviderForActiveScan import InsertionPointProviderForActiveScan
from misc.Constants import Constants
from misc.CustomHttpService import CustomHttpService
from misc.CustomRequestResponse import CustomRequestResponse
from misc.Downloader import DownloadMatcherCollection
from misc.Misc import CloseableTab
from misc.Misc import MenuItemAction
from misc.Misc import Readme
from misc.ScanController import ScanController
from ui.LogEntry import LogEntry
from ui.OptionsPanel import OptionsPanel
from ui.Table import Table

if DEBUG_MODE:
    # Hint: Module "gc" garbage collector is not fully implemented in Jython as it uses the Java garbage collector
    # see https://answers.launchpad.net/sikuli/+question/160893
    pass
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

        # A lock to make things thread safe that access extension level globals
        # Attention: use wisely! On MacOS it seems to be fine that a thread has the lock
        # and acquires it again, that's fine. However, on Windows acquiring the same lock
        # in the same thread twice will result in a thread lock and everything will halt!
        self.globals_write_lock = threading.Lock()

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

        self.checks = Checks(self)

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
        self.checks.extensionUnloaded()
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
        self.checks.do_checks(injector)