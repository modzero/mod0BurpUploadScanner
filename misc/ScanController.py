from helpers.FloydsHelpers import FloydsHelpers
from misc.Constants import Constants
from misc.CustomHttpService import CustomHttpService
from misc.CustomRequestResponse import CustomRequestResponse
from misc.Misc import ScanMessageEditorController
from ui.OptionsPanel import OptionsPanel
# Java stdlib imports
from javax.swing import JLabel
from javax.swing import JScrollPane
from javax.swing import JButton
from javax.swing import JSplitPane
from javax.swing import JTextField
from javax.swing import JTabbedPane
from javax.swing import JPanel
from javax.swing.event import DocumentListener
from java.awt import GridBagLayout
from java.awt import GridBagConstraints

from burp import IMessageEditorController


class ScanController(JSplitPane, IMessageEditorController, DocumentListener):

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
        #    print(x + ":", type(serialized_object[x]),)
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
        self.tf_upload_req_service = JTextField(CustomHttpService.to_url(self.upload_req_service), Constants.TEXTFIELD_SIZE)
        self.tf_upload_req_service.getDocument().addDocumentListener(self)
        self.button_panel.add(self.tf_upload_req_service, self.gbc)

        self.gbc.gridy += 1
        self.gbc.gridx = 0

        self.lbl_preflight_req_service = JLabel("Preflight request target (TCP/IP/TLS):")
        self.button_panel.add(self.lbl_preflight_req_service, self.gbc)
        self.lbl_preflight_req_service.setVisible(False)
        self.gbc.gridx += 1
        self.tf_preflight_req_service = JTextField('', Constants.TEXTFIELD_SIZE)
        self.tf_preflight_req_service.getDocument().addDocumentListener(self)
        self.tf_preflight_req_service.setVisible(False)
        self.button_panel.add(self.tf_preflight_req_service, self.gbc)

        self.gbc.gridy += 1
        self.gbc.gridx = 0

        self.lbl_redownload_req_service = JLabel("Redownload request target (TCP/IP/TLS):")
        self.button_panel.add(self.lbl_redownload_req_service, self.gbc)
        self.lbl_redownload_req_service.setVisible(False)
        self.gbc.gridx += 1
        self.tf_redownload_req_service = JTextField('', Constants.TEXTFIELD_SIZE)
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
        except Exception as e:
            OptionsPanel.mark_misconfigured(self.lbl_upload_req_service)
        if self.lbl_preflight_req_service.isVisible():
            try:
                self.preflight_req_service = CustomHttpService(FloydsHelpers.u2s(self.tf_preflight_req_service.getText()))
                OptionsPanel.mark_configured(self.lbl_preflight_req_service)
            except Exception as e:
                OptionsPanel.mark_misconfigured(self.lbl_preflight_req_service)
        if self.lbl_redownload_req_service.isVisible():
            try:
                self.redownload_req_service = CustomHttpService(FloydsHelpers.u2s(self.tf_redownload_req_service.getText()))
                OptionsPanel.mark_configured(self.lbl_redownload_req_service)
            except Exception as e:
                OptionsPanel.mark_misconfigured(self.lbl_redownload_req_service)

    def update_brr_from_ui(self):
        service = self.upload_req_service
        request = self.upload_req_view.getMessage()
        response = self.upload_resp_view.getMessage()
        self.brr = CustomRequestResponse('', '', service, request, response)