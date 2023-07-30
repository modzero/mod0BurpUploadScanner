from burp import JTable, IMessageEditorController

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
