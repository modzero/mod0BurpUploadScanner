from helpers.FloydsHelpers import FloydsHelpers
from burp import IHttpRequestResponse

from misc.CustomHttpService import CustomHttpService

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
        # print(type(self.com), type(self.high), type(CustomHttpService.to_url(self.serv)), type(self.req), type(self.resp))
        return self.com, self.high, CustomHttpService.to_url(self.serv), FloydsHelpers.jb2ps(self.req), FloydsHelpers.jb2ps(self.resp)

    def deserialize(self, serialized_object):
        self.com, self.high, service_url, self.req, self.resp = serialized_object
        self.req = FloydsHelpers.ps2jb(self.req)
        self.resp = FloydsHelpers.ps2jb(self.resp)
        self.serv = CustomHttpService(service_url)