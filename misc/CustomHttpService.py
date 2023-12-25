from helpers.FloydsHelpers import FloydsHelpers
from burp import IHttpService
import urlparse

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
