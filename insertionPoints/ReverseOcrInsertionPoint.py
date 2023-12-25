from burp import IScannerInsertionPoint

# Java stdlib imports
from java.awt import Color
from java.awt import Font
from java.awt import Image
from java.awt import RenderingHints
from java.awt.image import BufferedImage
from java.io import ByteArrayOutputStream
from javax.imageio import ImageIO

from helpers.FloydsHelpers import FloydsHelpers

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
