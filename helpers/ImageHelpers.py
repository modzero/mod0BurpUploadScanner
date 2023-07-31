import random

from helpers.FloydsHelpers import FloydsHelpers

from java.awt.image import BufferedImage
from java.io import ByteArrayOutputStream
from java.io import ByteArrayInputStream
from javax.imageio import ImageIO
from java.awt import Color

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
                    print("Exception in get_imageio, ImageIO seems to be able to read an image but not get a ImageReader for it")
            else:
                # print("Not a valid image in get_imageio")
                pass
        except Exception as e:
            print("Couldn't do get_imageio")
            print(e)
        return None, None

    @staticmethod
    def image_width_height(content):
        try:
            io, fileformat = ImageHelpers.get_imageio(content)
            if io:
                return io.getWidth(), io.getHeight(), fileformat
        except Exception as e:
            print("Couldn't do image_width_height")
            print(e)
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
                # print("Not a valid image in rescale_image")
                pass
        except Exception as e:
            print("Exception in rescale_image called with {} {} {}, but simply ignoring and going on".format(width, height, repr(content[:100])))
            print(e)
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
        except Exception as e:
            print("Exception in get_image_rgb_list called with {}, but simply ignoring and going on".format(repr(content[:100])))
            print(e)
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
        except Exception as e:
            print("Exception in get_image_from_rgb_list called with {}, but simply ignoring and going on".format(repr(rgbs[:100])))
            print(e)
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
        except Exception as e:
            print("Exception in is_grayscale called with {}, but simply ignoring and going on".format(repr(content[:100])))
            print(e)
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
        except Exception as e:
            print("Exception in new_image called with {} {} {}, but simply ignoring and going on".format(width, height, type_ext))
            print(e)
        return output
