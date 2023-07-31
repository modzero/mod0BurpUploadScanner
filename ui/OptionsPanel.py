# Burp imports
import profile
from burp import IScannerInsertionPoint
from misc.BackdooredFile import BackdooredFile
from misc.Constants import Constants
from misc.CustomHttpService import CustomHttpService
from misc.CustomRequestResponse import CustomRequestResponse
from misc.Misc import RunnableFunction
from debuging.debug import DEBUG_MODE
from helpers.FloydsHelpers import FloydsHelpers
from insertionPoints.CustomMultipartInsertionPoint import CustomMultipartInsertionPoint
# Java stdlib imports
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JCheckBox
from javax.swing.event import DocumentListener
from java.awt import Font
from java.awt import Color
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt.event import ActionListener
from java.lang import Thread
# python stdlib imports
import random  # to chose randomly
import urllib  # URL encode etc.
import os  # local paths parsing etc.
import stat  # To make exiftool executable executable
import urlparse  # urlparser for custom HTTP services
import ast  # to parse ${PYTHONSTR:'abc\ndef'} into a python str
import ast
import os
from java.awt import Font
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing.event import DocumentListener
from java.awt.event import ActionListener
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from ui.DirectoryChooserButton import DirectoryChooserButton
from ui.FileChooserButton import FileChooserButton

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
                    print("Found working exiftool by invoking '" + path + "' on the command line")
                    break
            else:
                print("Searched for exiftool but did not find a proper executable...")

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
            self.modules['activescan'].setSelected(False)
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
        t = JTextField(FloydsHelpers.u2s(text), Constants.TEXTFIELD_SIZE)
        t.getDocument().addDocumentListener(self)
        self._add_two(l, t)
        return l, t

    def file_chooser(self, desc, value=""):
        t = JTextField(value, Constants.TEXTFIELD_SIZE)
        t.getDocument().addDocumentListener(self)
        b = FileChooserButton()
        b.setup(t, desc)
        self._add_two(b, t)
        return b, t

    def dir_chooser(self, desc, value=""):
        t = JTextField(value, Constants.TEXTFIELD_SIZE)
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
            except (ValueError, SyntaxError) as e:
                print("Issue when processing your specified", input)
                print(e)
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
        except Exception as e:
            print("Exception, tf_image_height"), FloydsHelpers.u2s(self.tf_image_height.getText()), "is not numeric"
            self.image_height = 200
            OptionsPanel.mark_misconfigured(self.lbl_image_height)
        try:
            self.image_width = int(FloydsHelpers.u2s(self.tf_image_width.getText()))
            OptionsPanel.mark_configured(self.lbl_image_width)
        except Exception as e:
            print("Exception, tf_image_width", FloydsHelpers.u2s(self.tf_image_width.getText()), "is not numeric")
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
            print("Exception, fuzzer_random_mutations"), FloydsHelpers.u2s(self.tf_fuzzer_random_mutations.getText()), "is not numeric"
            self.fuzzer_random_mutations = 10
            OptionsPanel.mark_misconfigured(self.lbl_fuzzer_random_mutations)
        try:
            self.fuzzer_known_mutations = int(FloydsHelpers.u2s(self.tf_fuzzer_known_mutations.getText()))
            OptionsPanel.mark_configured(self.lbl_fuzzer_known_mutations)
        except:
            print("Exception, fuzzer_known_mutations"), FloydsHelpers.u2s(self.tf_fuzzer_known_mutations.getText()), "is not numeric"
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
            print("Does not seem to be a FlexiInjector request.")
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
                    print("No Preflight response, aborting redownload for: \n", preflight_request)
                    return None, None
            else:
                print("No Preflight request could be calculated, aborting redownload for: \n", preflight_request)
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
                    print("No Download response, aborting redownload for: \n", req)
                    return None, None
            else:
                # Happens quiet often, eg. when the server rejected our uploaded file and gave a different response
                # Such as a 500 or 400 error, so this case is in the usual workflow
                # print "Couldn't calculate download request", unicode(service), req
                return None, None
        return preflight_rr, download_rr
