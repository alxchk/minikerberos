import io
import enum
import struct

# https://tools.ietf.org/html/rfc4121#section-4.1.1.1


class ChecksumFlags(enum.IntEnum):
    GSS_C_DELEG_FLAG = 1
    GSS_C_MUTUAL_FLAG = 2
    GSS_C_REPLAY_FLAG = 4
    GSS_C_SEQUENCE_FLAG = 8
    GSS_C_CONF_FLAG = 16
    GSS_C_INTEG_FLAG = 32
    GSS_C_DCE_STYLE = 0x1000


# https://tools.ietf.org/html/rfc4121#section-4.1.1
class AuthenticatorChecksum(object):
    __slots__ = (
        'length_of_binding', 'channel_binding',
        'flags', 'delegation', 'delegation_length',
        'delegation_data', 'extensions'
    )

    def __init__(self):
        self.length_of_binding = None
        self.channel_binding = None  # MD5 hash of gss_channel_bindings_struct
        self.flags = None  # ChecksumFlags
        self.delegation = None
        self.delegation_length = None
        self.delegation_data = None
        self.extensions = None

    @staticmethod
    def from_bytes(data):
        AuthenticatorChecksum.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buffer):
        ac = AuthenticatorChecksum()
        ac.length_of_binding = struct.unpack('<I', buffer.read(4))
        # according to the latest RFC this is 16 bytes long always
        ac.channel_binding = buffer.read(ac.length_of_binding)
        ac.flags = ChecksumFlags(struct.unpack('<I', buffer.read(4)))
        if ac.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
            ac.delegation = bool(ord(buffer.read(1)))
            ac.delegation_length = struct.unpack('<H', buffer.read(2))
            ac.delegation_data = buffer.read(ac.delegation_length)

        ac.extensions = buffer.read()
        return ac

    def to_bytes(self):
        t = struct.pack('<I', len(self.channel_binding))
        t += self.channel_binding
        t += struct.pack('<I', self.flags)

        if self.flags & ChecksumFlags.GSS_C_DELEG_FLAG:
            t += chr(int(self.delegation))
            t += struct.pack('<H', len(self.delegation_data.to_bytes()))
            t += self.delegation_data

        if self.extensions:
            t += self.extensions.to_bytes()

        return t
