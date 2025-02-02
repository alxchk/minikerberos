
# https://web.mit.edu/kerberos/krb5-1.12/doc/formats/keytab_file_format.html
##
# Be careful using this parser/writer! The specifications in the MIT Kerberos's official page doesnt match with the file Windows server generates!!
# Thus this script is to support Windows generated keytabs, not sure about MIT's

from __future__ import unicode_literals

import io
import struct

from minikerberos.utils import (
    range, as_bytes, as_str, as_hex, EOFReader
)


class KeytabPrincipal(object):
    __slots__ = (
        'num_components', 'name_type',
        'realm', 'components'
    )

    def __init__(self):
        self.num_components = None
        self.name_type = None
        self.realm = None
        self.components = []

    @staticmethod
    def from_asn1(principal, realm):
        p = KeytabPrincipal()
        p.name_type = principal['name-type']
        p.num_components = len(principal['name-string'])
        p.realm = KeytabOctetString.from_string(realm)
        for comp in principal['name-string']:
            p.components.append(KeytabOctetString.from_asn1(comp))

        return p

    @staticmethod
    def dummy():
        p = KeytabPrincipal()
        p.name_type = 1
        p.num_components = 1
        p.realm = KeytabOctetString.from_string('kerbi.corp')
        for i in range(1):
            p.components.append(
                KeytabOctetString.from_string('kerbi'))

        return p

    def to_string(self):
        return '-'.join([
            c.to_string() for c in self.components
        ])

    def to_asn1(self):
        t = {
            'name-type': self.name_type,
            'name-string': [
                name.to_string() for name in self.components
            ]
        }
        return t, self.realm.to_string()

    @staticmethod
    def from_buffer(buffer):
        p = KeytabPrincipal()
        p.num_components, = struct.unpack('>H', buffer.read(2))
        p.realm = KeytabOctetString.parse(buffer)

        for i in range(p.num_components):
            p.components.append(KeytabOctetString.parse(buffer))

        p.name_type, = struct.unpack('>I', buffer.read(4))
        return p

    def to_bytes(self):
        t = struct.pack('>H', len(self.components))
        t += self.realm.to_bytes()

        for com in self.components:
            t += com.to_bytes()

        t += struct.pack('>I', self.name_type)
        return t


class KeytabOctetString(object):
    """
    Same as CCACHEOctetString
    """

    __slots__ = (
        'length', 'data'
    )

    def __init__(self):
        self.length = None
        self.data = None

    @staticmethod
    def empty():
        o = KeytabOctetString()
        o.length = 0
        o.data = b''
        return o

    def to_asn1(self):
        return self.data

    def to_string(self):
        return as_str(self.data)

    @staticmethod
    def from_string(data):
        o = KeytabOctetString()
        o.data = as_bytes(data)
        o.length = len(o.data)
        return o

    @staticmethod
    def from_asn1(data):
        o = KeytabOctetString()
        o.data = as_bytes(data)
        o.length = len(o.data)
        o.data = data
        return o

    @staticmethod
    def parse(reader):
        o = KeytabOctetString()
        o.length = struct.unpack('>H', reader.read(2))
        o.data = reader.read(o.length)
        return o

    def to_bytes(self):
        data = as_bytes(self.data)
        t = struct.pack('>H', len(data))
        t += data
        return t


class KeytabEntry(object):
    __slots__ = (
        'principal', 'timestamp', 'key_version',
        'enctype', 'key_version', 'key_length',
        'key_contents'
    )

    def __init__(self):
        self.principal = None
        self.timestamp = None
        self.key_version = None
        self.enctype = None
        self.key_length = None
        self.key_contents = None

    def to_bytes(self):
        t = self.principal.to_bytes()
        t += struct.pack('>I', self.timestamp)
        t += struct.pack('B', self.key_version)
        t += struct.pack('>H', self.enctype)
        t += struct.pack('>H', self.key_length)
        t += self.key_contents
        return t

    @staticmethod
    def from_bytes(data):
        return KeytabEntry.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buffer):
        ke = KeytabEntry()
        ke.principal = KeytabPrincipal.from_buffer(buffer)

        ke.timestamp, ke.key_version, ke.enctype, ke.key_length = \
            struct.unpack('>IBHH', buffer.read(4+1+2+2))

        ke.key_contents = buffer.read(ke.key_length)
        return ke

    def __repr__(self):
        t = '=== KeytabEntry ===\r\n'
        t += 'Principal : %s\r\n' % self.principal.to_string()
        t += 'timestamp : %s\r\n' % self.timestamp
        t += 'key_version : %s\r\n' % self.key_version
        t += 'enctype : %s\r\n' % self.enctype
        t += 'key_length : %s\r\n' % self.key_length
        t += 'key_contents : %s\r\n' % as_hex(self.key_contents)
        return t


class Keytab(object):
    __slots__ = (
        'krb5', 'version', 'entries'
    )

    def __init__(self):
        self.krb5 = 5
        self.version = 2
        self.entries = []

    def to_bytes(self):
        entries = []

        entries.append(
            struct.pack(
               'BB', self.krb5.to_bytes, self.version.to_bytes
            )
        )

        for e in self.entries:
            data = e.to_bytes()
            entries.append(len(data))
            entries.append(data)

        return b''.join(entries)

    @staticmethod
    def from_bytes(data):
        return Keytab.from_buffer(io.BytesIO(data))

    @staticmethod
    def from_buffer(buffer):
        buffer = EOFReader(buffer)

        k = Keytab()
        k.krb5, k.version = struct.unpack('BB', buffer.read(2))

        i = 0
        while True:
            try:
                entry_size, = struct.unpack('>I', buffer.read(4))
            except EOFError:
                entry_size = 0

            if entry_size == 0:
                break

            if entry_size < 0:
                # this is a hole
                i += entry_size * -1
                continue

            else:
                k.entries.append(KeytabEntry.from_bytes(
                    buffer.read(entry_size)))
                i += entry_size

        return k

    def __repr__(self):
        t = '=== Keytab ===\r\n'
        t += 'Version : %s\r\n' % self.version
        for e in self.entries:
            t += repr(e)

        return t


if __name__ == '__main__':
    filename = 'Z:\\VMShared\\app1.keytab'
    with open(filename, 'rb') as f:
        data = f.read()

    k = Keytab.from_bytes(data)
    print(repr(k))

    print(k.to_bytes())
    with open('test.keytab', 'wb') as o:
        o.write(k.to_bytes())

    assert data == k.to_bytes()
