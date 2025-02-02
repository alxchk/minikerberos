#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import datetime
import io
import struct

# this is from impacket, a bit modified
ZERO = datetime.timedelta(0)


class UTC(datetime.tzinfo):
    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


utc = UTC()
windows_epoch = datetime.datetime(1970, 1, 1, tzinfo=utc)


def dt_to_kerbtime(dt):
    td = dt - windows_epoch
    return int((
        td.microseconds + (
            td.seconds + td.days * 24 * 3600) * 10**6) / 1e6)


def TGSTicket2hashcat(res):
    tgs_encryption_type = int(res['ticket']['enc-part']['etype'])
    tgs_name_string = res['ticket']['sname']['name-string'][0]
    tgs_realm = res['ticket']['realm']
    tgs_checksum = res['ticket']['enc-part']['cipher'][:16]
    tgs_encrypted_data2 = res['ticket']['enc-part']['cipher'][16:]

    return '$krb5tgs$%s$*%s$%s$spn*$%s$%s' % (
        tgs_encryption_type, tgs_name_string, tgs_realm,
        as_hex(tgs_checksum), as_hex(tgs_encrypted_data2)
    )


def TGTTicket2hashcat(res):
    tgt_encryption_type = int(res['enc-part']['etype'])
    tgt_name_string = res['cname']['name-string'][0]
    tgt_realm = res['crealm']
    tgt_checksum = res['enc-part']['cipher'][:16]
    tgt_encrypted_data2 = res['enc-part']['cipher'][16:]

    return '$krb5asrep$%s$%s$%s$%s$%s' % (
        tgt_encryption_type, tgt_name_string, tgt_realm,
        as_hex(tgt_checksum), as_hex(tgt_encrypted_data2))


try:
    range = xrange

    def as_str(data):
        if isinstance(data, (list, tuple)):
            return list(
                as_str(x) for x in data
            )
        elif isinstance(data, str):
            return data.decode('latin-1')
        elif isinstance(data, unicode):
            return data
        else:
            raise ValueError('Unexpected type (%s)' % type(data))

    def as_bytes(data):
        if isinstance(data, (list, tuple)):
            return list(
                as_bytes(x) for x in data
            )
        elif isinstance(data, int):
            return chr(data)
        elif isinstance(data, unicode):
            return data.encode('latin-1')
        elif isinstance(data, str):
            return data
        else:
            raise ValueError('Unexpected type (%s)' % type(data))

    def as_hex(data):
        if isinstance(data, int):
            return '{:X}'.format(data)
        elif isinstance(data, str):
            return data.encode('hex')
        else:
            raise ValueError('Unexpected type (%s)' % type(data))

except NameError:
    NotImplementedError()


class EOFReader(object):
    __slots__ = ('_fobj',)

    def __init__(self, fobj):
        self._fobj = fobj

    def __getattr__(self, key):
        return getattr(self._fobj, key)

    def read(self, bytes):
        result = self._fobj.read(bytes)
        if len(result) != bytes:
            raise EOFError()

        return result
