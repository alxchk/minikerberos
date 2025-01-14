#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from __future__ import unicode_literals

import os
import io
import datetime
import glob
import logging
import hashlib
import struct

from minikerberos.asn1_structs import *
from minikerberos.utils import (
    dt_to_kerbtime, TGSTicket2hashcat, as_bytes, as_str, as_hex,
    EOFReader, range
)
from minikerberos.constants import *
from minikerberos import logger
from asn1crypto import core


class MalformedTicket(ValueError):
    pass


# http://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
class Header(object):
    __slots__ = (
        'tag', 'taglen', 'tagdata'
    )

    def __init__(self):
        self.tag = None
        self.taglen = None
        self.tagdata = None

    @staticmethod
    def parse(data):
        """
        returns a list of header tags
        """
        reader = io.BytesIO(data)
        headers = []

        while reader.tell() < len(data):
            h = Header()
            h.tag, h.taglen = struct.unpack('>HH', reader.read(4))
            h.tagdata = reader.read(h.taglen)
            headers.append(h)

        return headers

    def to_bytes(self):
        t =  struct.pack('>H', self.tag)
        t += struct.pack('>H', len(self.tagdata))
        t += self.tagdata
        return t

    def __str__(self):
        t = 'tag: %s\n' % self.tag
        t += 'taglen: %s\n' % self.taglen
        t += 'tagdata: %s\n' % self.tagdata
        return t


class DateTime(object):
    __slots__ = (
        'time_offset', 'usec_offset'
    )

    def __init__(self):
        self.time_offset = None
        self.usec_offset = None

    @staticmethod
    def parse(reader):
        d = DateTime()
        d.time_offset, d.usec_offset = struct.unpack(
            '>II', reader.read(8))
        return d

    def to_bytes(self):
        return struct.pack('>II', self.time_offset, self.usec_offset)


class Credential(object):
    __slots__ = (
        'client', 'server',  'key',
        'time', 'is_skey',  'tktflags',
        'num_address', 'addrs', 'num_authdata',
        'authdata',  'ticket', 'second_ticket'
    )

    def __init__(self):
        self.client = None
        self.server = None
        self.key = None
        self.time = None
        self.is_skey = None
        self.tktflags = None
        self.num_address = None
        self.addrs = []
        self.num_authdata = None
        self.authdata = []
        self.ticket = None
        self.second_ticket = None

    def to_hash(self):
        res = Ticket.load(self.ticket.to_asn1()).native

        tgs_encryption_type = int(res['enc-part']['etype'])
        t = len(res['sname']['name-string'])
        if t == 1:
            tgs_name_string = res['sname']['name-string'][0]
        else:
            tgs_name_string = res['sname']['name-string'][1]

        tgs_realm = res['realm']
        if tgs_encryption_type == EncryptionType.AES256_CTS_HMAC_SHA1_96.value:
            tgs_checksum = res['enc-part']['cipher'][-12:]
            tgs_encrypted_data2 = res['enc-part']['cipher'][:-12:]
            return '$krb5tgs$%s$%s$%s$%s$%s' % (
                tgs_encryption_type,tgs_name_string,tgs_realm,
                as_hex(tgs_checksum), as_hex(tgs_encrypted_data2)
            )
        else:
            tgs_checksum = res['enc-part']['cipher'][:16]
            tgs_encrypted_data2 = res['enc-part']['cipher'][16:]
            return '$krb5tgs$%s$*%s$%s$spn*$%s$%s' % (
                tgs_encryption_type,tgs_name_string,tgs_realm,
                as_hex(tgs_checksum), as_hex(tgs_encrypted_data2)
            )

    def to_tgt(self):
        """
        Returns the native format of an AS_REP message and the sessionkey in EncryptionKey native format
        """
        enc_part = EncryptedData({
            'etype': 1,
            'cipher': b''
        })

        try:
            ticket = Ticket.load(self.ticket.to_asn1()).native
        except ValueError:
            raise MalformedTicket()

        tgt_rep = {
            'pvno' : krb5_pvno,
            'msg-typ' : MESSAGE_TYPE.KRB_AS_REP.value,
            'crealm' : self.server.realm.to_string(),
            'cname' : self.client.to_asn1()[0],
            'ticket' : ticket,
            'enc-par' : enc_part.native
        }

        return tgt_rep, EncryptionKey(self.key.to_asn1()).native

    def to_kirbi(self):
        filename = '%s@%s_%s' % (
            self.client.to_string() , self.server.to_string(),
            hashlib.sha1(self.ticket.to_asn1()).hexdigest()[:8]
        )

        krbcredinfo = {}
        krbcredinfo['key'] = EncryptionKey(self.key.to_asn1())
        krbcredinfo['prealm'] = self.client.realm.to_string()
        krbcredinfo['pname'] = self.client.to_asn1()[0]
        krbcredinfo['flags'] = core.IntegerBitString(self.tktflags).cast(TicketFlags)

        if self.time.authtime != 0: #this parameter is not mandatory, and most of the time not present
            krbcredinfo['authtime'] = datetime.datetime.fromtimestamp(self.time.authtime)

        krbcredinfo['starttime'] = datetime.datetime.fromtimestamp(self.time.starttime)
        krbcredinfo['endtime'] = datetime.datetime.fromtimestamp(self.time.endtime)

        if self.time.renew_till != 0: #this parameter is not mandatory, and sometimes it's not present
            krbcredinfo['renew-till'] = datetime.datetime.fromtimestamp(self.time.authtime)

        krbcredinfo['srealm'] = self.server.realm.to_string()
        krbcredinfo['sname'] = self.server.to_asn1()[0]

        enc_krbcred = {}
        enc_krbcred['ticket-info'] = [KrbCredInfo(krbcredinfo)]

        krbcred = {}
        krbcred['pvno'] = krb5_pvno
        krbcred['msg-type'] = MESSAGE_TYPE.KRB_CRED.value
        krbcred['tickets'] = [Ticket.load(self.ticket.to_asn1())]
        krbcred['enc-part'] = EncryptedData({
            'etype': EncryptionType.NULL.value,
            'cipher': EncKrbCredPart(enc_krbcred).dump()
        })

        kirbi = KRBCRED(krbcred)
        return kirbi, filename

    @staticmethod
    def from_asn1(ticket, data):
        ###
        # data  = KrbCredInfo
        ###
        c = Credential()
        c.client = CCACHEPrincipal.from_asn1(
            data['pname'],
            data['prealm'
        ])

        c.server = CCACHEPrincipal.from_asn1(
            data['sname'],
            data['srealm']
        )

        c.key = Keyblock.from_asn1(data['key'])
        c.is_skey = 0 #not sure!

        c.tktflags = TicketFlags(
            data['flags']
        ).cast(core.IntegerBitString).native
        c.num_address = 0
        c.num_authdata = 0

        c.ticket = CCACHEOctetString.from_asn1(ticket['enc-part']['cipher'])
        c.second_ticket = CCACHEOctetString.empty()
        return c

    @staticmethod
    def parse(reader):
        c = Credential()
        c.client = CCACHEPrincipal.parse(reader)
        c.server = CCACHEPrincipal.parse(reader)
        c.key = Keyblock.parse(reader)
        c.time = Times.parse(reader)
        c.is_skey, c.tktflags, c.num_address = struct.unpack(
            '>BII', reader.read(9))

        for i in range(c.num_address):
            c.addrs.append(Address.parse(reader))

        c.num_authdata, = struct.unpack('>I', reader.read(4))
        for i in range(c.num_authdata):
            c.authdata.append(Authdata.parse(reader))

        c.ticket = CCACHEOctetString.parse(reader)
        c.second_ticket = CCACHEOctetString.parse(reader)
        return c

    @staticmethod
    def summary_header():
        return ('client','server','starttime','endtime','renew-till')

    def summary(self):
        return [
            '%s@%s' % (self.client.to_string(),self.client.realm.to_string()),
            '%s@%s' % (self.server.to_string(), self.server.realm.to_string()),
            datetime.datetime.fromtimestamp(self.time.starttime).isoformat() if self.time.starttime != 0 else 'N/A',
            datetime.datetime.fromtimestamp(self.time.endtime).isoformat() if self.time.endtime != 0 else 'N/A',
            datetime.datetime.fromtimestamp(self.time.renew_till).isoformat() if self.time.renew_till != 0 else 'N/A',
        ]

    def to_bytes(self):
        t =  self.client.to_bytes()
        t += self.server.to_bytes()
        t += self.key.to_bytes()
        t += self.time.to_bytes()

        t += struct.pack('>BII', self.is_skey, self.tktflags, self.num_address)
        for addr in self.addrs:
            t += addr.to_bytes()

        t += struct.pack('>I', self.num_authdata)
        for ad in self.authdata:
            t += ad.to_bytes()

        t += self.ticket.to_bytes()
        t += self.second_ticket.to_bytes()
        return t


class Keyblock(object):
    __slots__ = (
        'keytype', 'etype', 'keylen', 'keyvalue'
    )

    def __init__(self):
        self.keytype = None
        self.etype = None
        self.keylen = None
        self.keyvalue = None

    @staticmethod
    def from_asn1(data):
        k = Keyblock()
        k.keytype = data['keytype']
        k.etype = 0 # not sure
        k.keylen = len(data['keyvalue'])
        k.keyvalue = data['keyvalue']

        return k

    def to_asn1(self):
        t = {}
        t['keytype'] = self.keytype
        t['keyvalue'] = self.keyvalue

        return t

    @staticmethod
    def parse(reader):
        k = Keyblock()
        k.keytype, k.etype, k.keylen = struct.unpack(
            '>HHH', reader.read(6))
        k.keyvalue = reader.read(k.keylen)
        return k

    def to_bytes(self):
        t = struct.pack(
            '>HHH', self.keytype, self.etype, self.keylen)
        t += self.keyvalue
        return t


class Times(object):
    __slots__ = (
        'authtime', 'starttime', 'endtime', 'renew_till'
    )

    def __init__(self):
        self.authtime = None
        self.starttime = None
        self.endtime = None
        self.renew_till = None

    @staticmethod
    def from_asn1(enc_as_rep_part):
        t = Times()
        if 'authtime' in enc_as_rep_part and enc_as_rep_part['authtime']:
            t.authtime = dt_to_kerbtime(enc_as_rep_part['authtime'])
        else:
            t.authtime = 0

        if 'starttime' in enc_as_rep_part and enc_as_rep_part['starttime']:
            t.starttime = dt_to_kerbtime(enc_as_rep_part['starttime'])
        else:
            t.starttime = 0

        t.endtime = dt_to_kerbtime(enc_as_rep_part['endtime'])
        t.renew_till = dt_to_kerbtime(enc_as_rep_part['renew-till'])
        return t

    @staticmethod
    def dummy_time(start=datetime.datetime.utcnow()):
        t = Times()
        t.authtime = dt_to_kerbtime(start)
        t.starttime = dt_to_kerbtime(start)
        t.endtime = dt_to_kerbtime(start + datetime.timedelta(days=1))
        t.renew_till = dt_to_kerbtime(start + datetime.timedelta(days=2))
        return t

    @staticmethod
    def parse(reader):
        t = Times()
        t.authtime, t.starttime, t.endtime, t.renew_till = struct.unpack_from(
            '>IIII', reader.read(16))
        return t

    def to_bytes(self):
        return struct.pack(
            '>IIII',
            self.authtime, self.starttime,
            self.endtime, self.renew_till
        )


class Address(object):
    __slots__ = (
        'addrtype', 'addrdata'
    )

    def __init__(self):
        self.addrtype = None
        self.addrdata = None

    @staticmethod
    def parse(reader):
        a = Address()
        a.addrtype, = struct.unpack('>H', reader.read(2))
        a.addrdata = CCACHEOctetString.parse(reader)
        return a

    def to_bytes(self):
        t = struct.pack('>H', self.addrtype)
        t += self.addrdata.to_bytes()
        return t


class Authdata(object):
    __slots__ = (
        'authtype', 'authdata'
    )

    def __init__(self):
        self.authtype = None
        self.authdata = None

    @staticmethod
    def parse(reader):
        a = Authdata()
        a.authtype, = struct.unpack_from('>H', reader.read(2))
        a.authdata = CCACHEOctetString.parse(reader)
        return a

    def to_bytes(self):
        t = struct.pack('>H', self.authtype)
        t += self.authdata.to_bytes()
        return t


class CCACHEPrincipal(object):
    __slots__ = (
        'name_type', 'num_components', 'realm', 'components'
    )

    def __init__(self):
        self.name_type = None
        self.num_components = None
        self.realm = None
        self.components = []

    @staticmethod
    def from_asn1(principal, realm):
        p = CCACHEPrincipal()
        p.name_type = principal['name-type']
        p.num_components = len(principal['name-string'])
        p.realm = CCACHEOctetString.from_string(realm)
        for comp in principal['name-string']:
            p.components.append(CCACHEOctetString.from_asn1(comp))

        return p

    @staticmethod
    def dummy():
        p = CCACHEPrincipal()
        p.name_type = 1
        p.num_components = 1
        p.realm = CCACHEOctetString.from_string('kerbi.corp')
        for i in range(1):
            p.components.append(CCACHEOctetString.from_string('kerbi'))

        return p

    def to_string(self):
        return '-'.join([c.to_string() for c in self.components])

    def to_asn1(self):
        t = {
            'name-type': self.name_type,
            'name-string': [name.to_string() for name in self.components]
        }
        return t, self.realm.to_string()

    @staticmethod
    def parse(reader):
        p = CCACHEPrincipal()
        p.name_type, p.num_components = struct.unpack_from(
            '>II', reader.read(8))
        p.realm = CCACHEOctetString.parse(reader)

        for i in range(p.num_components):
            p.components.append(CCACHEOctetString.parse(reader))

        return p

    def to_bytes(self):
        t = struct.pack('>II', self.name_type, len(self.components))
        t += self.realm.to_bytes()

        for com in self.components:
            t += com.to_bytes()

        return t


class CCACHEOctetString(object):
    __slots__ = (
        'length', 'data'
    )

    def __init__(self):
        self.length = None
        self.data = None

    @staticmethod
    def empty():
        o = CCACHEOctetString()
        o.length = 0
        o.data = b''
        return o

    def to_asn1(self):
        return self.data

    def to_string(self):
        return as_str(self.data)

    @staticmethod
    def from_string(data):
        o = CCACHEOctetString()
        o.data = as_bytes(data)
        o.length = len(o.data)
        return o

    @staticmethod
    def from_asn1(data):
        o = CCACHEOctetString()
        o.length = len(data)
        o.data = data
        return o

    @staticmethod
    def parse(reader):
        o = CCACHEOctetString()
        o.length, = struct.unpack('>I', reader.read(4))
        o.data = reader.read(o.length)
        return o

    def to_bytes(self):
        return struct.pack('>I', self.length) + self.data


class CCACHE(object):
    """
    As the header is rarely used -mostly static- you'd need to init this
    object with empty = True to get an object without header already present
    """

    __slots__ = (
        'file_format_version', 'headers',
        'primary_principal', 'credentials'
    )

    def __init__(self, empty=False):
        self.file_format_version = None #0x0504
        self.headers = []
        self.primary_principal = None
        self.credentials = []

        if empty == False:
            self.__setup()

    def __setup(self):
        self.file_format_version = 0x0504

        header = Header()
        header.tag = 1
        header.taglen = 8
        #header.tagdata = b'\xff\xff\xff\xff\x00\x00\x00\x00'
        header.tagdata = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        self.headers.append(header)

        #t_hdr = b''
        #for header in self.headers:
        #	t_hdr += header.to_bytes()
        #self.headerlen = 1 #size of the entire header in bytes, encoded in 2 byte big-endian unsigned int

        self.primary_principal = CCACHEPrincipal.dummy()

    def __str__(self):
        t = '== CCACHE ==\n'
        t+= 'file_format_version : %s\n' % self.file_format_version
        for header in self.headers:
            t+= '%s\n' % header
        t+= 'primary_principal : %s\n' % self.primary_principal
        return t

    def add_tgt(self, as_rep, enc_as_rep_part, override_pp = True): #from AS_REP
        """
        Creates credential object from the TGT and adds to the ccache file
        The TGT is basically the native representation of the asn1 encoded AS_REP
        data that the AD sends upon a succsessful TGT request.

        This function doesn't do decryption of the encrypted part of the as_rep object,
        it is expected that the decrypted XXX is supplied in enc_as_rep_part

        override_pp: bool to determine if client principal should be used as the primary
        principal for the ccache file
        """

        c = Credential()
        c.client = CCACHEPrincipal.from_asn1(as_rep['cname'], as_rep['crealm'])

        if override_pp == True:
            self.primary_principal = c.client

        c.server = CCACHEPrincipal.from_asn1(enc_as_rep_part['sname'], enc_as_rep_part['srealm'])
        c.time = Times.from_asn1(enc_as_rep_part)
        c.key = Keyblock.from_asn1(enc_as_rep_part['key'])
        c.is_skey = 0 #not sure!

        c.tktflags = TicketFlags(enc_as_rep_part['flags']).cast(core.IntegerBitString).native
        c.num_address = 0
        c.num_authdata = 0

        print "SET TGT Ticket", len(Ticket(as_rep['ticket']).dump())

        c.ticket = CCACHEOctetString.from_asn1(Ticket(as_rep['ticket']).dump())
        c.second_ticket = CCACHEOctetString.empty()

        self.credentials.append(c)

    def add_tgs(self, tgs_rep, enc_tgs_rep_part, override_pp=False): #from AS_REP
        """
        Creates credential object from the TGS and adds to the ccache file
        The TGS is the native representation of the asn1 encoded TGS_REP data when the
        user requests a tgs to a specific service principal with a valid TGT

        This function doesn't do decryption of the encrypted part of the tgs_rep object,
        it is expected that the decrypted XXX is supplied in enc_as_rep_part

        override_pp: bool to determine if client principal should be used as the primary
        principal for the ccache file
        """

        c = Credential()
        c.client = CCACHEPrincipal.from_asn1(tgs_rep['cname'], tgs_rep['crealm'])
        if override_pp == True:
            self.primary_principal = c.client

        c.server = CCACHEPrincipal.from_asn1(enc_tgs_rep_part['sname'], enc_tgs_rep_part['srealm'])
        c.time = Times.from_asn1(enc_tgs_rep_part)
        c.key = Keyblock.from_asn1(enc_tgs_rep_part['key'])
        c.is_skey = 0 #not sure!

        c.tktflags = TicketFlags(enc_tgs_rep_part['flags']).cast(core.IntegerBitString).native
        c.num_address = 0
        c.num_authdata = 0
        c.ticket = CCACHEOctetString.from_asn1(Ticket(tgs_rep['ticket']).dump())
        c.second_ticket = CCACHEOctetString.empty()

        self.credentials.append(c)

    def add_kirbi(self, krbcred, override_pp=True):
        c = Credential()
        enc_credinfo = EncKrbCredPart.load(krbcred['enc-part']['cipher']).native
        ticket_info = enc_credinfo['ticket-info'][0]

        c.client = CCACHEPrincipal.from_asn1(ticket_info['pname'], ticket_info['prealm'])
        if override_pp == True:
            self.primary_principal = c.client

        #yaaaaay 4 additional weirdness!!!!
        #if sname name-string contains a realm as well htne impacket will crash miserably :(
        if len(ticket_info['sname']['name-string']) > 2 and ticket_info['sname']['name-string'][-1].upper() == ticket_info['srealm'].upper():
            logging.debug('SNAME contains the realm as well, trimming it')
            t = ticket_info['sname']
            t['name-string'] = t['name-string'][:-1]
            c.server = CCACHEPrincipal.from_asn1(t, ticket_info['srealm'])
        else:
            c.server = CCACHEPrincipal.from_asn1(ticket_info['sname'], ticket_info['srealm'])

        c.time = Times.from_asn1(ticket_info)
        c.key = Keyblock.from_asn1(ticket_info['key'])
        c.is_skey = 0 #not sure!

        c.tktflags = TicketFlags(ticket_info['flags']).cast(core.IntegerBitString).native
        c.num_address = 0
        c.num_authdata = 0
        c.ticket = CCACHEOctetString.from_asn1(Ticket(krbcred['tickets'][0]).dump()) #kirbi only stores one ticket per file
        c.second_ticket = CCACHEOctetString.empty()

        self.credentials.append(c)

    @staticmethod
    def from_kirbi(kirbidata):
        kirbi = KRBCRED.load(kirbidata).native
        cc = CCACHE()
        cc.add_kirbi(kirbi)
        return cc

    def get_all_tgt(self):
        """
        Returns a list of AS_REP tickets in native format (dict).
        To determine which ticket are AP_REP we check for the server principal to be the kerberos service
        """
        tgts = []
        for cred in self.credentials:
            if cred.server.to_string().lower().find('krbtgt') != -1:
                try:
                    tgts.append(cred.to_tgt())
                except MalformedTicket:
                    # The ticket field of a configuration entry is not (usually) a valid
                    # encoding of a Kerberos ticket. An implementation must not treat the
                    # cache file as malformed if it cannot decode the ticket
                    pass

        return tgts

    def get_hashes(self, all_hashes=False):
        """
        Returns a list of hashes in hashcat-firendly format for tickets with encryption type 23 (which is RC4)
        all_hashes: overrides the encryption type filtering and returns hash for all tickets

        """
        hashes = []
        for cred in self.credentials:
            try:
                res = Ticket.load(cred.ticket.to_asn1()).native
            except ValueError:
                continue

            if int(res['enc-part']['etype']) == 23 or all_hashes == True:
                hashes.append(cred.to_hash())

        return hashes

    @staticmethod
    def parse(reader):
        reader = EOFReader(reader)

        c = CCACHE(True)
        c.file_format_version, hdr_size = struct.unpack('>HH', reader.read(4))
        c.headers = Header.parse(reader.read(hdr_size))

        c.primary_principal = CCACHEPrincipal.parse(reader)

        while True:
            try:
                c.credentials.append(Credential.parse(reader))
            except EOFError:
                break

        return c

    def to_bytes(self):
        t = struct.pack('>H', self.file_format_version)

        t_hdr = b''
        for header in self.headers:
            t_hdr += header.to_bytes()

        t += struct.pack('>H', len(t_hdr))
        t += t_hdr

        t += self.primary_principal.to_bytes()
        for cred in self.credentials:
            t += cred.to_bytes()

        return t

    @staticmethod
    def from_kirbifile(kirbi_filename):
        kf_abs = os.path.abspath(kirbi_filename)
        kirbidata = None
        with open(kf_abs, 'rb') as f:
            kirbidata = f.read()

        return CCACHE.from_kirbi(kirbidata)

    @staticmethod
    def from_kirbidir(directory_path):
        """
        Iterates trough all .kirbi files in a given directory and converts all of them into one CCACHE object
        """
        cc = CCACHE()
        dir_path = os.path.join(os.path.abspath(directory_path), '*.kirbi')
        for filename in glob.glob(dir_path):
            with open(filename, 'rb') as f:
                kirbidata = f.read()
                kirbi = KRBCRED.load(kirbidata).native
                cc.add_kirbi(kirbi)

        return cc

    def to_kirbidir(self, directory_path):
        """
        Converts all credential object in the CCACHE object to the kirbi file format used by mimikatz.
        The kirbi file format supports one credential per file, so prepare for a lot of files being generated.

        directory_path: str the directory to write the kirbi files to
        """
        kf_abs = os.path.abspath(directory_path)
        for cred in self.credentials:
            kirbi, filename = cred.to_kirbi()
            filename = '%s.kirbi' % filename.replace('..','!')
            filepath = os.path.join(kf_abs, filename)
            with open(filepath, 'wb') as o:
                o.write(kirbi.dump())

    @staticmethod
    def from_file(filename):
        """
        Parses the ccache file and returns a CCACHE object
        """
        with open(filename, 'rb') as f:
            return CCACHE.parse(f)

    def to_file(self, filename):
        """
        Writes the contents of the CCACHE object to a file
        """
        with open(filename, 'wb') as f:
            f.write(self.to_bytes())

