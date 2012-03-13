#!/usr/bin/python
# Copyright (c) Phil Mayers
# See LICENSE for details

import tempfile
import sys
import os
import struct
import hashlib
import socket
socket.SO_ORIGINAL_DST = 80
import ssl as pyssl

from twisted.internet import ssl, reactor, protocol, defer, utils, threads
from twisted.python import log
from twisted.protocols import tls

# This function takes a real cert, and build a fake cert with the same
# CN and subjectAltName values, signed with "ca.crt" / "ca.key" in
# the current working direction
@defer.inlineCallbacks
def certMaker(cert):
    print cert
    if cert['subject'][-1][0][0]!='commonName':
        raise Exception('tip of subject is not commonName')

    hostname = cert['subject'][-1][0][1]
    chash = cert['hash']

    keyfile = '%s-key.pem' % (chash,)
    csrfile = '%s-csr.pem' % (chash,)
    certfile = '%s-crt.pem' % (chash,)

    try:
        # check for a cert already on-disk
        # with the same sha1 hash of binary blob
        os.stat(certfile)
    except:
        print "making new fake cert"
    else:
        print "using fake cert from disk"
        # file already exists on-disk
        # assume key is present too
        r = {
                'name': hostname,
                'cert': certfile,
                'key': keyfile,
                }
        defer.returnValue(r)


    # Is this sufficient? Maybe we want to copy whole DN?
    # Or read the 2nd & subsequent bits of the DN from our CA cert?
    subj = '/CN=%s/OU=FakeCA/O=My Fake CA' % (
            hostname,
            )

    # FIXME: key filenames by host/port combo, or maybe "real" cert hash?
    # FIXME: make the CA configurable?
    res = yield utils.getProcessOutputAndValue('/usr/bin/openssl',
        ('req','-newkey','rsa:1024','-nodes','-subj',subj,'-keyout',keyfile,'-out',csrfile),
        )
    out, err, code = res
    if code!=0:
        raise Exception('error generating csr '+err)

    fd, tmpname = tempfile.mkstemp()
    try:
        ext = os.fdopen(fd, 'w')

        # write the subjectAltName extension into a temp .cnf file
        dns = []
        if 'subjectAltName' in cert:
            for san in cert['subjectAltName']:
                if san[0]!='DNS':
                    continue
                dns.append('DNS:'+san[1])
        if dns:
            print >>ext, "subjectAltName=" + ','.join(dns)

        # FIXME: copy other extensions? eku?
        ext.close()

        # process the .csr with our CA cert to generate a signed cert
        res = yield utils.getProcessOutputAndValue('/usr/bin/openssl',
            ('x509','-req','-days','365','-in',csrfile,'-CA','ca.crt','-CAkey','ca.key','-set_serial','0','-extfile',tmpname,'-out',certfile),
            )
    finally:
        # remove temp file
        os.unlink(tmpname)

    out, err, code = res
    if code==0:
        r = {
                'name': hostname,
                'cert': certfile,
                'key': keyfile,
                }
        defer.returnValue(r)

    raise Exception('failed to generate cert '+err)

# The twisted SSL client API is a bit of a pain
# we use the normal python socket/ssl API via a
# deferToThread
def _ssl_cert_chain(host, port):

    # FIXME: use getaddrinfo, not IPv6-safe here
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # FIXME: configurable timeout?
    s.settimeout(5)
    s.connect((host, port))

    sec = pyssl.wrap_socket(
            s,
            # NOTE: it seems that, unless we do verification,
            # python doesn't expose the peer cert to us.
            # This means we need to supply a CA bundle, so
            # this code doesn't support self-signed certs.
            #
            # It might be possible to do better with an explicit
            # context & verify callback?
            cert_reqs=pyssl.CERT_REQUIRED,
            ca_certs='/etc/pki/tls/certs/ca-bundle.trust.crt',
            )
    # should be redundant, in theory...
    sec.do_handshake()

    # get peer certs
    rv = sec.getpeercert()
    bin = sec.getpeercert(binary_form=True)
    rv['hash'] = hashlib.sha1(bin).hexdigest()

    sec.close()
    del sec
    del s
    return rv
def ssl_cert_chain(host, port):
    return threads.deferToThread(_ssl_cert_chain, host, port)

class CertCache:
    def __init__(self):
        self._cache = {}

    @defer.inlineCallbacks
    def checkSSL(self, host, port):

        if (host, port) in self._cache:
            defer.returnValue(self._cache[host, port])

        # get the cert on that ip/port combp
        cert = yield ssl_cert_chain(host, port)

        # make a fake
        fake = yield certMaker(cert)

        # add to cache
        self._cache[host, port] = fake

        # done
        defer.returnValue(fake)

cache = CertCache()

class Forwarder(protocol.Protocol):
    other = None

    def connectionLost(self, reason):
        if self.other is None:
            pass
        else:
            self.other.transport.loseConnection()
            self.other = None

    def dataReceived(self, data):
        self.other.transport.write(data)

class ForwardOut(Forwarder):
    def connectionMade(self):
        self.other.other = self

        # copied from t.p.portforward
        self.transport.registerProducer(self.other.transport, True)
        self.other.transport.registerProducer(self.transport, True)

        # re-start the inbound transport produder & ssl server mode
        self.other._resume()

class ForwardFactory(protocol.ClientFactory):
    noisy = False

    def buildProtocol(self, addr):
        prot = ForwardOut()
        prot.other = self.other
        return prot

    def clientConnectionFailed(self, reason):
        self.other.transport.loseConnection()

class MitmProtocol(Forwarder):

    certinfo = None

    def connectionMade(self):
        # stop the transport producing
        self.transport.pauseProducing()

        # get the original IP
        # WARNING: accessing private member of transport
        # also, will fail if the socket isn't actually redirected
        orig = self.transport.socket.getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST, 16)
        # WARNING: not IPv6-safe
        fam, port, addr, rest = struct.unpack('!HH4s8s', orig)
        addr = socket.inet_ntoa(addr)

        log.msg("connection to", addr, port, "intercepted")

        d = cache.checkSSL(addr, port).addCallback(self._gotcert, addr, port)
        d.addErrback(self._goterr, addr, port)

    def _goterr(self, fail, orighost, origport):
        log.msg('failed to get SSL cert for', orighost, origport)
        log.err(fail)
        self.transport.loseConnection()

    def _gotcert(self, result, orighost, origport):
        self.certinfo = result

        log.msg("conneccting to", orighost, origport)
        f = ForwardFactory()
        f.other = self

        ccf = ssl.ClientContextFactory()
        reactor.connectSSL(orighost, origport, f, ccf)

    def _resume(self):
        # ok, outbound SSL connection is alive
        self.transport.resumeProducing()

        ctx = ssl.DefaultOpenSSLContextFactory(self.certinfo['key'], self.certinfo['cert'])
        self.transport.startTLS(ctx)


class MitmFactory(protocol.ServerFactory):
    noisy = False

    def logPrefix(self):
        return '-'

    def buildProtocol(self, addr):
        return MitmProtocol()

def main():
    log.startLogging(sys.stderr)

    factory = MitmFactory()
    reactor.listenTCP(4443, factory)
    reactor.run()

if __name__=='__main__':
    main()
