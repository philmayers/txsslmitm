== About ==

This program is a simple SSL man-in-the-middle proxy. It is designed
to intercept SSL connections via the Linux iptables REDIRECT target,
generate a fake certificate matching the real server (but signed by
a local CA) and then relay the data.

== Requirements ==

 * Python 2.6 or greater
 * Twisted
 * OpenSSL
 * pyOpenSSL

== Setup ==

First, you must configure iptables to redirect the traffic, like so:

 iptables -t nat -A PREROUTING -s 192.168.0.0/16 -p tcp --dport 443 \
  -j REDIRECT --to-ports 4443

Obviously you will need to direct your traffic through your Linux box,
using whatever method e.g. routing.

== Private CA ==

You will need a CA cert & key in the working directory of the process:

 * ca.crt
 * ca.key

...so that OpenSSL can sign the fake certificate requests. The process
will dump 3 files for each certificate it impersonates:

 hash-key.pem - RSA key
 hash-csr.pem - Cert-signing requests
 hash-crt.pem - X509 cert, signed by ca.key (verified by ca.crt)

Obviously your clients will need to have imported, and to trust, your
private CA cert.

== Usage ==

The proxy listens for REDIRECT-ed connections on port 4443, extracts
the original destination address, connects and extracts the far-end
cert and impersonates it, then relays the data.

It should work transparently. It will cache certs, and should remember
them across restarts. If the same cert is used on multiple IPs, it
will recognise this and use the same fake cert.

== Problems ==

The fake certs are pretty minimal - CN and subjecAltName=DNS:* are copied
over, but no other extensions (e.g. extendedKeyUsage). There is no CRL
URL, or OSCP.

Some SSL applications may employ CA whitelisting for certain certs, to
specifically defeat SSL ca-in-the-middle attacks.

It relies on Linux, iptables, and being able to get your traffic through
such a Linux box.

It accesses the Twisted ITransport "socket" object directly to call
getsockopt(SOL_IP, SO_ORIGINAL_DST) which is probably not good.

It is probably vulnerable to all kinds of denial-of-service bugs.

There is no negative caching (see above).

 Phil Mayers
 March 2012
