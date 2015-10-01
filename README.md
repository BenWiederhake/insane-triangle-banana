= What =

Small tool to read a PEM file containing a "RSA PUBLIC KEY",
including a test program and afl-harness.

= Why =

I helped in proting libtgl away from OpenSSL, and for a while it looked 
like we couldn't avoid that format. As you can see, it's really not 
worth the trouble, since this pulls the following dependencies:

	$ pkg-config --cflags nss
	-I/usr/include/nss -I/usr/include/nspr
	$ pkg-config --libs nss
	-lnss3 -lnssutil3 -lsmime3 -lssl3 -lplds4 -lplc4 -lnspr4

That's just too much. Instead, we opted for a private format.
(See https://github.com/BenWiederhake/pem2bignum which I will
 publish shortly).

= WTF is that format? =

Maybe this helps someone in the future. The layers of the encoding are:

- ASCII guards (the "----BEGIN RSA PUBLIC KEY----" things). No content,
  just making sure the user copy/pasted correctly.
- Base64: No content, just making sure the data looks like "plaintext"
  to the enduser.
- ASN.1: Really horrible "binary-XML" thing that nobody can read easily.

For the record, in the case of RSA PUBLIC KEYs, the ASN.1 format is
specified in https://tools.ietf.org/html/rfc3447#appendix-A.1 .

Just so you don't have to click the link:

    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }

= Alternatives to this =

You would need to:

1. re-use the file reading and de-guarding from insane-triangle-banana
2. use a third-party base64 decoder
3. Decode the ASN.1 on your own, by either parsing it on your own,
   using a lightweight ASN.1 decoder, or just using pem2bignum to save
   your sanity.

I attempted the "using a lightweight ASN.1 decoder" (see the "tom-asn"
branch), but eventually went for my own format (this is the part with
blackjack and hookers).

= Is this secure? =

If you have to ask, then no, it is not secure to use someone else's 
code you just found on the internet and instead of looking at it you're 
reading a crappy README I'm writing because I kinda feel obliged to.

No, stupid.

However, the core functions are from NSS, and the parsing is pretty 
well eye-proofed and stands against afl-fuzz, so I'm confident that all 
relevant exploits will target other areas of the app.
