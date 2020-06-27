# PoCK: Proof of Compromised Key

**Try out the web-based proof-of-concept at** https://cbonnell.github.io/pock

## What is PoCK?

PoCK is a mechanism by which possession of a private key can be demonstrated. The primary use case is to demonstrate that the corresponding private key for a Certificate in the web PKI has been compromised and that revocation of all certificates containing the public key is required.

## What are the design considerations for PoCK?

PoCK is intended to be used as a standard revocation request format in the web PKI. 

The requirements of this revocation request format are as follows:

3. The format should be readily produced and consumed by ubiquitous, industry-standard tooling and libraries. Creating a bespoke container format would require authoring extensive tooling to produce and consume the proofs.
4. The proof should convey all the information required to ascertain proof of key compromise and the set of certificates that need to be revoked.
5. The format should not contain any dynamic fields that require online access to the private key material to produce certificate-specific proofs. In other words, the PoCK can be created once and reused to demonstrate compromised keys after the associated private key may be stored offline or destroyed.

A format that meets the above requirements provides the following benefits:

1. Researchers who report compromised keys to Certification Authorities can produce proofs that are readily produced by industry-standard tools and are easily sendable via email to CA Problem Reporting Mechanisms.
2. Certification Authority personnel can readily ascertain proof of key compromise from Certificate Problem Reports and look up the associated set of certificates that need to be revoked in response.

The above two benefits translate into less hassle for researchers and CAs alike, which allows for more rapid revocation of affected certificates, which in turn protects Internet users from MiTM attacks, eavesdropping, etc.

## How is a PoCK created?

PoCK uses X.509 certificates as the container format for the proof. Various fields in the certificate are static:

- Serial number `0x1`
- notBefore `1950-01-01 midnight UTC`
- notAfter `1950-01-01 midnight UTC`
- subjectDN `CN=--------------------PROOF OF COMPROMISED KEY--------------------`
- issuerDN `CN=--------------------PROOF OF COMPROMISED KEY--------------------`
- Extensions `basicConstraints cA: false, critical: true`

These values were chosen so that a PoCK could not be confused with a valid certificate that may be created for practical use. In other words, the probability that the rightful possessor of the private key would create such a certificate which then could be leveraged by an attacker to revoke certificates even if the private key is not compromised (i.e., a DoS attack) is exceedingly low.

The PoCK contains the public key component of the compromised key and is signed by the compromised key. In other words, a PoCK is a self-signed certificate with a specific set of field values.

## How is a PoCK verified?

Verification of the PoCK is as simple as verifying the signature using the public key contained in the certificate.

To obtain the set of certificates that need to be revoked, the SPKI hash of the PoCK can be used to search for certificates that have the same SPKI hash.

## Acknowledgements

Thanks to Kenji Urushima for the [jsrsasign](https://github.com/kjur/jsrsasign) library, which provides the primitives for key handling, certificate creation, etc. for the proof-of-concept implementation. 