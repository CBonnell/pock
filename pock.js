(function () {
    const SERIAL_NUMBER = 0;
    const DATE = '500101000000Z';
    const O_RDN_VALUE = '-'.repeat(20) + 'PROOF OF COMPROMISED KEY' + '-'.repeat(20);

    function readCertificatePem (certificatePem) {
        const certificate = new X509();

        certificate.readCertPEM(certificatePem);

        return certificate;
    }

    function getChallengeCertificateSubject (certificatePem) {
        const hex = pemtohex(certificatePem);

        // get certificate SHA-256 thumbprint
        const thumbprint = KJUR.crypto.Util.hashHex(hex, 'sha256');

        return `/CN=${thumbprint}/O=${O_RDN_VALUE}`;
    }

    function isSelfSigned (certificate) {
        const publicKey = certificate.getPublicKey();

        return certificate.getSubjectHex() == certificate.getIssuerHex() &&
            certificate.verifySignature(publicKey);
    }

    function verifyCertificateFields (certificate) {
        return certificate.getSerialNumber() == SERIAL_NUMBER &&
            certificate.getNotBefore() == DATE &&
            certificate.getNotBefore() == certificate.getNotAfter();
    }

    function getSignatureAlgorithmNameForKey (key) {
        switch (key.constructor) {
            case KJUR.crypto.ECDSA:
                switch (key.getShortNISTCurveName()) {
                    case 'P-256':
                        return 'SHA256withECDSA';
                    case 'P-384':
                        return 'SHA384withECDSA';
                    default:
                        throw 'Unsupported ECDSA curve';
                }
            case RSAKey:
                return 'SHA256withRSA';
            default:
                throw 'Unsupported key type: ' + key.constructor;
        }
    }

    window.createProofOfKeyCompromise = function (compromisedCertificatePem, privateKeyPem) {
        const compromisedCertificate = readCertificatePem(compromisedCertificatePem);
        const key = KEYUTIL.getKey(privateKeyPem);

        const dn = getChallengeCertificateSubject(compromisedCertificatePem);
        const sigAlgName = getSignatureAlgorithmNameForKey(key);

        const publicKeyPem = KEYUTIL.getPEM(compromisedCertificate.getPublicKey());

        const challengeCertificatePem = KJUR.asn1.x509.X509Util.newCertPEM({
            serial: {int: SERIAL_NUMBER},
            sigalg: {name: sigAlgName},
            issuer: {str: dn},
            subject: {str: dn},
            notbefore: {str: DATE},
            notafter: {str: DATE},
            sbjpubkey: publicKeyPem,
            cakey: key
        });

        const challengeCertificate = readCertificatePem(challengeCertificatePem);

        if (!challengeCertificate.verifySignature(compromisedCertificate.getPublicKey())) {
            throw 'The public key in the certificate does not match the compromised private key';
        }

        return challengeCertificatePem;
    };

    window.verifyProofOfKeyCompromise = function (compromisedCertificatePem, challengeCertificatePem) {
        const compromisedCertificate = readCertificatePem(compromisedCertificatePem);
        const challengeCertificate = readCertificatePem(challengeCertificatePem);

        if (!verifyCertificateFields(challengeCertificate)) {
            throw 'Challenge certificate does not contain the expected certificate field values';
        }

        if (compromisedCertificate.getPublicKeyHex() != challengeCertificate.getPublicKeyHex()) {
            throw 'Compromised certificate and challenge certificate public keys do not match';
        }

        if (!isSelfSigned (challengeCertificate)) {
            throw 'Challenge certificate is not self-signed';
        }

        if (challengeCertificate.getSubjectString() != getChallengeCertificateSubject(compromisedCertificate)) {
            throw 'Challenege certificate subject does not match compromised certificate thumbprint';
        }
    };
})();