(function () {
    const SERIAL_NUMBER = 0;
    const DATE = '500101000000Z';
    const CN_RDN_VALUE = '-'.repeat(20) + 'PROOF OF COMPROMISED KEY' + '-'.repeat(20);

    function getChallengeCertificateSubject () {
        return `/CN=${CN_RDN_VALUE}`;
    }

    function isSelfSigned (certificate) {
        const publicKey = certificate.getPublicKey();

        return certificate.getSubjectHex() == certificate.getIssuerHex() &&
            certificate.verifySignature(publicKey);
    }

    function verifyCertificateFields (certificate) {
        return parseInt(certificate.getSerialNumberHex(), 16) == SERIAL_NUMBER &&
            certificate.getNotBefore() == DATE &&
            certificate.getNotBefore() == certificate.getNotAfter() &&
            certificate.getSubjectString() == getChallengeCertificateSubject();
    }

    function getSignatureAlgorithmNameForKey (key) {
        switch (key.constructor) {
            case KJUR.crypto.ECDSA:
                switch (key.getShortNISTPCurveName()) {
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

    window.getPemThumbprint = function(pem) {
        const hex = pemtohex(pem);

        return KJUR.crypto.Util.hashHex(hex, 'sha256');
    }

    window.readCertificatePem = function (certificatePem) {
        const certificate = new X509();

        certificate.readCertPEM(certificatePem);

        return certificate;
    }

    window.createProofOfCompromisedKey = function (privateKeyPem) {
        const key = KEYUTIL.getKey(privateKeyPem);

        const dn = getChallengeCertificateSubject();
        const sigAlgName = getSignatureAlgorithmNameForKey(key);

        const challengeCertificatePem = KJUR.asn1.x509.X509Util.newCertPEM({
            serial: {int: SERIAL_NUMBER},
            sigalg: {name: sigAlgName},
            issuer: {str: dn},
            subject: {str: dn},
            notbefore: {str: DATE},
            notafter: {str: DATE},
            sbjpubkey: privateKeyPem,
            cakey: key
        });

        return challengeCertificatePem;
    };

    window.verifyProofOfCompromisedKey = function (compromisedCertificatePem, challengeCertificatePem) {
        const compromisedCertificate = compromisedCertificatePem ? readCertificatePem(compromisedCertificatePem) : null;
        const challengeCertificate = readCertificatePem(challengeCertificatePem);

        if (!verifyCertificateFields(challengeCertificate)) {
            throw 'PoCK does not contain the expected certificate field values';
        }

        if (!isSelfSigned (challengeCertificate)) {
            throw 'PoCK is not self-signed';
        }

        if (compromisedCertificate && compromisedCertificate.getPublicKeyHex() != challengeCertificate.getPublicKeyHex()) {
            throw 'Compromised certificate and PoCK public keys do not match';
        }
    };
})();