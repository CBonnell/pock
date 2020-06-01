let pockPem = null;

function createPock() {
    const certificatePem = $('#txtCertificatePem').val();
    const compromisedKeyPem = $('#txtCompromisedKeyPem').val();

    errorHandler(function () {
        pockPem = createProofOfCompromisedKey(certificatePem, compromisedKeyPem);

        $('#createPockResult').text(pockPem);
        $('#createPockResultContainer').show();
    }, 'Could not create proof of compromised key');
}

function verifyPock() {
    const compromisedCertificatePem = $('#txtCompromisedCertificatePem').val();
    const pockCertificatePem = $('#txtPockCertificatePem').val();

    errorHandler(function () {
        verifyProofOfCompromisedKey(compromisedCertificatePem, pockCertificatePem);

        displayMessage('success', 'The Proof of Compromised Key has been successfully verified.')
    }, 'Could not verify proof of compromised key');
}

function getCrtshLinkForThumbprint(thumbprint) {
    return `https://crt.sh?sha256=${thumbprint}`
}

function getCensysLinkForThumbprint(thumbprint) {
    return `https://censys.io/certificates?q=parsed.fingerprint_sha256%3A+${thumbprint}`
}

function displayMessage(messageClass, message, heading) {
    const div = $('<div />', {'class': `alert alert-${messageClass} alert-dismissible fade show`, role: 'alert'});

    const span = $('<span />');
    if (heading) {
        span.append($('<strong />', {text: `${heading}: `}));
    }
    span.append(document.createTextNode(message));
    div.append(span);

    const button = $('<button />', {'class': 'close', type: 'button', 'data-dismiss': 'alert', 'aria-label': 'Close'});
    button.append($('<span />', {'aria-hidden': 'true', text: '\u00d7'}));

    div.append(button);

    $('#message-display').empty().append(div);
}

function displayError(message, heading) {
    displayMessage('danger', message, heading);
}

function createListItem (header, value) {
    const a = $('<a />', {href: '#', 'class': 'list-group-item list-group-item-action flex-column align-items-start py-0'});
    const div = $('<div />', {'class': 'd-flex'});
    a.append(div);

    div.append($('<h5 />', {text: header}));

    a.append($('<p />', {text: value}));

    return a;
}

function getKeyType (key) {
    switch (key.constructor) {
        case RSAKey:
            return 'RSA';
        case KJUR.crypto.ECDSA:
            return 'ECDSA';
        default:
            throw 'Unknown key type: ' + key.constructor;
    } 
}

function displayCertificateDetails (certificatePem, parentDiv, displayExternalLinks) {
    parentDiv.empty();

    const certificate = readCertificatePem(certificatePem);

    const group = $('<div />', {'class': 'list-group'});

    group
        .append(createListItem('Serial Number', certificate.getSerialNumberHex()))
        .append(createListItem('Issuer DN', certificate.getIssuerString()))
        .append(createListItem('Subject DN', certificate.getSubjectString()))
        .append(createListItem('Not After', zulutodate(certificate.getNotAfter().toLocaleString())))
        .append(createListItem('SHA-256 Thumbprint', getCertificateThumbprint(certificatePem)));

    parentDiv.append(group);

    if (displayExternalLinks) {
        const thumbprint = getCertificateThumbprint(certificatePem);

        parentDiv
            .append($('<a />', {href: getCrtshLinkForThumbprint(thumbprint), text: 'crt.sh', target: '_blank'}))
            .append($('<br />'))
            .append($('<a />', {href: getCensysLinkForThumbprint(thumbprint), text: 'censys.io', target: '_blank'}));
    }
}

function displayKeyDetails (keyPem, parentDiv) {
    parentDiv.empty();

    const key = KEYUTIL.getKey(keyPem);

    const group = $('<div />', {'class': 'list-group'});

    group
        .append(createListItem('Key Type', getKeyType(key)));

    parentDiv.append(group);
}

function errorHandler (f, heading) {
    try {
        f();
    }
    catch (e) {
        console.error(e);

        displayError(e.message || e, heading);
    }
}

$(function () {
    const txtCertificatePem = $('#txtCertificatePem');
    const txtCompromisedKeyPem = $('#txtCompromisedKeyPem');

    const txtCompromisedCertificatePem = $('#txtCompromisedCertificatePem');
    const txtPockCertificatePem = $('#txtPockCertificatePem');

    txtCertificatePem.on('input', function () {
        errorHandler(function () {
            displayCertificateDetails(txtCertificatePem.val(), $('#compromisedCertificateDetailsCreate'), true);
        }, 'Could not parse compromised certificate')
    });
    txtCompromisedKeyPem.on('input', function () {
        errorHandler(function () {
            displayKeyDetails(txtCompromisedKeyPem.val(), $('#compromisedKeyDetails'));
        }, 'Could not parse compromised key');
    });

    txtCompromisedCertificatePem.on('input', function () {
        errorHandler(function () {
            displayCertificateDetails(txtCompromisedCertificatePem.val(), $('#compromisedCertificateDetailsVerify'), true);
        }, 'Could not parse compromised certificate')
    });
    txtPockCertificatePem.on('input', function () {
        errorHandler(function () {
            displayCertificateDetails(txtPockCertificatePem.val(), $('#pockCertificateDetailsVerify'));
        }, 'Could not parse POCK certificate')
    });

    $('#btnCopyPockPem').click(function () { navigator.clipboard.writeText(pockPem); });
});
