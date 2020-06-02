let pockPem = null;

function createPock() {
    const certificatePem = $('#txtCertificatePem').val();
    const compromisedKeyPem = $('#txtCompromisedKeyPem').val();

    errorHandler(function () {
        pockPem = createProofOfCompromisedKey(certificatePem, compromisedKeyPem);

        displayMessage('success', 'The POCK has been successfully created');

        $('#createPockResult').text(pockPem);
        $('#createPockResultContainer').show();
    }, 'Could not create POCK');
}

function verifyPock() {
    const compromisedCertificatePem = $('#txtCompromisedCertificatePem').val();
    const pockCertificatePem = $('#txtPockCertificatePem').val();

    errorHandler(function () {
        verifyProofOfCompromisedKey(compromisedCertificatePem, pockCertificatePem);

        displayMessage('success', 'The POCK has been successfully verified as proof of compromise for the specified certificate');
    }, 'Could not verify POCK');
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
    const tr = $('<tr />');
    tr.append($('<th />', {scope: 'row', text: header}));
    tr.append($('<td />', {text: value}));

    return tr;
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

    const table = $('<table />', {'class': 'table table-sm'});

    const tbody = $('<tbody />');
    table.append(tbody);

    tbody
        .append(createListItem('Serial Number', certificate.getSerialNumberHex()))
        .append(createListItem('Issuer DN', certificate.getIssuerString()))
        .append(createListItem('Subject DN', certificate.getSubjectString()))
        .append(createListItem('Not After', zulutodate(certificate.getNotAfter().toLocaleString())))
        .append(createListItem('Certificate SHA-256 Thumbprint', getPemThumbprint(certificatePem)))
        .append(createListItem('SPKI SHA-256 Thumbprint', KJUR.crypto.Util.hashHex(certificate.getPublicKeyHex(), 'sha256')));

    parentDiv.append(table);

    if (displayExternalLinks) {
        const thumbprint = getPemThumbprint(certificatePem);

        parentDiv
            .append($('<a />', {href: getCrtshLinkForThumbprint(thumbprint), text: 'crt.sh', target: '_blank'}))
            .append($('<br />'))
            .append($('<a />', {href: getCensysLinkForThumbprint(thumbprint), text: 'censys.io', target: '_blank'}));
    }
}

function displayKeyDetails (keyPem, parentDiv) {
    parentDiv.empty();

    const key = KEYUTIL.getKey(keyPem);

    const table = $('<table />', {'class': 'table table-sm'});

    const tbody = $('<tbody />');
    table.append(tbody);

    tbody
        .append(createListItem('Key Type', getKeyType(key)));

    parentDiv.append(table);
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
        }, 'Could not parse POCK')
    });

    $('#btnCopyPockPem').click(function () { navigator.clipboard.writeText(pockPem); });
});
