let pockPem = null;

function createPock() {
    const compromisedKeyPem = $('#txtCompromisedKeyPem').val();

    errorHandler(function () {
        pockPem = createProofOfCompromisedKey(compromisedKeyPem);

        displayMessage('success', 'The PoCK has been successfully created');

        $('#createPockResult').text(pockPem.replace(/\r/g, ''));
        $('#createPockResultContainer').show();

        displayCertificateDetails(pockPem, $('#createdPockDetails'));
    }, 'Could not create PoCK');
}

function verifyPock() {
    const compromisedCertificatePem = $('#txtCompromisedCertificatePem').val();
    const pockCertificatePem = $('#txtPockCertificatePem').val();

    errorHandler(function () {
        verifyProofOfCompromisedKey(compromisedCertificatePem, pockCertificatePem);

        displayMessage('success', compromisedCertificatePem ?
            'The PoCK has been successfully verified as proof of compromise for the specified certificate' :
            'The PoCK has been successfully verified');
    }, 'Could not verify PoCK');
}

function getCrtshLinkForThumbprint(type, thumbprint) {
    return `https://crt.sh?${type}=${thumbprint}`
}

function getCensysLinkForThumbprint(type, thumbprint) {
    return `https://censys.io/certificates?q=parsed.${type}%3A+${thumbprint}`
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

function createListItem (header, value, extra) {
    const tr = $('<tr />');
    tr.append($('<th />', {scope: 'row', text: header}));

    const td = $('<td />', {text: value});

    tr.append(td);
    if (extra) {
        td.append($('<br />'));
        td.append(extra);
    }

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

function displayCertificateDetails (certificatePem, parentDiv) {
    parentDiv.empty();

    const certificate = readCertificatePem(certificatePem);

    const table = $('<table />', {'class': 'table table-sm'});

    const tbody = $('<tbody />');
    table.append(tbody);

    const generateThumbprintLinks = function (crtshType, censysType, thumbprint) {
        const span = $('<span />', );
        span
            .append($('<a />', {href: getCrtshLinkForThumbprint(crtshType, thumbprint), target: '_blank', text: 'crt.sh'}))
            .append(document.createTextNode(' '))
            .append($('<a />', {href: getCensysLinkForThumbprint(censysType, thumbprint), target: '_blank', text: 'censys.io'}));

        return span;
    }

    const certificateThumbprint = getPemThumbprint(certificatePem);
    const spkiThumbprint = KJUR.crypto.Util.hashHex(certificate.getPublicKeyHex(), 'sha256');

    tbody
        .append(createListItem('Serial Number', certificate.getSerialNumberHex()))
        .append(createListItem('Issuer DN', certificate.getIssuerString()))
        .append(createListItem('Subject DN', certificate.getSubjectString()))
        .append(createListItem('Not After', zulutodate(certificate.getNotAfter().toLocaleString())))
        .append(createListItem(
            'Certificate SHA-256 Thumbprint',
            certificateThumbprint,
            generateThumbprintLinks('sha256', 'sha256_fingerprint', certificateThumbprint)))
        .append(createListItem(
            'SPKI SHA-256 Thumbprint',
            spkiThumbprint,
            generateThumbprintLinks('spkisha256', 'spki_subject_fingerprint', spkiThumbprint)));

    parentDiv.append(table);
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
    const txtCompromisedKeyPem = $('#txtCompromisedKeyPem');

    const txtCompromisedCertificatePem = $('#txtCompromisedCertificatePem');
    const txtPockCertificatePem = $('#txtPockCertificatePem');

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
        }, 'Could not parse PoCK')
    });

    $('#btnCopyPockPem').click(function () { navigator.clipboard.writeText(pockPem); });
});
