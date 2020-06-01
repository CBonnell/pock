
function createPock() {
    let certificatePem = $('#txtCertificatePem').val();
    let compromisedKeyPem = $('#txtCompromisedKeyPem').val();

    let proof = createProofOfKeyCompromise(certificatePem, compromisedKeyPem);
    $('#output').text(proof);

    navigator.clipboard.writeText(proof);
}

function getCrtshLinkForThumbprint(thumbprint) {
    return `https://crt.sh?sha256=${thumbprint}`
}

function getCensysLinkForThumbprint(thumbprint) {
    return `https://censys.io/certificates?q=parsed.fingerprint_sha256%3A+${thumbprint}`
}

function displayCertificateDetails (certificatePem, parentDiv, displayExternalLinks) {
    parentDiv.empty();

    try {
        var certificate = readCertificatePem(certificatePem);
    }
    catch (e) {
        console.error(e);

        return;
    }

    const createListItem = function (header, value) {
        const a = $('<a />', {href: '#', 'class': 'list-group-item list-group-item-action flex-column align-items-start py-0'});
        const div = $('<div />', {'class': 'd-flex'});
        a.append(div);

        div.append($('<h5 />', {text: header}));

        a.append($('<p />', {text: value}));

        return a;
    }

    const group = $('<div />', {'class': 'list-group'});

    group
        .append(createListItem('Serial Number', certificate.getSerialNumberHex()))
        .append(createListItem('Issuer DN', certificate.getIssuerString()))
        .append(createListItem('Subject DN', certificate.getSubjectString()))
        .append(createListItem('Not Before', zulutodate(certificate.getNotBefore().toLocaleString())))
        .append(createListItem('Not After', zulutodate(certificate.getNotAfter().toLocaleString())));

    parentDiv.append(group);

    if (displayExternalLinks) {
        const thumbprint = getCertificateThumbprint(certificatePem);

        parentDiv
            .append($('<a />', {href: getCrtshLinkForThumbprint(thumbprint), text: 'crt.sh', target: '_blank'}))
            .append($('<br />'))
            .append($('<a />', {href: getCensysLinkForThumbprint(thumbprint), text: 'censys.io', target: '_blank'}));
    }
}

function displayKeyDetails () {

}

$(function () {
    const txtCertificatePem = $('#txtCertificatePem');

    txtCertificatePem.on('input', function () { displayCertificateDetails(txtCertificatePem.val(), $('#compromisedCertificateDetails'), true); });
    $('#txtCompromisedKeyPem').on('input', displayKeyDetails);

});
