function createPock() {
    let certificatePem = $('#txtCertificatePem').val();
    let compromisedKeyPem = $('#txtCompromisedKeyPem').val();

    let proof = createProofOfKeyCompromise(certificatePem, compromisedKeyPem);
    $('#output').text(proof);

    navigator.clipboard.writeText(proof);
}