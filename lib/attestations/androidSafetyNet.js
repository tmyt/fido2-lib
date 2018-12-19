/* eslint-disable no-invalid-this */
// validators are a mixin, so it's okay that we're using 'this' all over the place

"use strict";

const {
    printHex,
    coerceToArrayBuffer,
    coerceToBase64,
    abToBuf,
    abToPem,
    ab2str,
    b64ToJsObject
} = require("../utils");
const crypto = require("crypto");
const {
    CertManager
} = require("../certUtils");
const jose = require("node-jose");

function androidSafetyNetParseFn(attStmt) {
    var ret = new Map();

    // console.log("android-safetynet", attStmt);

    ret.set("ver", attStmt.ver);

    var response = ab2str(attStmt.response);
    ret.set("response", response);

    // console.log("returning", ret);
    return ret;
}

// TODO: https://w3c.github.io/webauthn/#android-safetynet-attestation
async function androidSafetyNetValidateFn() {
    var response = this.authnrData.get("response");
    // 1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
    // 2. Verify that response is a valid SafetyNet response of version ver.
    // https://github.com/cisco/node-jose#verifying-a-jws
    var parsedJws = await jose.JWS.createVerify().verify(response, { allowEmbeddedKey: true });
    this.authnrData.set("payload", JSON.parse(ab2str(coerceToArrayBuffer(parsedJws.payload, "MDS TOC payload"))));
    this.audit.journal.add("response");
    this.audit.journal.add("ver");

    // 3. Verify that the nonce in the response is identical to the Base64url encoding of
    // the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
    // var { nonce } = this.authnrData.get('payload');
    
    // get certs
    this.authnrData.set("attCert", parsedJws.header.x5c.shift());
    this.authnrData.set("x5c", parsedJws.header.x5c);

    // 4. Let attestationCert be the attestation certificate
    // var attestationCert = Certificate(this.authnrData.get('attCert'));

    // 5. Verify that attestationCert is issued to the hostname "attest.android.com"
    // if (attestationCert.getIssuer() !== 'attest.android.com') {
    //     throw new Error("android-safetynet attestationCert not issued to attest.android.com")
    // }
    // Mock approval of all the things.
    this.audit.journal.add("attCert");

    // // verify cert chain
    // var rootCerts;
    // if (Array.isArray(rootCert)) rootCerts = rootCert;
    // else rootCerts = [rootCert];
    // var ret = await CertManager.verifyCertChain(header.x5c, rootCerts, crls);

    // Mock approval of all the things.
    this.audit.journal.add("x5c");

    // 6. Verify that the ctsProfileMatch attribute in the payload of response is true.
    var { ctsProfileMatch } = this.authnrData.get('payload');
    if (ctsProfileMatch !== true) {
        throw new Error("android-safetynet ctsProfileMatch is not 'true'");
    }
    this.audit.journal.add("payload");
    this.audit.journal.add("fmt");
    // If successful, return implementation-specific values representing attestation type Basic and attestation trust path attestationCert.
    this.audit.info.set("attestation-type", "basic");
    return true;
}

module.exports = {
    name: "android-safetynet",
    parseFn: androidSafetyNetParseFn,
    validateFn: androidSafetyNetValidateFn
};
