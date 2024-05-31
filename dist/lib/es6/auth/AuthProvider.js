import { randomBytes } from "crypto";
function convertDecimalToHex(dec) {
    return ('0' + dec.toString(16)).substr(-2);
}
function sha256(plain) {
    var encoder = new TextEncoder();
    var data = encoder.encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}
function base64urlencode(a) {
    var str = "";
    var bytes = new Uint8Array(a);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}
function createCodeChallange(verifier) {
    var hashed = sha256(verifier);
    var base64encoded = base64urlencode(hashed);
    return base64encoded;
}
function getCodeverifier() {
    var array = new Uint32Array(56 / 2);
    crypto.getRandomValues(array);
    return Array.from(array, convertDecimalToHex).join('');
}
export var ConstructLoginURL = function (tenantName, redirectURI, policyName, clientID, scope) {
    var encoded_uri = encodeURI(redirectURI);
    var nonce = randomBytes(16).toString('base64');
    var code_verifier = getCodeverifier();
    var code_challenge = createCodeChallange(code_verifier);
    var uri = "https://".concat(tenantName, ".b2clogin.com/").concat(tenantName, ".onmicrosoft.com/oauth2/v2.0/authorize?p=").concat(policyName, "&client_id=").concat(clientID, "&redirect_uri=").concat(encoded_uri, "&scope=").concat(scope, "&response_type=code&prompt=login");
    return uri + "&response_mode=form_post" + "&nonce=" + nonce + "&code_challenge=" + code_challenge + "&code_challenge_method=S256";
};
