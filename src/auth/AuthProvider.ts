import { randomBytes } from "crypto";

function convertDecimalToHex(dec) {
    return ('0' + dec.toString(16)).substr(-2)
}

function  sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}

function  base64urlencode(a) {
    let str = "";
    let bytes = new Uint8Array(a);
    let len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
    str += String.fromCharCode(bytes[i]);
    }
    return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function createCodeChallange(verifier:string){
    let hashed =  sha256(verifier);
    let base64encoded = base64urlencode(hashed);
    return base64encoded;
}

function getCodeverifier(){
    let array = new Uint32Array(56/2);
    crypto.getRandomValues(array);
    return Array.from(array, convertDecimalToHex).join('');
}

export const ConstructLoginURL = (tenantName, redirectURI, policyName, clientID, scope) =>{
    const encoded_uri = encodeURI(redirectURI)
    let nonce: string = randomBytes(16).toString('base64');
    const code_verifier = getCodeverifier();
    const code_challenge = createCodeChallange(code_verifier);
    let uri = `https://${tenantName}.b2clogin.com/${tenantName}.onmicrosoft.com/oauth2/v2.0/authorize?p=${policyName}&client_id=${clientID}&redirect_uri=${encoded_uri}&scope=${scope}&response_type=code&prompt=login`
    return uri+"&response_mode=form_post" +"&nonce="+nonce + "&code_challenge="+code_challenge+"&code_challenge_method=S256"
}