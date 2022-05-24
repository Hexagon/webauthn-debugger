
import { base64 } from "../backend/backend.js";

/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
const publicKeyCredentialToJSON = (pubKeyCred) => {
	/* ----- DO NOT MODIFY THIS CODE ----- */
	if(pubKeyCred instanceof Array) {
		const arr = [];
		for(const i of pubKeyCred)
			arr.push(publicKeyCredentialToJSON(i));

		return arr;
	}

	if(pubKeyCred instanceof ArrayBuffer) {
		return base64.fromArrayBuffer(pubKeyCred,true);
	}

	if(pubKeyCred instanceof Object) {
		const obj = {};

		for (const key in pubKeyCred) {
			obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
		}

		return obj;
	}

	return pubKeyCred;
};

/**
 * Decodes arrayBuffer required fields.
 */
const preformatMakeCredReq = (makeCredReq) => {
	makeCredReq.challenge = base64.toArrayBuffer(makeCredReq.challenge,true);
	makeCredReq.user.id = base64.toArrayBuffer(makeCredReq.user.id,true);

	// Decode id of each excludeCredentials
	if (makeCredReq.excludeCredentials) {
		makeCredReq.excludeCredentials = makeCredReq.excludeCredentials.map((e) => { return { id: base64.toArrayBuffer(e.id, true), type: e.type };});
	}

	return makeCredReq;
};

export {publicKeyCredentialToJSON, preformatMakeCredReq};