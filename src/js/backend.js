import { } from "./browser-workaround.js";
import { tools, Fido2Lib } from "fido2/dist/main.js";
const { base64 } = tools;
import { getConfig } from "./config.js";

const session = new Map();

class Fido2 {

	f2l;

	constructor(rpId, rpName, rpIcon, timeout) {
		this.f2l = new Fido2Lib({
			timeout,
			rpId,
			rpName,
			rpIcon: rpIcon,
			challengeSize: 128,
			attestation: getConfig.attestation,
			cryptoParams: getConfig().cryptoParams,
			authenticatorAttachment: getConfig().authenticatorAttachment, // ["platform", "cross-platform"]
			authenticatorRequireResidentKey: getConfig().authenticatorRequireResidentKey,
			authenticatorUserVerification: getConfig().authenticatorUserVerification
		});
	}

	async registration(id) {
		const registrationOptions = await this.f2l.attestationOptions();
		
		// make sure to add registrationOptions.user.id
		registrationOptions.user = {
			id: id,
			name: `User created at (${new Date().toLocaleString()})`,
			displayName: `User created at (${new Date().toLocaleString()})`
			
		};

		registrationOptions.status = "ok";

		registrationOptions.challenge = base64.fromArrayBuffer(registrationOptions.challenge, true);

		return registrationOptions;
	}

	async attestation(clientAttestationResponse, origin, challenge) {
		const attestationExpectations = {
			challenge: challenge,
			origin: origin,
			factor: "either"
		};
		const regResult = await this.f2l.attestationResult(clientAttestationResponse, attestationExpectations); // will throw on error
		return regResult;
	}

	async login() {
		const assertionOptions = await this.f2l.assertionOptions();
		assertionOptions.challenge = base64.fromArrayBuffer(assertionOptions.challenge, true);
		assertionOptions.status = "ok";
		return assertionOptions;
	}

	async assertion(assertionResult, expectedAssertionResult) {
		const authnResult = await this.f2l.assertionResult(assertionResult, expectedAssertionResult); // will throw on error
		return authnResult;
	}
}

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
const randomBase64URLBuffer = (len) => {
	len = len || 32;
	const randomBytes = new Uint8Array(len);
	crypto.getRandomValues(randomBytes);
	return base64.fromArrayBuffer(randomBytes, true);
};

const backendRegister = async () => {

	const id = randomBase64URLBuffer();

	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);

	const challengeMakeCred = await f2l.registration(id);
    
	// Transfer challenge to session
	session.set("challenge", challengeMakeCred.challenge);

	// Respond with credentials
	return challengeMakeCred;
};


const backendAdd = async () => {

	if(!session.get("loggedIn")) {
		return {
			"status": "failed",
			"message": "User not logged in!"
		};
	}
		
	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);

	const challengeMakeCred = await f2l.registration(id);
    
	// Transfer challenge to session
	session.set("challenge", challengeMakeCred.challenge);

	// Respond with credentials
	return challengeMakeCred;
};

const backendLogin = async () => {

	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);

	const assertionOptions = await f2l.login();

	// Transfer challenge to session
	session.set("challenge", assertionOptions.challenge);

	return assertionOptions;
};

const backendResponse = async (webauthnResp) => {
	if(!webauthnResp       || !webauthnResp.id
    || !webauthnResp.rawId || !webauthnResp.response
    || !webauthnResp.type  || webauthnResp.type !== "public-key" ) {
		return {
			"status": "failed",
			"message": "Response missing one or more of id/rawId/response/type fields, or type is not public-key!"
		};
	}
	
	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);
	
	if(webauthnResp.response.attestationObject !== undefined) {
		/* This is create cred */
		const result = await f2l.attestation(webauthnResp, getConfig().origin, session.get("challenge"));
		console.log(result);
		session.set("loggedIn", true);

		return { "status": "ok" };

	} else if(webauthnResp.response.authenticatorData !== undefined) {
		webauthnResp.rawId = base64.toArrayBuffer(webauthnResp.rawId, true);
		webauthnResp.response.userHandle = webauthnResp.rawId;
		webauthnResp.response.clientDataJSON = base64.toString(webauthnResp.response.clientDataJSON, true);

		
				const assertionExpectations = {
					// Remove the following comment if allowCredentials has been added into authnOptions so the credential received will be validate against allowCredentials array.
					challenge: session.get("challenge"),
					origin: getConfig().origin,
					factor: "either",
					prevCounter: 0
				};

				const result = await f2l.assertion(webauthnResp, assertionExpectations);

		
		// authentication complete!
		if (result) {
			session.set("loggedIn", true);
			return { "status": "ok" };

		// Authentication failed
		} else {
			return {
				"status": "failed",
				"message": "Can not authenticate signature!"
			};
		}
	} else {
		return {
			"status": "failed",
			"message": "Can not authenticate signature!"
		};
	}
};

export { backendAdd, backendRegister, backendLogin, backendResponse, base64 };