import { } from "./browser-workaround.js";
import { tools, Fido2Lib } from "https://cdn.jsdelivr.net/npm/fido2-lib@3.2.2/dist/main.js";
const { base64 } = tools;
import { getConfig } from "./config.js";

const session = new Map();
const database = {
    users: {}
};

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

	async registration(username, displayName, id) {
		const registrationOptions = await this.f2l.attestationOptions();
		
		// make sure to add registrationOptions.user.id
		registrationOptions.user = {
			id: id,
			name: username,
			displayName: displayName
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

// Clean username
const username = { clean: function (username) {
	let usernameClean = username.replace(/[^a-z0-9\-_]/gi,"");
	usernameClean = usernameClean.toLowerCase();
	return usernameClean;
}};

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

const backendRegister = async (ctx) => {
	if(!ctx || !ctx.username || !ctx.name) {
		return {
			"status": "failed",
			"message": "ctx missing name or username field!"
		};
	}

	const usernameClean = username.clean(ctx.username),
		name     = usernameClean;

	if (!usernameClean) {
		return {
			"status": "failed",
			"message": "Invalid username!"
		};
	}

	if(database.users[usernameClean] && database.users[usernameClean].registered) {
		return {
			"status": "failed",
			"message": `Username ${usernameClean} already exists`
		};
	}

	const id = randomBase64URLBuffer();

	database.users[usernameClean] = {
		"name": name,
		"registered": false,
		"id": id,
		"authenticators": [],
		"oneTimeToken": undefined,
		"recoveryEmail": undefined
	};

	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);

	const challengeMakeCred = await f2l.registration(usernameClean, name, id);
    
	// Transfer challenge and username to session
	session.set("challenge", challengeMakeCred.challenge);
	session.set("username", usernameClean);

	// Respond with credentials
	return challengeMakeCred;
};


const backendAdd = async (ctx) => {
	if(!ctx) {
		return {
			"status": "failed",
			"message": "ctx missing name or username field!"
		};
	}

	if(!session.get("loggedIn")) {
		return {
			"status": "failed",
			"message": "User not logged in!"
		};
	}

	const 
		usernameClean = username.clean(session.get("username")),
		name     = usernameClean,
		id       = database.users[session.get("username")].id;

		
	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);

	const challengeMakeCred = await f2l.registration(usernameClean, name, id);
    
	// Transfer challenge to session
	session.set("challenge", challengeMakeCred.challenge);

	// Exclude existing credentials
	challengeMakeCred.excludeCredentials = database.users[session.get("username")].authenticators.map((e) => { return { id: base64.fromArrayBuffer(e.credId, true), type: e.type }; });

	// Respond with credentials
	return challengeMakeCred;
};

const backendLogin = async (ctx) => {
	if(!ctx || !ctx.username) {
		return {
			"status": "failed",
			"message": "ctx missing username field!"
		};
	}

	const usernameClean = username.clean(ctx.username);

	if(!database.users[usernameClean] || !database.users[usernameClean].registered) {
		return {
			"status": "failed",
			"message": `User ${usernameClean} does not exist!`
		};
	}

	
	const f2l = new Fido2(
		getConfig().rpId, 
		getConfig().rpName, 
		undefined, 
		90 * 1000 // 90 seconds
	);

	const assertionOptions = await f2l.login(usernameClean);

	// Transfer challenge and username to session
	session.set("challenge", assertionOptions.challenge);
	session.set("username", usernameClean);

	// Pass this, to limit selectable credentials for user... This may be set in response instead, so that
	// all of a users server (public) credentials isn't exposed to anyone
	const allowCredentials = [];
	for(const authr of database.users[session.get("username")].authenticators) {
		allowCredentials.push({
			type: authr.type,
			id: authr.credId,
			transports: authr.transports
		});
	}

	assertionOptions.allowCredentials = allowCredentials;

	session.set("allowCredentials", allowCredentials);

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
        
		const token = {
			credId: result.authnrData.get("credId"),
			publicKey: result.authnrData.get("credentialPublicKeyPem"),
			type: webauthnResp.type,
			counter: result.authnrData.get("counter"),
			created: new Date().getTime(),
			transports: webauthnResp.transports
		};

		database.users[session.get("username")].authenticators.push(token);
		database.users[session.get("username")].registered = true;

		session.set("loggedIn", true);

		return { "status": "ok" };

	} else if(webauthnResp.response.authenticatorData !== undefined) {
		/* This is get assertion */
		const validAuthenticators = database.users[session.get("username")].authenticators;
		let winningAuthenticator;

		webauthnResp.rawId = base64.toArrayBuffer(webauthnResp.rawId, true);
		webauthnResp.response.userHandle = webauthnResp.rawId;
		for(const authrIdx in validAuthenticators) {
			const authr = validAuthenticators[authrIdx];
			try {

				const assertionExpectations = {
					// Remove the following comment if allowCredentials has been added into authnOptions so the credential received will be validate against allowCredentials array.
					allowCredentials: session.get("allowCredentials"),
					challenge: session.get("challenge"),
					origin: getConfig().origin,
					factor: "either",
					publicKey: authr.publicKey,
					prevCounter: authr.counter,
					userHandle: authr.credId
				};

				const result = await f2l.assertion(webauthnResp, assertionExpectations);

				winningAuthenticator = result;
				if (database.users[session.get("username")].authenticators) {
					database.users[session.get("username")].authenticators[authrIdx].counter = result.authnrData.get("counter");
				}                    
				break;
        
			} catch (_e) {
				// Ignore
				// console.log(e);
			}
		}

		// authentication complete!
		if (winningAuthenticator && database.users[session.get("username")].registered ) {
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