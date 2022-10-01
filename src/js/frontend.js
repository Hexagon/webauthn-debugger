import { preformatMakeCredReq, publicKeyCredentialToJSON } from  "./utils.js";
import { backendAdd, backendLogin, backendRegister, backendResponse, base64 } from "./backend.js";
import { parseAttestationObject, parseClientResponse } from "https://cdn.jsdelivr.net/npm/fido2-lib@3.3.3/dist/main.js";
import { doLog } from "./view.js";

/* Handle for register form submission */
async function register (username, additional) {
    
	// Username and name is the same in our example
	const name = username;

	// Step 1 - Prepare publicKeyCredentialCreationOptions
	console.log("Registration Step 1 - Request publicKeyCredentialCreationOptions for user: ", username);
	const publicKeyCredentialCreationOptions = additional ? await backendAdd({username, name}) : await backendRegister({username, name});
	if(publicKeyCredentialCreationOptions.status !== "ok")
		throw new Error(`Server responed with error. The message is: ${publicKeyCredentialCreationOptions.message}`);

	const publicKey = preformatMakeCredReq(publicKeyCredentialCreationOptions);

	doLog("registration", "Request credentials create options", "Browser", "RP", username, publicKey);

	// Step 2 - Request credentials from browser
	console.log("Registration Step 2 - Request credential, navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions }), publicKeyCredentialCreationOptions = ", publicKey);
	const credentialsCreateResponse = await navigator.credentials.create({ publicKey });

	doLog("registration", "Request credentials from authenticator", "Browser", "Authenticator", publicKey, credentialsCreateResponse);

	// Step 3 - Run getTransports if it is supported
	if (credentialsCreateResponse.response && credentialsCreateResponse.response.getTransports) {
		credentialsCreateResponse.response.debugTransports = credentialsCreateResponse.response.getTransports();
	}

	// Step 3.1 - Run getTransports if it is supported
	if (credentialsCreateResponse.response && credentialsCreateResponse.response.getAuthenticatorData) {
		credentialsCreateResponse.response.debugAuthenticatorData = credentialsCreateResponse.response.getAuthenticatorData();
	}

	// Step 3.2 Decode attestation object
	if (credentialsCreateResponse.response && credentialsCreateResponse.response.attestationObject) {
		const decodedAttestationObject = await parseAttestationObject(credentialsCreateResponse.response.attestationObject);
		credentialsCreateResponse.response.debugAttestationObject = Object.fromEntries(decodedAttestationObject);
	}

	// Step 4 - Pass response from credentials.create to "backend"
	console.log("Registration Step 3 - Pass credential to backend, credential = ", credentialsCreateResponse);
	const finalResponse = await backendResponse(credentialsCreateResponse);
	
	doLog("registration", "Pass crendentials from RP", "Browser", "RP", credentialsCreateResponse, finalResponse);

	// Done!
	if(finalResponse.status === "ok") {
		alert('Registration OK');
	} else {
		alert(`Server responed with error. The message is: ${finalResponse.message}`);
	}
}

/* Handler for login form submission */
async function login(username) {

	// Step 1 - Get assertionOptions for username from "backend"
	console.log("Assertion Step 1 - backendLogin(username): username = ", username);

	const assertionOptions = await backendLogin({ username: username });	
	if(assertionOptions.status !== "ok")
		throw new Error(`Server responed with error. The message is: ${assertionOptions.message}`);
		
	doLog("assertion", "Get assertion options for user", "Browser", "RP", { username: username }, assertionOptions);

	assertionOptions.challenge = base64.toArrayBuffer(assertionOptions.challenge, true);

	// Step 2 - get assertions from browser
	console.log("Assertion Step 2 - navigator.credentials.get({publicKey: assertionOptions}), assertionOptions = ", assertionOptions);
	const credentialsGetResponseJson = publicKeyCredentialToJSON(await navigator.credentials.get({ publicKey: assertionOptions } ));
	doLog("assertion", "Request credentials from authenticator", "Browser", "Authenticator", { publicKey: assertionOptions } , credentialsGetResponseJson);

	// Step 3 - Pass response from credentials.create to "backend"
	console.log("Assertion Step 3 - Pass credential to backend, credential = ", credentialsGetResponseJson);
	const finalResponse = await backendResponse(credentialsGetResponseJson);
	doLog("assertion", "Pass crendentials from RP", "Browser", "RP", credentialsGetResponseJson, finalResponse);

	// Done!
	if(finalResponse.status === "ok") {
		alert('Assertion OK');
	} else {
		alert(`Server responed with error. The message is: ${finalResponse.message}`);
	}
}

export { register, login };