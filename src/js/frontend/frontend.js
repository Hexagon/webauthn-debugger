/* global base64, loadMainContainer,  */
import { base64 } from "../backend/backend.js";
import { preformatMakeCredReq } from  "./utils.js";
import { backendAdd, backendLogin, backendRegister, backendResponse } from "../backend/backend.js";
import { showJson, doLog } from "../view/view.js";

/* Handle for register form submission */
async function register (username, additional) {
    
	// Username and name is the same in our example
	const name = username;

	// Step 1 - Prepare publicKeyCredentialCreationOptions
	console.log("registration", "Registration Step 1 - Request publicKeyCredentialCreationOptions for user: ", username);
	const publicKeyCredentialCreationOptions = additional ? await backendAdd({username, name}) : await backendRegister({username, name});
	if(publicKeyCredentialCreationOptions.status !== "ok")
		throw new Error(`Server responed with error. The message is: ${publicKeyCredentialCreationOptions.message}`);

	const publicKey = preformatMakeCredReq(publicKeyCredentialCreationOptions);

	doLog("registration", "Request credentials create options", "Browser", "RP", username, publicKeyCredentialCreationOptions);

	// Step 2 - Request credentials from browser
	console.log("Registration Step 2 - Request credential, navigator.credentials.create({ publicKey: publicKeyCredentialCreationOptions }), publicKeyCredentialCreationOptions = ", publicKeyCredentialCreationOptions);
	showJson("publicKeyCredentialCreationOptions", publicKeyCredentialCreationOptions);
	const credentialsCreateResponse = await navigator.credentials.create({ publicKey });

	doLog("registration", "Request credentials from authenticator", "Browser", "Authenticator", publicKeyCredentialCreationOptions, credentialsCreateResponse);

	// Step 3 - Run getTransports if it is supported
	if (credentialsCreateResponse.getTransports) {
		credentialsCreateResponse.transports = credentialsCreateResponse.getTransports();
	}

	// Step 4 - Pass response from credentials.create to "backend"
	console.log("Registration Step 3 - Pass credential to backend, credential = ", credentialsCreateResponse);
	const finalResponse = await backendResponse(credentialsCreateResponse);
	
	doLog("registration", "Pass crendentials from RP", "Browser", "RP", credentialsCreateResponse, finalResponse);

	// Done!
	if(finalResponse.status === "ok") {
		alert('Registration OK');
		console.log("Registration OK");
	} else {
		console.log("Registration Not OK");
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
	
	const credentialsGetResponse = await navigator.credentials.get({ publicKey: assertionOptions } );
	doLog("assertion", "Request credentials from authenticator", "Browser", "Authenticator", { publicKey: assertionOptions } , credentialsGetResponse);

	// Step 3 - OK!
	console.log("Assertion Step 3 - credentialsGetResponse = ", credentialsGetResponse);
	if(credentialsGetResponse !== null) {
		alert("Assertion OK");
		loadMainContainer();
	} else {
		console.log(`Assertion Not OK: ${credentialsGetResponse}`);
		alert(`Assertion Not OK: ${credentialsGetResponse}`);
	}
}

export { register, login };