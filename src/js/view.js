import { register, login } from "./frontend.js";
import { base64 } from "./backend.js";
import uuid from "uuid";
import JSONFormatter from "json-formatter";
import { functions } from "fido2/test/helpers/fido2-helpers.js";

$("#button-register").click(async () => {
	$("#log-assertion").html('');
	$("#log-registration").html('');
	try {
		const username = $("#username")[0].value;
		if(!username) {
			alert("Username is missing!");
		} else {
			await register(username);
		}
	} catch(e) {
		alert(e);
	}
});

$("#button-login").click(async () => {   
	try {
		$("#log-assertion").html('');
		const username = $("#username")[0].value;
		if(!username) {
			alert("Username is missing!");
		} else {
			await login(username);
		}
	} catch(e) {
		alert(e);
	}
});

function showJson(jsonData) {
	const 
		  jsonFormatterObj = new JSONFormatter(jsonData, 3),
		  jsonFormatterElm = jsonFormatterObj.render();
	return jsonFormatterElm;
}

// Only done to be able to show PublicKeyCredential in jsonFormatter. Never do this.
function unprotectKey(mayBeAKey) {
	let unProtectedKey = {};
	if (mayBeAKey instanceof PublicKeyCredential) {
		const expectedProperties = ['authenticatorAttachment','id','rawId','response','type'];
		for(const expProp of expectedProperties) {
			unProtectedKey[expProp] = mayBeAKey[expProp];
		}
	} else {
		unProtectedKey = mayBeAKey;
	}
	return unProtectedKey;
}

function base64ify(obj) {
	const newObj = {};
	for (const property in obj) {
		if (obj[property] instanceof Uint8Array || obj[property] instanceof ArrayBuffer) {
			newObj[property] = base64.fromArrayBuffer(obj[property], true);
		} else if (typeof obj[property] === "object") {
			newObj[property] = base64ify(obj[property]);
		} else {
			newObj[property] = obj[property];
		}
	}
	return newObj || obj;
}


function doLog(target, description, sender, receiver, senderJson, receiverJson) {
	const randomId = uuid();
	let logEntryHTML = "";
	logEntryHTML += "<table width='100%'><thead><tr><td colspan='3'>" + description + "</td></tr></thead>";
	logEntryHTML += "<tbody><tr><td>"+sender+"</td><td>→</td><td>"+receiver+"</td></tr>";
	logEntryHTML += "<tr><td class=\"json-view\"><div class=\"json-view-inner\"><pre><code id=\"request-"+randomId+"\"></code></pre></div></td><td>→</td><td class=\"json-view\"><div class=\"json-view-inner\"><pre><code id=\"response-"+randomId+"\"></code></pre></div></td></tr></tbody></table>";
	$('#log-'+target).append(logEntryHTML);
	$('#request-'+randomId).append(showJson(base64ify(unprotectKey(functions.cloneObject(senderJson)))));
	$('#response-'+randomId).append(showJson(base64ify(unprotectKey(functions.cloneObject(receiverJson)))));
}

export { showJson, doLog };