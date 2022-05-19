import { register, login } from "./../frontend/frontend.js";
import uuid from "https://cdn.jsdelivr.net/npm/uuid@8.3.2/dist/esm-browser/v4.js";
import JSONFormatter from "https://cdn.jsdelivr.net/npm/json-formatter-js@2.3.4/dist/json-formatter.esm.js";
console.log(JSONFormatter);

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
	for (var property in obj) {
		if (obj.hasOwnProperty(property)) {
			if (typeof obj[property] == "object") {
				obj[property] = base64ify(obj[property]);
			} else if (obj[property] instanceof Uint8Array || obj[property] instanceof ArrayBuffer) {
				obj[property] = base64.fromArrayBuffer(obj[property]);
			}
		}
	}
	return obj;
}


function doLog(target, description, sender, receiver, senderJson, receiverJson) {
	let logEntryHTML = "",
		randomId = uuid();
	logEntryHTML += "<table width='100%'><thead><tr><td colspan='3'>" + description + "</td></tr></thead>";
	logEntryHTML += "<tbody><tr><td>"+sender+"</td><td>→</td><td>"+receiver+"</td></tr>";
	logEntryHTML += "<tr><td><pre><code id=\"request-"+randomId+"\"></code></pre></td><td>→</td><td><pre><code id=\"response-"+randomId+"\"></code></pre></td></tr></tbody></table>";
	$('#log-'+target).append(logEntryHTML);
	$('#request-'+randomId).append(showJson(base64ify(unprotectKey(senderJson))));
	$('#response-'+randomId).append(showJson(base64ify(unprotectKey(receiverJson))));
}

export { showJson, doLog };