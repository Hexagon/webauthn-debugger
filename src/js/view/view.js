import { register, login } from "../frontend/frontend.js";
import uuid from "https://cdn.jsdelivr.net/npm/uuid@8.3.2/dist/esm-browser/v4.js";
import jsnview from "https://cdn.jsdelivr.net/npm/jsnview@2.0.4/build/index.esm.js";
import { functions } from "https://unpkg.com/fido2-lib@3.1.6/test/helpers/fido2-helpers.js?module";

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
	const options = {
		showLen: false,
		showType: false,
		showBrackets: true,
		showFoldmarker: false,
		colors: { boolean: '#ff2929', null: '#ff2929', string: '#690', number: '#905', float: '#002f99' }
	}
	const treeView = jsnview(jsonData, options); // returns HTMLElement
	return treeView;
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
	logEntryHTML += "<tr><td class=\"json-view\"><div id=\"json-view-inner\"><pre><code id=\"request-"+randomId+"\"></code></pre></div></td><td>→</td><td class=\"json-view\"><div class=\"json-view-inner\"><pre><code id=\"response-"+randomId+"\"></code></pre></div></td></tr></tbody></table>";
	$('#log-'+target).append(logEntryHTML);
	$('#request-'+randomId).append(showJson(base64ify(unprotectKey(functions.cloneObject(senderJson)))));
	$('#response-'+randomId).append(showJson(base64ify(unprotectKey(functions.cloneObject(receiverJson)))));
}

export { showJson, doLog };