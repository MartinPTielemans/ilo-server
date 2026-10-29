// Runs the passkey ceremonies for the sign-in pages. WebAuthn wants
// ArrayBuffers where the server's JSON has base64url strings.

const toBytes = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

const toText = (buffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const json = await response.json();
  if (!response.ok) throw new Error(json.error || "The server refused the passkey.");
  return json;
}

async function register() {
  const { publicKey } = await post("/authorize/passkey/register");
  publicKey.challenge = toBytes(publicKey.challenge);
  publicKey.user.id = toBytes(publicKey.user.id);
  for (const credential of publicKey.excludeCredentials ?? []) credential.id = toBytes(credential.id);
  const credential = await navigator.credentials.create({ publicKey });
  return post("/authorize/passkey/register/finish", {
    id: credential.id,
    rawId: toText(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toText(credential.response.attestationObject),
      clientDataJSON: toText(credential.response.clientDataJSON),
    },
    extensions: credential.getClientExtensionResults(),
  });
}

async function login() {
  const { publicKey } = await post("/authorize/passkey/login");
  publicKey.challenge = toBytes(publicKey.challenge);
  for (const credential of publicKey.allowCredentials ?? []) credential.id = toBytes(credential.id);
  const credential = await navigator.credentials.get({ publicKey });
  const response = credential.response;
  return post("/authorize/passkey/login/finish", {
    id: credential.id,
    rawId: toText(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toText(response.authenticatorData),
      clientDataJSON: toText(response.clientDataJSON),
      signature: toText(response.signature),
      userHandle: response.userHandle ? toText(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  });
}

for (const button of document.querySelectorAll("[data-passkey]")) {
  // Without WebAuthn, the page's other way on is the only one.
  if (!window.PublicKeyCredential) {
    button.hidden = true;
    continue;
  }
  button.addEventListener("click", async () => {
    const error = document.getElementById("passkey-error");
    error.hidden = true;
    button.disabled = true;
    try {
      const { redirect } = await (button.dataset.passkey === "register" ? register() : login());
      location.assign(redirect);
    } catch (failure) {
      error.textContent = failure.name === "NotAllowedError" ? "The passkey was cancelled." : failure.message;
      error.hidden = false;
      button.disabled = false;
    }
  });
}
