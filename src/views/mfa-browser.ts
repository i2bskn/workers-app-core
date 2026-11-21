// This script is served by the Worker on its own origin. Only the public options and assertion go to the browser.
export const mfaBrowserScript = `"use strict";
const form = document.querySelector("[data-webauthn]");
if (form) {
  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    const button = form.querySelector("button");
    const status = form.querySelector("[role=status]");
    button.disabled = true;
    status.textContent = "";
    try {
      const registering = form.dataset.webauthn === "enroll";
      if (!window.isSecureContext || typeof PublicKeyCredential === "undefined") {
        throw new Error("このブラウザまたは接続ではパスキーを利用できません。");
      }
      const optionsResult = await fetch("/auth/mfa/webauthn/options", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}"
      });
      if (!optionsResult.ok) throw new Error("認証を開始できませんでした。もう一度ログインしてください。");
      const json = await optionsResult.json();
      const parse = registering
        ? PublicKeyCredential.parseCreationOptionsFromJSON
        : PublicKeyCredential.parseRequestOptionsFromJSON;
      if (!parse || !PublicKeyCredential.prototype.toJSON) {
        throw new Error("パスキーを利用するにはブラウザを更新してください。");
      }
      const options = { publicKey: parse.call(PublicKeyCredential, json) };
      const credential = registering
        ? await navigator.credentials.create(options)
        : await navigator.credentials.get(options);
      if (!credential) throw new Error("パスキーの操作を完了できませんでした。");
      form.elements.response.value = JSON.stringify(credential.toJSON());
      form.submit();
    } catch (error) {
      status.textContent = error.name === "NotAllowedError"
        ? "パスキーの操作がキャンセルされたか、有効期限が切れました。"
        : error.message || "パスキーを利用できませんでした。";
      button.disabled = false;
    }
  });
}
`;
