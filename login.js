"use strict";

const form = document.getElementById("login-form");
const errorBox = document.getElementById("auth-error");
let changingPassword = window.location.pathname === "/change-password";

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function displayPasswordChange() {
  changingPassword = true;
  document.getElementById("auth-eyebrow").textContent = "REQUIRED SECURITY STEP";
  document.getElementById("auth-title").textContent = "Change your password";
  document.getElementById("auth-description").textContent = "Set a private password before accessing your workspace.";
  document.getElementById("username-field").hidden = true;
  document.getElementById("username").required = false;
  document.getElementById("password-label").textContent = "New password";
  document.getElementById("password").value = "";
  document.getElementById("password").autocomplete = "new-password";
  document.getElementById("confirm-field").hidden = false;
  document.getElementById("confirm-password").required = true;
  document.getElementById("submit-button").innerHTML = "Update password <span>→</span>";
  document.getElementById("auth-footnote").hidden = true;
  document.getElementById("password").focus();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  const password = document.getElementById("password").value;
  try {
    if (changingPassword) {
      if (password !== document.getElementById("confirm-password").value) {
        showError("The passwords do not match.");
        return;
      }
      const response = await fetch("/api/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Unable to update password.");
      window.location.assign(result.workspace);
      return;
    }

    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: document.getElementById("username").value, password })
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Sign-in failed.");
    if (result.mustChangePassword) {
      window.location.assign("/change-password");
      return;
    }
    window.location.assign(result.workspace);
  } catch (error) {
    showError(error.message);
  }
});

if (changingPassword) displayPasswordChange();
