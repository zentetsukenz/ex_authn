import { ExAuthn } from "./ex_authn.js";

let auth = new ExAuthn({
  base: "http://localhost:4500",
  beginRegistration: "/begin_registration",
  finishRegistration: "/finish_registration"
});

window.onload = (e) => {
  const registerButton = document.getElementById("register");
  const nameInput = document.getElementById("name");

  registerButton.onclick = (e) => {
    auth
      .register(nameInput.value)
      .then(resp => console.log(resp));
  };
};
