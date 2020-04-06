const base64js = require("base64-js");

class ExAuthn {
  constructor({base, beginRegistration, finishRegistration}) {
    this.beginRegistrationURL = new URL(beginRegistration, base);
    this.finishRegistrationURL = new URL(finishRegistration, base);
  }

  async register(username, options) {
    let credentialOptions;
    try {
      credentialOptions = await this._fetchJson(this.beginRegistrationURL, {
        method: "POST",
        body: {
          username: username,
          options: options
        }
      });
    } catch (err) {
      console.error(err);
      throw err;
    }

    let credential = await this._createCredential(credentialOptions);

    return await this._submitCredential(credential);
  }

  async _createCredential({publicKey}) {
    publicKey.challenge = this._decode(publicKey.challenge);
    publicKey.user.id = this._decode(publicKey.user.id);
    if (publicKey.excludeCredentials) {
      for (var i = 0; i < publicKey.excludeCredentials.length; i++) {
        publicKey.excludeCredentials[i].id = this._decode(publicKey.excludeCredentials[i].id);
      }
    }

    return await navigator.credentials.create({
      publicKey: publicKey
    });
  }

  async _submitCredential(credential) {
    let attestationObject = this._pack(credential.response.attestationObject);
    let clientDataJSON = this._pack(credential.response.clientDataJSON);
    let rawId = this._pack(credential.rawId);

    let finalCredential;
    try {
      finalCredential = await this._fetchJson(this.finishRegistrationURL, {
        method: "POST",
        body: {
          id: credential.id,
          raw_id: this._encode(rawId),
          type: credential.type,
          response: {
            attestation_object: this._encode(attestationObject),
            client_data_json: this._encode(clientDataJSON)
          }
        }
      });
    } catch (err) {
      console.error(err);
      throw err;
    }

    return finalCredential;
  }

  async _fetchJson(url, options) {
    options.headers = options.headers || {};
    options.headers["Content-Type"] = "application/json; charset=utf-8";
    options.headers["Accept"] = "application/json";
    options.body = JSON.stringify(options.body);

    const response = await fetch(url, options);
    const body = await response.json();
    if (body.fail)
      throw body.fail;
    return body;
  }

  _decode(string) {
    return Uint8Array.from(atob(string), c => c.charCodeAt(0));
  }

  _encode(buffer) {
    return base64js.fromByteArray(buffer)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  _pack(data) {
    return new Uint8Array(data);
  }
}

export { ExAuthn };
