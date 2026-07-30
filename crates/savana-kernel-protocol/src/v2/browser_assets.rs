/// Fixed, dependency-free browser client for the four loopback-only Savana UI
/// origins. It deliberately keeps opaque capabilities in page memory and uses
/// canonical CBOR for every script-initiated request.
pub const SAVANA_BROWSER_SCRIPT_V2: &[u8] = br####""use strict";
(() => {
  const $ = (selector) => document.querySelector(selector);
  const status = (message, failed = false) => {
    const node = $("#savana-status");
    if (node) {
      node.textContent = message;
      node.setAttribute("data-failed", failed ? "true" : "false");
    }
  };
  const concat = (...parts) => {
    const size = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  };
  const head = (major, value) => {
    const n = typeof value === "bigint" ? value : BigInt(value);
    if (n < 24n) return Uint8Array.of((major << 5) | Number(n));
    if (n <= 0xffn) return Uint8Array.of((major << 5) | 24, Number(n));
    if (n <= 0xffffn) {
      return Uint8Array.of((major << 5) | 25, Number(n >> 8n), Number(n & 0xffn));
    }
    if (n <= 0xffffffffn) {
      return Uint8Array.of(
        (major << 5) | 26,
        Number((n >> 24n) & 0xffn),
        Number((n >> 16n) & 0xffn),
        Number((n >> 8n) & 0xffn),
        Number(n & 0xffn)
      );
    }
    const out = new Uint8Array(9);
    out[0] = (major << 5) | 27;
    let remaining = n;
    for (let index = 8; index >= 1; index -= 1) {
      out[index] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    return out;
  };
  const cborUnsigned = (value) => head(0, value);
  const cborBytes = (value) => concat(head(2, value.length), value);
  const cborText = (value) => {
    const encoded = new TextEncoder().encode(value);
    return concat(head(3, encoded.length), encoded);
  };
  const cborArray = (...values) => concat(head(4, values.length), ...values);
  const cborNull = Uint8Array.of(0xf6);
  const closed = (tag) => cborArray(cborUnsigned(tag));
  const nonce = () => crypto.getRandomValues(new Uint8Array(32));
  const b64urlDecode = (value) => {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/")
      + "=".repeat((4 - value.length % 4) % 4);
    const raw = atob(padded);
    return Uint8Array.from(raw, (character) => character.charCodeAt(0));
  };
  const b64urlEncode = (value) => {
    let raw = "";
    for (const byte of value) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const decode = (bytes) => {
    let offset = 0;
    const length = (additional) => {
      if (additional < 24) return additional;
      const count = additional === 24 ? 1 : additional === 25 ? 2
        : additional === 26 ? 4 : additional === 27 ? 8 : 0;
      if (count === 0 || offset + count > bytes.length) throw new Error("invalid CBOR length");
      let value = 0n;
      for (let index = 0; index < count; index += 1) {
        value = (value << 8n) | BigInt(bytes[offset++]);
      }
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) return value;
      return Number(value);
    };
    const item = () => {
      if (offset >= bytes.length) throw new Error("truncated CBOR");
      const initial = bytes[offset++];
      const major = initial >> 5;
      const additional = initial & 31;
      if (major === 7 && additional === 22) return null;
      if (major === 7 && additional === 20) return false;
      if (major === 7 && additional === 21) return true;
      const size = length(additional);
      if (major === 0) return size;
      if (major === 2 || major === 3) {
        const count = Number(size);
        if (offset + count > bytes.length) throw new Error("truncated CBOR bytes");
        const value = bytes.slice(offset, offset + count);
        offset += count;
        return major === 2 ? value : new TextDecoder("utf-8", {fatal: true}).decode(value);
      }
      if (major === 4) {
        const value = [];
        for (let index = 0; index < Number(size); index += 1) value.push(item());
        return value;
      }
      throw new Error("unsupported CBOR type");
    };
    const value = item();
    if (offset !== bytes.length) throw new Error("trailing CBOR");
    return value;
  };
  const post = async (path, body) => {
    const response = await fetch(path, {
      method: "POST",
      headers: {"Content-Type": "application/cbor"},
      body,
      cache: "no-store",
      credentials: "omit",
      redirect: "error"
    });
    if (!response.ok) throw new Error(`request failed (${response.status})`);
    return new Uint8Array(await response.arrayBuffer());
  };
  const transferForm = (origin, path, transfer, newTab = false) => {
    const form = document.createElement("form");
    form.method = "post";
    form.action = `${origin}${path}`;
    if (newTab) {
      form.target = "_blank";
      form.rel = "noopener";
    }
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "transfer";
    input.value = b64urlEncode(transfer);
    form.append(input);
    document.body.append(form);
    form.submit();
  };
  const webAuthnOptions = (encoded) => {
    const options = JSON.parse(new TextDecoder().decode(encoded));
    options.challenge = b64urlDecode(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((entry) => ({
        ...entry,
        id: b64urlDecode(entry.id)
      }));
    }
    if (options.user && typeof options.user.id === "string") {
      options.user.id = b64urlDecode(options.user.id);
    }
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((entry) => ({
        ...entry,
        id: b64urlDecode(entry.id)
      }));
    }
    return options;
  };
  const assertion = (credential) => {
    const response = credential.response;
    if (!response.userHandle || response.userHandle.byteLength !== 32) {
      throw new Error("hardware credential did not return its bound principal");
    }
    return cborArray(
      cborBytes(new Uint8Array(credential.rawId)),
      cborBytes(new Uint8Array(response.authenticatorData)),
      cborBytes(new Uint8Array(response.clientDataJSON)),
      cborBytes(new Uint8Array(response.signature)),
      cborBytes(new Uint8Array(response.userHandle))
    );
  };
  const printable = (value) => {
    if (value instanceof Uint8Array) {
      if (value.length <= 64) {
        return `bytes:${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
      }
      return `bytes:${value.length}`;
    }
    if (typeof value === "bigint") return value.toString();
    if (Array.isArray(value)) return value.map(printable);
    return value;
  };

  const runJarvis = async (main) => {
    if (!main || main.dataset.bootstrap !== "true") return;
    const selectorText = location.pathname.split("/").pop();
    const selector = b64urlDecode(selectorText);
    if (selector.length !== 32) throw new Error("invalid bootstrap selector");
    status("Resolving the one-time kernel bootstrap...");
    const response = await fetch("/v2/bootstrap/continue", {
      method: "POST",
      headers: {"Content-Type": "application/cbor"},
      body: cborArray(cborBytes(selector), cborBytes(nonce())),
      cache: "no-store",
      credentials: "omit",
      redirect: "error"
    });
    if (!response.ok) throw new Error(`bootstrap failed (${response.status})`);
    const html = await response.text();
    document.open();
    document.write(html);
    document.close();
  };

  const finishAuthentication = async (purpose, preAuthentication) => {
    const tag = purpose === "ingress" ? 1 : purpose === "approval-display" ? 2 : 3;
    const requestNonce = nonce();
    status("Waiting for the hardware authenticator...");
    const begun = decode(await post(
      "/v2/ui-auth/begin",
      cborArray(cborUnsigned(tag), cborBytes(preAuthentication), cborBytes(requestNonce))
    ));
    if (!Array.isArray(begun) || begun.length !== 3 || begun[0] !== tag) {
      throw new Error("authentication ceremony type mismatch");
    }
    const credential = await navigator.credentials.get({
      publicKey: webAuthnOptions(begun[2])
    });
    if (!credential) throw new Error("hardware authentication was cancelled");
    const finished = decode(await post(
      "/v2/ui-auth/finish",
      cborArray(
        cborUnsigned(tag),
        cborBytes(begun[1]),
        cborBytes(requestNonce),
        assertion(credential)
      )
    ));
    if (finished[0] === 1 && purpose === "ingress") {
      transferForm("http://localhost:8767", "/v2/ui-auth/complete", finished[2]);
      return;
    }
    if (finished[0] === 3 && purpose === "agent") {
      transferForm("http://localhost:8768", "/v2/ui-auth/complete", finished[2]);
      return;
    }
    if (finished[0] === 2 && purpose === "approval-display") {
      await showApproval(finished[1]);
      return;
    }
    throw new Error("unexpected authentication settlement");
  };

  const showApproval = async (tab) => {
    const view = decode(await post("/v2/approval/display", cborBytes(tab)));
    const main = $("main");
    main.replaceChildren();
    const heading = document.createElement("h1");
    heading.textContent = "Review Savana approval";
    const summary = document.createElement("pre");
    summary.textContent = JSON.stringify(printable(view), null, 2);
    const deny = document.createElement("button");
    deny.textContent = "Deny";
    const approve = document.createElement("button");
    approve.textContent = "Approve";
    main.append(heading, summary, deny, approve);
    const decide = async (decision) => {
      deny.disabled = true;
      approve.disabled = true;
      const requestNonce = nonce();
      const begun = decode(await post(
        "/v2/approval/decision/begin",
        cborArray(cborBytes(tab), cborBytes(requestNonce), closed(decision))
      ));
      const credential = await navigator.credentials.get({
        publicKey: webAuthnOptions(begun[1])
      });
      if (!credential) throw new Error("approval authentication was cancelled");
      const result = decode(await post(
        "/v2/approval/decision/finish",
        cborArray(cborBytes(begun[0]), cborBytes(requestNonce), assertion(credential))
      ));
      status(result === 2 ? "Approved. You may close this page." : "Denied. You may close this page.");
    };
    deny.addEventListener("click", () => decide(1).catch(fail));
    approve.addEventListener("click", () => decide(2).catch(fail));
    status("Confirm the exact digest projection with your hardware authenticator.");
  };

  const runEnrollment = (main) => {
    const start = $("#savana-enrollment-start");
    const handleInput = $("#savana-enrollment-handle");
    const codeInput = $("#savana-enrollment-code");
    if (!start || !handleInput || !codeInput) throw new Error("enrollment controls are missing");
    start.addEventListener("click", async () => {
      start.disabled = true;
      const enrollment = decode(b64urlDecode(handleInput.value.trim()));
      if (!(enrollment instanceof Uint8Array) || enrollment.length !== 32) {
        throw new Error("invalid enrollment handle");
      }
      const code = codeInput.value;
      if (!code || code.length > 256) throw new Error("invalid enrollment code");
      const beginNonce = nonce();
      const begun = decode(await post(
        "/v2/webauthn/enroll/begin",
        cborArray(cborBytes(enrollment), cborBytes(beginNonce), cborText(code))
      ));
      codeInput.value = "";
      handleInput.value = "";
      const credential = await navigator.credentials.create({
        publicKey: webAuthnOptions(begun[1])
      });
      if (!credential || !credential.response || !credential.response.attestationObject) {
        throw new Error("hardware enrollment was cancelled");
      }
      const finished = decode(await post(
        "/v2/webauthn/enroll/finish",
        cborArray(
          cborBytes(begun[0]),
          cborBytes(nonce()),
          cborBytes(new Uint8Array(credential.rawId)),
          cborBytes(new Uint8Array(credential.response.clientDataJSON)),
          cborBytes(new Uint8Array(credential.response.attestationObject))
        )
      ));
      status(`Credential enrolled (${b64urlEncode(finished[0])}).`);
    });
  };

  const runApproval = (main) => {
    if (main && main.dataset.enrollment === "true") {
      runEnrollment(main);
      return;
    }
    if (!main || !main.dataset.preAuthentication) return;
    const encoded = b64urlDecode(main.dataset.preAuthentication);
    const preAuthentication = decode(encoded);
    if (!(preAuthentication instanceof Uint8Array) || preAuthentication.length !== 32) {
      throw new Error("invalid pre-authentication capability");
    }
    const button = $("#savana-authenticate");
    if (!button) throw new Error("authentication control is missing");
    button.addEventListener("click", () => {
      button.disabled = true;
      finishAuthentication(main.dataset.purpose, preAuthentication).catch(fail);
    });
  };

  const runIngress = (main) => {
    if (!main || !main.dataset.ingressTab) return;
    const tab = decode(b64urlDecode(main.dataset.ingressTab));
    const submit = $("#savana-ingress-submit");
    const input = $("#savana-ingress-input");
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      const content = new TextEncoder().encode(input.value);
      if (content.length === 0) throw new Error("input is empty");
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", content));
      let begun = decode(await post(
        "/v2/input/begin",
        cborArray(
          cborUnsigned(1),
          cborBytes(tab),
          cborBytes(nonce()),
          closed(1),
          cborUnsigned(content.length),
          cborBytes(digest)
        )
      ));
      let sequence = begun[1];
      const maximum = 64 * 1024;
      for (let offset = 0; offset < content.length; offset += maximum) {
        const chunk = content.slice(offset, Math.min(offset + maximum, content.length));
        const accepted = decode(await post(
          "/v2/input/chunk",
          cborArray(
            cborUnsigned(2),
            cborBytes(tab),
            cborBytes(nonce()),
            cborUnsigned(sequence),
            cborBytes(chunk)
          )
        ));
        sequence = accepted[1] + 1;
        status(`Uploaded ${Math.min(offset + maximum, content.length)} of ${content.length} bytes...`);
      }
      const finalized = decode(await post(
        "/v2/input/finalize",
        cborArray(cborUnsigned(3), cborBytes(tab), cborBytes(nonce()), cborBytes(digest))
      ));
      if (finalized[0] === 3) {
        transferForm("http://localhost:8766", "/v2/ui-auth/accept", finalized[1], true);
        submit.disabled = false;
        submit.textContent = "Check approval and commit";
      } else if (finalized[0] === 5) {
        status("Input committed to the Rust kernel.");
      } else {
        throw new Error("input was not committed");
      }
    });
  };

  const agentActionBody = (tab, tag, reference) => cborArray(
    cborUnsigned(2),
    cborBytes(tab),
    cborBytes(nonce()),
    reference
      ? cborArray(cborUnsigned(tag), cborBytes(reference))
      : cborArray(cborUnsigned(tag))
  );
  const agentButton = (container, label, action) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.addEventListener("click", () => action(button).catch(fail));
    container.append(button);
  };
  const loadAgentView = async (tab, documentReference) => {
    const response = decode(await post(
      "/v2/agent/view",
      cborArray(
        cborUnsigned(1),
        cborBytes(tab),
        cborBytes(nonce()),
        cborBytes(documentReference),
        cborArray(),
        cborUnsigned(1024 * 1024)
      )
    ));
    $("#savana-agent-view").textContent = JSON.stringify(printable(response[0]), null, 2);
    return response[1];
  };
  const runAgent = async (main) => {
    if (!main || !main.dataset.agentTab || !main.dataset.agentDocument) return;
    const tab = decode(b64urlDecode(main.dataset.agentTab));
    const documentReference = decode(b64urlDecode(main.dataset.agentDocument));
    const controls = $("#savana-agent-actions");
    const result = $("#savana-agent-result");
    const act = async (tag, reference, button) => {
      button.disabled = true;
      const response = decode(await post(
        "/v2/agent/action",
        agentActionBody(tab, tag, reference)
      ));
      result.textContent = JSON.stringify(printable(response), null, 2);
      const postCarrier = (response[0] === 1 || response[0] === 5 || response[0] === 8)
        ? response[1] : null;
      if (postCarrier && postCarrier[0] === 7) {
        transferForm("http://localhost:8767", "/v2/bootstrap/accept", postCarrier[1], true);
      } else if (postCarrier && postCarrier[0] === 8) {
        transferForm("http://localhost:8766", "/v2/ui-auth/accept", postCarrier[1], true);
      }
      button.disabled = false;
      status("Kernel action completed. Approval pages open separately so this tab keeps its capabilities.");
      await rebuild();
    };
    const rebuild = async () => {
      const objects = await loadAgentView(tab, documentReference);
      controls.replaceChildren();
      agentButton(controls, "Run planner", (button) => act(2, null, button));
      agentButton(controls, "Open follow-up input", (button) => act(1, null, button));
      agentButton(controls, "Close session", (button) => act(9, null, button));
      for (const object of objects) {
        const [tag, reference] = object;
        if (tag === 1) {
          agentButton(controls, "Prepare final release", (button) => act(6, reference, button));
          agentButton(controls, "Revoke vault", (button) => act(8, reference, button));
        } else if (tag === 2) {
          agentButton(controls, "Propose plan step", (button) => act(3, reference, button));
        } else if (tag === 3) {
          agentButton(controls, "Evaluate pending tool", (button) => act(4, reference, button));
        } else if (tag === 4) {
          agentButton(controls, "Dispatch tool", (button) => act(5, reference, button));
        } else if (tag === 5) {
          agentButton(controls, "Dispatch release", (button) => act(7, reference, button));
        } else if (tag === 6) {
          agentButton(controls, "Refresh execution", (button) => act(10, reference, button));
        } else if (tag === 7) {
          agentButton(controls, "Refresh release", (button) => act(11, reference, button));
        }
      }
    };
    await rebuild();
    status("Authenticated kernel view loaded.");
  };

  const fail = (error) => {
    status(error instanceof Error ? error.message : "Savana UI failed closed", true);
  };
  const main = $("main");
  const port = location.port;
  Promise.resolve()
    .then(() => {
      if (port === "8765") return runJarvis(main);
      if (port === "8766") return runApproval(main);
      if (port === "8767") return runIngress(main);
      if (port === "8768") return runAgent(main);
      throw new Error("unauthorized Savana UI origin");
    })
    .catch(fail);
})();
"####;
