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
      throw new Error("credential did not return its bound principal");
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

  const approvalDisplayText = async (view) => {
    if (!Array.isArray(view) || view.length !== 5
        || !Array.isArray(view[0]) || view[0].length !== 1
        || typeof view[3] !== "string" || view[3].length === 0
        || !(view[1] instanceof Uint8Array) || view[1].length !== 32
        || !(view[2] instanceof Uint8Array) || view[2].length !== 32
        || !(view[4] instanceof Uint8Array) || view[4].length !== 32
        || view[1].every((byte) => byte === 0)
        || view[2].every((byte) => byte === 0)
        || view[4].every((byte) => byte === 0)
        || view[3].normalize("NFC") !== view[3]
        || /[\u0000-\u001f\u007f-\u009f]/u.test(view[3])) {
      throw new Error("invalid approval display artifact");
    }
    const textBytes = new TextEncoder().encode(view[3]);
    if (textBytes.length > 1024 * 1024) throw new Error("approval display artifact is too large");
    const domain = new TextEncoder().encode("SAVANA_APPROVAL_DISPLAY_BYTES_V2\0");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(domain, textBytes)));
    if (!digest.every((byte, index) => byte === view[2][index])) {
      throw new Error("approval display digest mismatch");
    }
    return view[3];
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
    status("Waiting for your passkey or security key...");
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
    if (!credential) throw new Error("authentication was cancelled");
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
    const statusNode = $("#savana-status") || document.createElement("p");
    statusNode.id = "savana-status";
    main.replaceChildren();
    delete main.dataset.preAuthentication;
    main.append(statusNode);
    const heading = document.createElement("h1");
    heading.textContent = "Review Savana approval";
    const summary = document.createElement("pre");
    summary.textContent = await approvalDisplayText(view);
    const deny = document.createElement("button");
    deny.textContent = "Deny";
    const approve = document.createElement("button");
    approve.textContent = "Approve";
    main.append(heading, summary, deny, approve, statusNode);
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
      if (result !== decision) throw new Error("Approval response does not match your decision");
      status(result === 2 ? "Approved. You may close this page." : "Denied. You may close this page.");
    };
    deny.addEventListener("click", () => decide(1).catch(fail));
    approve.addEventListener("click", () => decide(2).catch(fail));
    status("Confirm the exact digest projection with your passkey or security key.");
  };

  const runEnrollment = (main) => {
    const start = $("#savana-enrollment-start");
    const handleInput = $("#savana-enrollment-handle");
    const codeInput = $("#savana-enrollment-code");
    if (!start || !handleInput || !codeInput) throw new Error("enrollment controls are missing");
    let attempted = false;
    start.addEventListener("click", () => (async () => {
      if (attempted) return;
      attempted = true;
      start.disabled = true;
      status("Starting credential registration...");
      const enrollment = decode(b64urlDecode(handleInput.value.trim()));
      if (!(enrollment instanceof Uint8Array) || enrollment.length !== 32) {
        throw new Error("invalid enrollment handle");
      }
      const code = codeInput.value;
      if (!code || code.length > 256) throw new Error("invalid enrollment code");
      // Never retain or automatically replay a one-time credential after an
      // uncertain request. A fresh enrollment must be explicitly initiated.
      codeInput.value = "";
      handleInput.value = "";
      const beginNonce = nonce();
      const begun = decode(await post(
        "/v2/webauthn/enroll/begin",
        cborArray(cborBytes(enrollment), cborBytes(beginNonce), cborText(code))
      ));
      const creationOptions = webAuthnOptions(begun[1]);
      status(creationOptions.attestation === "none"
        ? "Create a passkey. It may sync across your devices; this profile does not attest device-bound hardware."
        : "Register an attested, non-backup hardware security key.");
      const credential = await navigator.credentials.create({ publicKey: creationOptions });
      if (!credential || !credential.response || !credential.response.attestationObject) {
        throw new Error("credential enrollment was cancelled");
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
    })().catch(() => {
      codeInput.value = "";
      handleInput.value = "";
      status("Registration was not confirmed. The code may have expired, the connection may have failed, or verification was cancelled. Do not assume a credential was registered. Ask the administrator to check the outcome before starting a new registration.", true);
    }));
  };

  const runPrivateSession = (main) => {
    if (!main || main.dataset.privateSession !== "true") return;
    const input = $("#savana-private-transfer");
    const button = $("#savana-private-connect");
    if (main.dataset.privateTransfer) {
      input.value = main.dataset.privateTransfer;
      main.removeAttribute("data-private-transfer");
    }
    button.addEventListener("click", () => (async () => {
      button.disabled = true;
      const text = input.value.trim();
      if (!/^[A-Za-z0-9_-]{43}$/.test(text)) throw new Error("invalid private session handoff");
      const transfer = b64urlDecode(text);
      input.value = "";
      const begun = decode(await post("/v04/session/begin", cborArray(cborUnsigned(4), cborBytes(transfer))));
      if (!Array.isArray(begun) || begun.length !== 2 || begun[0] !== 4) throw new Error("invalid private session challenge");
      status("Authenticate this private task session. This does not approve tools or result publication.");
      const credential = await navigator.credentials.get({ publicKey: webAuthnOptions(begun[1]) });
      if (!credential) throw new Error("authentication was cancelled");
      const finished = decode(await post("/v04/session/finish", cborArray(cborUnsigned(4), cborBytes(transfer), assertion(credential))));
      if (!Array.isArray(finished) || finished.length !== 2 || finished[0] !== 4
          || !(finished[1] instanceof Uint8Array) || finished[1].length !== 32) throw new Error("invalid private session response");
      input.remove();
      button.remove();
      status("Authentication complete. Waiting for the kernel to validate this task session.");
      const browser = finished[1];
      const actions = $("#savana-private-actions");
      let offered = null;
      const poll = async () => {
        const response = decode(await post("/v04/session/poll", cborArray(cborUnsigned(4), cborBytes(browser))));
        if (!Array.isArray(response) || response.length !== 2 || response[0] !== 4
          || (response[1] !== null && (!(response[1] instanceof Uint8Array) || response[1].length !== 32))) throw new Error("Invalid private handoff");
        const transfer = response[1];
        if (transfer === null) {
          if (offered) actions.replaceChildren();
          offered = null;
        } else if (!offered || !transfer.every((b, i) => b === offered[i])) {
          offered = transfer;
          const review = document.createElement("button");
          review.type = "button";
          review.textContent = "Review pending action";
          review.addEventListener("click", () => transferForm("http://localhost:8766", "/v04/private-approval/accept", transfer, true));
          actions.replaceChildren(review);
          status("A pending action needs your separate review and approval.");
        }
        setTimeout(() => poll().catch(error => { browser.fill(0); actions.replaceChildren(); fail(error); }), 1500);
      };
      await poll();
    })().catch(error => { button.disabled = false; fail(error); }));
  };

  const runApproval = (main) => {
    if (main && main.dataset.privateSession === "true") return runPrivateSession(main);
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
    const recovery = document.createElement("section");
    const heading = document.createElement("h2");
    heading.textContent = "Recover an existing task authorization";
    const explanation = document.createElement("p");
    explanation.textContent = "Use the previously observed issuance request digest. Recovery does not create a new grant or reset its budget. Pending drafts still require task approval.";
    const requestInput = document.createElement("input");
    requestInput.id = "savana-task-request";
    requestInput.setAttribute("aria-label", "Issuance request digest (64 hexadecimal characters)");
    requestInput.setAttribute("maxlength", "64");
    requestInput.setAttribute("autocomplete", "off");
    const recover = document.createElement("button");
    recover.id = "savana-task-recover";
    recover.type = "button";
    recover.textContent = "Recover existing authorization";
    let pendingRecovery = null;
    const digestBytes = value => {
      if (!/^[0-9a-fA-F]{64}$/.test(value) || /^0{64}$/.test(value)) throw new Error("Enter the exact nonzero 64-character request digest");
      return Uint8Array.from(value.match(/../g), v => parseInt(v, 16));
    };
    recover.addEventListener("click", () => (async () => {
      recover.disabled = true;
      const expected = pendingRecovery || digestBytes(requestInput.value.trim());
      const response = decode(await post(
        pendingRecovery ? "/v2/task/approval/commit" : "/v2/task/recover",
        cborArray(cborUnsigned(pendingRecovery ? 7 : 9), cborBytes(tab), cborBytes(nonce()), cborBytes(expected))
      ));
      if (Array.isArray(response) && response.length === 1 && response[0] === 9) {
        pendingRecovery = null;
        requestInput.disabled = false;
        recover.textContent = "Recover existing authorization";
        status("Task authorization approval was denied.", true);
      } else {
        if (!Array.isArray(response) || response.length !== 3
          || !(response[1] instanceof Uint8Array) || response[1].length !== 32
          || !response[1].every((b, i) => b === expected[i])
          || !(response[2] instanceof Uint8Array) || response[2].length !== 32
          || response[2].every(b => b === 0)) throw new Error("Task recovery response mismatch");
        if (response[0] === 7) {
          pendingRecovery = null;
          requestInput.disabled = false;
          recover.textContent = "Recover existing authorization";
          status("Recovered existing task authorization receipt. No new grant or budget was created.");
        } else if (response[0] === 8) {
          pendingRecovery = expected;
          requestInput.disabled = true;
          transferForm("http://localhost:8766", "/v2/ui-auth/accept", response[2], true);
          recover.textContent = "Check task approval";
          status("Complete the separate task approval page, then check approval here.");
        } else throw new Error("Unexpected task recovery status");
      }
      recover.disabled = false;
    })().catch(fail));
    recovery.append(heading, explanation, requestInput, recover);
    main.append(recovery);
    const editor = document.createElement("section");
    const editorTitle = document.createElement("h2");
    editorTitle.textContent = "Define the task authorization";
    const loadContext = document.createElement("button");
    loadContext.id = "savana-task-context";
    loadContext.type = "button";
    loadContext.textContent = "Load current kernel task and tools";
    const editorBody = document.createElement("div");
    editor.append(editorTitle, loadContext, editorBody);
    main.append(editor);
    const privateSession = document.createElement("button");
    privateSession.id = "savana-open-private-session";
    privateSession.type = "button";
    privateSession.textContent = "Open private task session";
    privateSession.addEventListener("click", () => (async () => {
      privateSession.disabled = true;
      const response = decode(await post("/v04/session/open", cborArray(cborUnsigned(11), cborBytes(tab), cborBytes(nonce()))));
      if (!Array.isArray(response) || response.length !== 2 || response[0] !== 4
          || !(response[1] instanceof Uint8Array) || response[1].length !== 32) throw new Error("Invalid private session handoff");
      transferForm("http://localhost:8766", "/v04/session/accept", response[1], true);
      privateSession.disabled = false;
      status("Authenticate on the private session page. Tool approvals remain separate.");
    })().catch(error => { privateSession.disabled = false; fail(error); }));
    main.append(privateSession);
    const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
    const u64 = value => {
      if (!/^(0|[1-9][0-9]{0,19})$/.test(value)) throw new Error("Use an unsigned decimal integer");
      const n = BigInt(value);
      if (n > 18446744073709551615n) throw new Error("Integer exceeds the supported bound");
      return n;
    };
    loadContext.addEventListener("click", () => (async () => {
      loadContext.disabled = true;
      const c = decode(await post("/v2/task/context", cborArray(cborUnsigned(10), cborBytes(tab), cborBytes(nonce()))));
      if (!Array.isArray(c) || c.length !== 12 || c[0] !== 1
        || ![1,2,3,4,6].every(i => c[i] instanceof Uint8Array && c[i].length === 32)
        || !Array.isArray(c[10]) || c[10].length > 64 || !Array.isArray(c[11]) || c[11].length > 64) throw new Error("Invalid task context");
      editorBody.replaceChildren();
      const summary = document.createElement("p");
      summary.textContent = `Task ${hex(c[2])}. Input ${hex(c[6])}. ${c[9] ? 'Revision ' + c[9][1] + '; previous consumption remains.' : 'New authorization.'} Creating a draft requires input committed on this page. This page does not grant permission; separate task approval is required.`;
      editorBody.append(summary);
      for (const id of c[11]) {
        if (!(id instanceof Uint8Array) || id.length !== 32) throw new Error("Invalid pending request");
        const choose = document.createElement("button");
        choose.type = "button";
        choose.textContent = `Select pending request ${hex(id)}`;
        choose.addEventListener("click", () => {
          if (pendingRecovery) throw new Error("Finish the current task approval first");
          requestInput.value = hex(id);
          status("Pending request selected. Use Recover existing authorization to review it.");
        });
        editorBody.append(choose);
      }
      const tools = c[10].map(t => {
        if (!Array.isArray(t) || t.length !== 3 || !(t[0] instanceof Uint8Array) || t[0].length !== 32 || typeof t[1] !== "string" || !(t[2] instanceof Uint8Array)) throw new Error("Invalid tool context");
        const p = decode(t[2]);
        if (!Array.isArray(p) || p.length !== 8 || p[0] !== 1 || !Array.isArray(p[7])) throw new Error("Invalid signed business profile");
        return {id:t[0],name:t[1],bytes:t[2],profile:p};
      });
      if (!tools.length) {
        const unavailable = document.createElement("p");
        unavailable.textContent = "No active tool has a reviewed business profile. Deployment must provide signed profiles before a task can be authorized.";
        editorBody.append(unavailable);
        loadContext.disabled = false;
        return;
      }
      const controls = [];
      const makeInput = (parent, label, value = "") => {
        const node = document.createElement("input");
        node.value = value; node.setAttribute("aria-label", label);
        const text = document.createElement("label"); text.textContent = label; text.append(node);
        parent.append(text); controls.push(node); return node;
      };
      const clauseContainer = document.createElement("div");
      const addClause = document.createElement("button");
      addClause.id = "savana-task-add-clause"; addClause.type = "button"; addClause.textContent = "Add authorization clause";
      const create = document.createElement("button");
      create.id = "savana-task-prepare"; create.type = "button"; create.textContent = "Review and approve this task scope";
      const clauses = [];
      const add = () => {
        if (clauses.length >= 64) throw new Error("At most 64 clauses are supported");
        const box = document.createElement("fieldset");
        const title = document.createElement("legend"); title.textContent = `Clause ${clauses.length + 1}`; box.append(title);
        const id = makeInput(box, "Clause ID", String(clauses.length + 1));
        const single = makeInput(box, "Maximum magnitude per attempt", "1");
        const budget = makeInput(box, "Total magnitude budget", "1");
        const attempts = makeInput(box, "Maximum attempts (including failures)", "1");
        const predecessors = makeInput(box, "Predecessor clause IDs, comma-separated; all require verified success");
        const retry = makeInput(box, "Allow magnitude refund after proven no effect (true or false)", "false");
        const alternatives = [];
        const addAlternative = document.createElement("button");
        addAlternative.type = "button"; addAlternative.textContent = "Add another complete alternative"; controls.push(addAlternative);
        const addAlt = () => {
          if (alternatives.length >= 64) throw new Error("At most 64 alternatives are supported");
          const row = document.createElement("fieldset");
          const label = document.createElement("legend"); label.textContent = `Complete alternative ${alternatives.length + 1} (fields stay together)`; row.append(label);
          const selector = document.createElement("select"); selector.setAttribute("aria-label", "Approved tool profile"); controls.push(selector);
          tools.forEach((t,i) => { const o = document.createElement("option"); o.value = String(i); o.textContent = t.name; selector.append(o); });
          selector.value = "0";
          const fields = document.createElement("div"); row.append(selector, fields); box.append(row);
          const alternative = {tool:null, fields:[]};
          const select = () => {
            const tool = tools[Number(selector.value)]; if (!tool) throw new Error("Select a current tool");
            alternative.tool = tool; alternative.fields = []; fields.replaceChildren();
            const detail = document.createElement("p");
            detail.textContent = `Operation ${tool.profile[2]}; effect ${tool.profile[5]}; target ${hex(tool.profile[3])}; credential ${hex(tool.profile[4])}. Magnitude rule ${tool.profile[6][0]} (1: count field, 2: fixed count, 3: UTF-8 payload bytes), fixed value ${tool.profile[6][1]}.`;
            fields.append(detail);
            for (const f of tool.profile[7]) {
              if (!Array.isArray(f) || f.length !== 3) throw new Error("Invalid profile field");
              if (![1,2,5].includes(f[1])) continue;
              const value = makeInput(fields, `${f[0]} (${f[2] === 1 ? 'text' : f[2] === 2 ? 'unsigned integer' : 'true or false'})`, f[1] === 1 && tool.profile[5] === 7 ? `input:${hex(c[6])}` : "");
              alternative.fields.push({name:f[0],kind:f[2],input:value});
            }
          };
          selector.addEventListener("change", select); select(); alternatives.push(alternative);
        };
        addAlternative.addEventListener("click", () => { try { addAlt(); } catch(e) { fail(e); } });
        box.append(addAlternative); clauseContainer.append(box); addAlt();
        clauses.push({id,single,budget,attempts,predecessors,retry,alternatives});
      };
      addClause.addEventListener("click", () => { try { add(); } catch(e) { fail(e); } });
      editorBody.append(clauseContainer, addClause, create); add();
      create.addEventListener("click", () => (async () => {
        create.disabled = true; addClause.disabled = true; controls.forEach(node => { node.disabled = true; });
        const clauseBytes = clauses.map(clause => {
          const alternatives = clause.alternatives.map(a => {
            const fields = a.fields.slice().sort((x,y) => x.name < y.name ? -1 : x.name > y.name ? 1 : 0);
            const values = fields.map(f => {
              let v;
              if (f.kind === 1) v = JSON.stringify(f.input.value);
              else if (f.kind === 2) v = u64(f.input.value).toString();
              else if (f.kind === 3 && ["true","false"].includes(f.input.value)) v = f.input.value;
              else throw new Error("Unsupported control value");
              return JSON.stringify(f.name) + ":" + v;
            });
            const bytes = new TextEncoder().encode("{" + values.join(",") + "}");
            return cborArray(cborBytes(a.tool.id), cborBytes(cborArray(cborUnsigned(1), cborBytes(a.tool.bytes), cborBytes(bytes))));
          });
          const predecessors = clause.predecessors.value.trim() ? clause.predecessors.value.split(",").map(v => cborUnsigned(u64(v.trim()))) : [];
          if (!["true","false"].includes(clause.retry.value)) throw new Error("Retry must be true or false");
          return cborArray(cborUnsigned(u64(clause.id.value)), cborArray(...alternatives), cborUnsigned(u64(clause.single.value)), cborUnsigned(u64(clause.budget.value)), cborUnsigned(u64(clause.attempts.value)), cborArray(...predecessors), Uint8Array.of(clause.retry.value === "true" ? 0xf5 : 0xf4));
        });
        const identity = c[9] || [nonce(),1];
        const draft = cborArray(cborUnsigned(1), cborBytes(identity[0]), cborBytes(c[1]), cborBytes(c[2]), cborUnsigned(identity[1]), cborBytes(c[3]), cborBytes(c[4]), cborUnsigned(c[5]), cborUnsigned(c[7]), cborUnsigned(c[8]), cborBytes(c[6]), cborArray(...clauseBytes));
        const issuanceNonce = nonce();
        const framed = value => { const length = new Uint8Array(8); new DataView(length.buffer).setBigUint64(0, BigInt(value.length)); return concat(length, value); };
        const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", concat(new TextEncoder().encode("SAVANA_TASK_ISSUANCE_REQUEST_V2_SCHEMA1\0"), ...[c[3],c[2],c[1],issuanceNonce].map(framed))));
        // Expose the stable request identifier before transport: an uncertain
        // response can be recovered, not retried with a new authority identity.
        requestInput.value = hex(expected);
        status(`Task issuance request ${hex(expected)}. This is not an authorization.`);
        const response = decode(await post("/v2/task/approval/prepare", cborArray(cborUnsigned(6), cborBytes(tab), cborBytes(issuanceNonce), cborBytes(draft))));
        if (!Array.isArray(response) || response.length !== 3 || response[0] !== 8 || !(response[1] instanceof Uint8Array) || !response[1].every((b,i) => b === expected[i]) || response[1].length !== 32 || !(response[2] instanceof Uint8Array) || response[2].length !== 32 || response[2].every(b => b === 0)) throw new Error("Task approval response mismatch");
        pendingRecovery = expected; requestInput.disabled = true; recover.textContent = "Check task approval";
        transferForm("http://localhost:8766", "/v2/ui-auth/accept", response[2], true);
        status("Complete the separate task approval page, then check approval here. No authority has been installed by this form.");
      })().catch(fail));
      loadContext.disabled = false;
    })().catch(error => { loadContext.disabled = false; fail(error); }));
    const submit = $("#savana-ingress-submit");
    const input = $("#savana-ingress-input");
    let uploadedDigest = null;
    submit.addEventListener("click", () => (async () => {
      submit.disabled = true;
      if (!uploadedDigest) {
      const content = new TextEncoder().encode(input.value);
      if (content.length === 0) throw new Error("input is empty");
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", content));
      input.disabled = true;
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
      uploadedDigest = digest;
      }
      const finalized = decode(await post(
        "/v2/input/finalize",
        cborArray(cborUnsigned(3), cborBytes(tab), cborBytes(nonce()), cborBytes(uploadedDigest))
      ));
      if (finalized[0] === 3) {
        transferForm("http://localhost:8766", "/v2/ui-auth/accept", finalized[1], true);
        submit.disabled = false;
        submit.textContent = "Check approval and commit";
      } else if (finalized[0] === 5) {
        status("Input committed to the Rust kernel. Load the current task and tools to define its authorization.");
      } else {
        throw new Error("input was not committed");
      }
    })().catch(fail));
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
      agentButton(
        controls,
        "Run planner (share intent with configured third party)",
        (button) => act(16, null, button)
      );
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

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::SAVANA_BROWSER_SCRIPT_V2;

    #[test]
    fn enrollment_reports_uncertainty_without_replaying_codes() {
        let script =
            serde_json::to_string(std::str::from_utf8(SAVANA_BROWSER_SCRIPT_V2).unwrap()).unwrap();
        let harness = format!("const browserScript = {script};")
            + r####"
const assert = require('assert/strict'), vm = require('vm');
const bytes = b => Buffer.concat([Buffer.from([0x58,b.length]),b]);
const pair = (a,b) => Buffer.concat([Buffer.from([0x82]),bytes(a),bytes(b)]);
(async()=>{
for(const mode of ['invalid','network','expired','cancel','finish-failure','success']) {
  const nodes = new Map(), calls = [];
  const node = () => ({value:'',textContent:'',disabled:false,dataset:{},
    setAttribute(k,v){this[k]=v;},addEventListener(k,v){this[k]=v;}});
  const main=node(), handle=node(), code=node(), button=node(), status=node();
  main.dataset.enrollment='true';
  handle.value=mode==='invalid'?'AA':bytes(Buffer.alloc(32,1)).toString('base64url');
  code.value='one-time-secret';
  for(const [key,value] of [['main',main],['#savana-enrollment-handle',handle],
      ['#savana-enrollment-code',code],['#savana-enrollment-start',button],['#savana-status',status]]) nodes.set(key,value);
  const context={Uint8Array,TextEncoder,TextDecoder,Error,crypto:require('crypto').webcrypto,
    location:{port:'8766'},document:{querySelector:s=>nodes.get(s)},
    atob:s=>Buffer.from(s,'base64').toString('binary'),btoa:s=>Buffer.from(s,'binary').toString('base64'),
    navigator:{credentials:{create:async()=>{
      assert.equal(code.value,''); assert.equal(handle.value,'');
      if(mode==='cancel') throw Error('private authenticator details');
      return {rawId:Buffer.alloc(16,1),response:{clientDataJSON:Buffer.from('{}'),attestationObject:Buffer.alloc(32,2)}};
    }}},fetch:async path=>{
      calls.push(path); assert.equal(code.value,''); assert.equal(handle.value,'');
      if(mode==='network'||(mode==='finish-failure'&&calls.length===2)) throw Error('private network details');
      if(mode==='expired') return {ok:false,status:403};
      const body=calls.length===1?pair(Buffer.alloc(32,3),Buffer.from('{"challenge":"AA","attestation":"none"}')):
        Buffer.concat([Buffer.from([0x81]),bytes(Buffer.alloc(32,4))]);
      return {ok:true,arrayBuffer:async()=>body};
    }};
  vm.runInNewContext(browserScript,context);
  const settle=async check=>{for(let i=0;i<100;i++){if(check())return;await Promise.resolve();}throw Error('UI did not settle');};
  await settle(()=>typeof button.click==='function');
  button.click();
  await settle(()=>status['data-failed']==='true'||status.textContent.startsWith('Credential enrolled'));
  assert.equal(code.value,''); assert.equal(handle.value,''); assert.equal(button.disabled,true);
  assert.equal(status.textContent.includes('private '),false,'do not expose raw errors');
  assert.equal(status['data-failed'],mode==='success'?'false':'true');
  const count=calls.length; button.click(); await Promise.resolve(); await Promise.resolve();
  assert.equal(calls.length,count,'never replay enrollment automatically');
  assert.equal(count,mode==='invalid'?0:['success','finish-failure'].includes(mode)?2:1);
}
})().catch(e=>{console.error(e);process.exitCode=1;});
"####;
        let output = Command::new("node")
            .arg("-e")
            .arg(harness)
            .output()
            .expect("Node.js required");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn private_session_browser_authenticates_then_offers_only_separate_approval() {
        let script =
            serde_json::to_string(std::str::from_utf8(SAVANA_BROWSER_SCRIPT_V2).unwrap()).unwrap();
        let harness = format!("const browserScript = {script};")
            + r####"
const assert = require('assert/strict');
globalThis.crypto = require('crypto').webcrypto;
const timers = [], calls = [], forms = [], elements = new Map();
globalThis.setTimeout = callback => { timers.push(callback); return timers.length; };
const element = tag => ({ dataset:{}, children:[], value:'', disabled:false, textContent:'',
  setAttribute(name,value){ this[name]=value; },
  append(...nodes){ this.children.push(...nodes); },
  replaceChildren(...nodes){ this.children = nodes; },
  addEventListener(kind,fn){ this[kind] = fn; },
  remove(){ this.removed = true; },
  removeAttribute(name){ if(name==='data-private-transfer') delete this.dataset.privateTransfer; },
  submit(){ forms.push(this); }
});
const main=element('main'), input=element('input'), button=element('button'), status=element('p'), actions=element('div');
const handoff=Buffer.alloc(32,2), cap=Buffer.alloc(32,3), approval=Buffer.alloc(32,4);
main.dataset={privateSession:'true', privateTransfer:handoff.toString('base64url')};
elements.set('main',main); elements.set('#savana-private-transfer',input); elements.set('#savana-private-connect',button);
elements.set('#savana-status',status); elements.set('#savana-private-actions',actions);
globalThis.document={querySelector:s=>elements.get(s),createElement:element,body:element('body')};
globalThis.location={port:'8766',pathname:'/v04/session/accept'};
globalThis.localStorage={setItem(){throw Error('private token persisted');},getItem(){throw Error('private token read');}};
Object.defineProperty(globalThis,'navigator',{value:{credentials:{get:async ({publicKey})=>{
  assert.equal(publicKey.userVerification,'required');
  assert.equal(input.value,'');
  assert.equal(main.dataset.privateTransfer,undefined);
  return {rawId:Buffer.alloc(32,5),response:{authenticatorData:Buffer.alloc(37,6),clientDataJSON:Buffer.from('{}'),signature:Buffer.alloc(70,7),userHandle:Buffer.alloc(32,8)}};
}}}});
const response = b => Buffer.concat([Buffer.from([0x82,4,0x58,b.length]),b]);
globalThis.fetch=async(path,options)=>{
  calls.push([path,Buffer.from(options.body)]);
  assert.equal(options.method,'POST');
  let bytes;
  if(path==='/v04/session/begin'){
    assert.deepEqual(Buffer.from(options.body),response(handoff));
    bytes=response(Buffer.from('{"challenge":"AA","userVerification":"required"}'));
  } else if(path==='/v04/session/finish') bytes=response(cap);
  else if(path==='/v04/session/poll'){
    assert.deepEqual(Buffer.from(options.body),response(cap)); bytes=response(approval);
  } else throw Error('unexpected private API '+path);
  return {ok:true,arrayBuffer:async()=>bytes};
};
eval(browserScript);
const settle=async predicate=>{for(let i=0;i<100;i++){if(predicate())return;await Promise.resolve();}throw Error('UI did not finish: '+status.textContent);};
(async()=>{
  await settle(()=>typeof button.click==='function');
  button.click();
  await settle(()=>actions.children.length===1);
  assert.equal(forms.length,0,'identity authentication must not silently approve or navigate');
  assert.deepEqual(calls.map(c=>c[0]),['/v04/session/begin','/v04/session/finish','/v04/session/poll']);
  assert.equal(input.removed,true); assert.equal(button.removed,true);
  actions.children[0].click();
  assert.equal(forms.length,1);
  assert.equal(forms[0].action,'http://localhost:8766/v04/private-approval/accept');
  assert.equal(forms[0].target,'_blank'); assert.equal(forms[0].rel,'noopener');
  assert.equal(forms[0].children[0].value,approval.toString('base64url'));
  assert.equal(timers.length,1);
})().catch(e=>{console.error(e);process.exitCode=1;});
"####;
        let output = Command::new("node")
            .arg("-e")
            .arg(harness)
            .output()
            .expect("Node.js is required for browser behavior tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn planner_intent_opt_out_is_separate_and_does_not_replace_private_default() {
        let script = std::str::from_utf8(SAVANA_BROWSER_SCRIPT_V2).unwrap();
        assert!(script.contains("agentButton(controls, \"Run planner\", (button) => act(2"));
        assert!(script.contains("Run planner (share intent with configured third party)"));
        assert!(script.contains("(button) => act(16, null, button)"));
    }

    #[test]
    fn approval_dom_renders_complete_non_ascii_text_without_byte_summary() {
        for decision in [1, 2, 3] {
            let browser_script = std::str::from_utf8(SAVANA_BROWSER_SCRIPT_V2).unwrap();
            let mut harness = format!("const decision = {decision}; const browserScript = ");
            harness.push_str(&serde_json::to_string(browser_script).unwrap());
            harness.push_str(
            r####";
const exactText = "批准：é漢字 — " + "approval artifact ".repeat(6);
const elements = new Map();
let approvalText = null;
const element = (tag) => ({
  tagName: tag.toUpperCase(),
  dataset: {},
  disabled: false,
  textContent: "",
  children: [],
  setAttribute() {},
  append(...nodes) { for (const node of nodes) { this.children.push(node); if (node.id) elements.set('#' + node.id, node); } },
  replaceChildren() { this.children = []; elements.delete('#savana-status'); },
  addEventListener(kind, listener) { this[kind] = listener; }
});
const main = element("main");
main.dataset.purpose = "approval-display";
const preAuthentication = Uint8Array.of(0x58, 0x20, ...new Uint8Array(32).fill(0x11));
main.dataset.preAuthentication = Buffer.from(preAuthentication).toString("base64url");
const authenticate = element("button");
const status = element("p");
status.id = 'savana-status';
elements.set("main", main);
elements.set("#savana-authenticate", authenticate);
elements.set("#savana-status", status);
globalThis.document = {
  body: element("body"),
  querySelector(selector) { return elements.get(selector) ?? null; },
  createElement(tag) {
    const created = element(tag);
    if (tag === "pre") {
      Object.defineProperty(created, "textContent", {
        get() { return approvalText; },
        set(value) { approvalText = value; }
      });
    }
    return created;
  }
};
globalThis.location = {port: "8766", pathname: "/"};
Object.defineProperty(globalThis, "navigator", {value: {credentials: {get: async () => ({
  rawId: Uint8Array.of(1).buffer,
  response: {
    authenticatorData: Uint8Array.of(2).buffer,
    clientDataJSON: Uint8Array.of(3).buffer,
    signature: Uint8Array.of(4).buffer,
    userHandle: new Uint8Array(32).fill(5).buffer
  }
})}}, configurable: true});
const concat = (...parts) => {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};
const head = (major, length) => length < 24
  ? Uint8Array.of((major << 5) | length)
  : length <= 0xff
    ? Uint8Array.of((major << 5) | 24, length)
    : Uint8Array.of((major << 5) | 25, length >> 8, length & 0xff);
const unsigned = (value) => head(0, value);
const bytes = (value) => concat(head(2, value.length), value);
const text = (value) => {
  const encoded = new TextEncoder().encode(value);
  return concat(head(3, encoded.length), encoded);
};
const array = (...values) => concat(head(4, values.length), ...values);
const projection = new Uint8Array(32).fill(0x22);
const digest = new Uint8Array(require("crypto").createHash("sha256")
  .update(Buffer.from("SAVANA_APPROVAL_DISPLAY_BYTES_V2\0"))
  .update(Buffer.from(exactText))
  .digest());
const node = new Uint8Array(32).fill(0x55);
const responses = new Map([
  ["/v2/ui-auth/begin", array(unsigned(2), bytes(new Uint8Array(32).fill(0x33)), bytes(new TextEncoder().encode('{"challenge":"AA"}')))],
  ["/v2/ui-auth/finish", array(unsigned(2), bytes(new Uint8Array(32).fill(0x44)))],
  ["/v2/approval/display", array(array(unsigned(2)), bytes(projection), bytes(digest), text(exactText), bytes(node))],
  ["/v2/approval/decision/begin", array(bytes(new Uint8Array(32).fill(0x66)), bytes(new TextEncoder().encode('{"challenge":"AA"}')))],
  ["/v2/approval/decision/finish", unsigned(decision)]
]);
globalThis.fetch = async (path) => {
  const response = responses.get(path);
  if (!response) throw new Error(`unexpected fetch ${path}`);
  return {
    ok: true,
    status: 200,
    arrayBuffer: async () => response.buffer.slice(response.byteOffset, response.byteOffset + response.byteLength)
  };
};
eval(browserScript);
const waitFor = async (predicate) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(`browser behavior did not complete (status: ${status.textContent})`);
};
(async () => {
  await waitFor(() => typeof authenticate.click === "function");
  authenticate.click();
  await waitFor(() => approvalText !== null);
  if (approvalText !== exactText) {
    throw new Error(`expected exact DOM text ${JSON.stringify(exactText)}, got ${JSON.stringify(approvalText)}`);
  }
  if (approvalText.includes("bytes:")) throw new Error("diagnostic byte summary reached approval DOM");
  await waitFor(() => main.children.some(n => n.textContent === 'Approve' && typeof n.click === 'function'));
  if (main.dataset.preAuthentication !== undefined) throw new Error('old pre-authentication remains in the page');
  if (elements.get('#savana-status') !== status) throw new Error('approval removed its status element');
  const button = main.children.find(n => n.textContent === (decision === 1 ? 'Deny' : 'Approve'));
  button.click();
  await waitFor(() => status.textContent === (decision === 3 ? 'Approval response does not match your decision' : decision === 2 ? 'Approved. You may close this page.' : 'Denied. You may close this page.'));
})().catch((error) => { console.error(error); process.exitCode = 1; });
"####,
        );
            let output = Command::new("node")
                .arg("-e")
                .arg(harness)
                .output()
                .expect("Node.js is required for fixed browser asset behavior tests");
            assert!(
                output.status.success(),
                "browser behavior failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn ingress_editor_builds_a_rust_valid_draft_and_checks_input_approval_without_reupload() {
        use crate::v2::*;
        let d = |n| Digest32V2::new([n; 32]);
        let context = TaskAuthorizationContextV2::new(
            PrincipalIdV2::new([1; 32]),
            DurableTaskIdV2::new([2; 32]),
            d(3),
            d(4),
            7,
            d(5),
            UnixMillisV2::new(100),
            UnixMillisV2::new(500),
            Some((d(6), 2)),
            vec![TaskAuthorizationToolContextV2::new(
                d(7),
                "release.allowed".into(),
                final_release_business_profile_v2(d(8), d(9)).unwrap(),
            )
            .unwrap()],
            vec![],
        )
        .unwrap();
        let mut harness = format!(
            "const browserScript = {}; const contextBytes = {};",
            serde_json::to_string(std::str::from_utf8(SAVANA_BROWSER_SCRIPT_V2).unwrap()).unwrap(),
            serde_json::to_string(&encode_task_authorization_context_v2(&context).unwrap())
                .unwrap()
        );
        harness.push_str(r####"
const assert = require('assert');
const elements = new Map(), labelled = new Map(), transfers = [], calls = [];
const element = tag => ({tagName:tag.toUpperCase(),dataset:{},value:'',textContent:'',disabled:false,
 set id(v){elements.set('#'+v,this);}, setAttribute(k,v){if(k==='aria-label')labelled.set(v,this);}, append(){},replaceChildren(){},
 submit(){transfers.push(this.action);},addEventListener(event,fn){this[event]=fn;}});
const main=element('main');main.dataset.ingressTab=Buffer.from([0x58,32,...new Uint8Array(32).fill(1)]).toString('base64url');elements.set('main',main);
for(const [id,tag] of [['savana-status','p'],['savana-ingress-input','textarea'],['savana-ingress-submit','button']]){const e=element(tag);e.id=id;}
globalThis.document={querySelector:s=>elements.get(s)??null,createElement:element,body:element('body')};
globalThis.location={port:'8767',pathname:'/v2/input'};
let finalized=0, captured=null;
globalThis.fetch=async(path,options)=>{
 calls.push(path);let response;
 if(path==='/v2/input/begin') response=[0x82,1,0];
 else if(path==='/v2/input/chunk')response=[0x83,2,0,0x58,32,...new Uint8Array(32).fill(2)];
 else if(path==='/v2/input/finalize')response=++finalized===1?[0x82,3,0x58,32,...new Uint8Array(32).fill(3)]:[0x82,5,0x81,4];
 else if(path==='/v2/task/context')response=contextBytes;
 else if(path==='/v2/task/approval/prepare'){
  captured=Buffer.from(options.body).toString('base64');
  const request=Buffer.from(elements.get('#savana-task-request').value,'hex');
  response=[0x83,8,0x58,32,...request,0x58,32,...new Uint8Array(32).fill(4)];
 } else throw new Error('unexpected request '+path);
 const bytes=Uint8Array.from(response);return {ok:true,status:200,arrayBuffer:async()=>bytes.buffer};
};
eval(browserScript);
const wait=async fn=>{for(let i=0;i<300;i++){if(fn())return;await new Promise(r=>setTimeout(r,1));}throw new Error('timeout: '+elements.get('#savana-status').textContent);};
(async()=>{
 await wait(()=>elements.has('#savana-task-context'));
 elements.get('#savana-ingress-input').value='abc';elements.get('#savana-ingress-submit').click();
 await wait(()=>elements.get('#savana-ingress-submit').textContent==='Check approval and commit');
 assert.equal(finalized,1);elements.get('#savana-ingress-submit').click();
 await wait(()=>elements.get('#savana-status').textContent.startsWith('Input committed'));
 assert.deepEqual(calls,['/v2/input/begin','/v2/input/chunk','/v2/input/finalize','/v2/input/finalize']);
 elements.get('#savana-task-context').click();await wait(()=>elements.has('#savana-task-prepare'));
 labelled.get('destination (text)').value='application-turn:'+'0b'.repeat(32);
 elements.get('#savana-task-prepare').click();await wait(()=>elements.get('#savana-status').textContent.startsWith('Complete the separate task approval page'));
 assert.equal(calls.filter(p=>p==='/v2/task/approval/prepare').length,1);
 assert.equal(calls.filter(p=>p==='/v2/task/approval/commit').length,0);
 assert.equal(transfers.length,2);assert.equal(elements.get('#savana-task-request').disabled,true);
 console.log(captured);
})().catch(e=>{console.error(e);process.exitCode=1;});
"####);
        let output = Command::new("node")
            .arg("-e")
            .arg(harness)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(String::from_utf8(output.stdout).unwrap().trim())
            .unwrap();
        let IngressBrowserRequestV2::PrepareTaskAuthorizationApproval { draft, .. } =
            decode_ingress_browser_request_v2(&bytes).unwrap()
        else {
            panic!("wrong operation");
        };
        assert_eq!(draft.source_input_digest(), d(5));
        assert_eq!(draft.authorization_id(), d(6));
        assert_eq!(draft.revision(), 2);
        assert_eq!(
            draft.clauses()[0].alternatives()[0].descriptor_digest(),
            d(7)
        );
        assert!(draft
            .render_approval_text()
            .unwrap()
            .as_str()
            .contains(&format!("application-turn:{}", "0b".repeat(32))));
    }

    #[test]
    fn ingress_dom_recovers_existing_issuance_without_upload_or_implicit_approval() {
        let script = std::str::from_utf8(SAVANA_BROWSER_SCRIPT_V2).unwrap();
        for mode in ["installed", "pending", "wrong-receipt"] {
            let mut harness = format!(
                "const mode = {mode:?}; const browserScript = {};",
                serde_json::to_string(script).unwrap()
            );
            harness.push_str(r####"
const assert = require('assert');
const elements = new Map();
const transfers = [];
const element = tag => ({tagName: tag.toUpperCase(), dataset: {}, value: '', textContent: '', disabled: false,
  set id(v) { elements.set('#' + v, this); }, setAttribute() {}, append() {}, replaceChildren() {},
  submit() { transfers.push(this.action); },
  addEventListener(event, fn) { this[event] = fn; }});
const main = element('main'); main.dataset.ingressTab = Buffer.from([0x58,32,...new Uint8Array(32).fill(1)]).toString('base64url');
elements.set('main', main);
for (const [id,tag] of [['savana-status','p'], ['savana-ingress-input','textarea'], ['savana-ingress-submit','button']]) { const e=element(tag); e.id=id; }
globalThis.document = {querySelector: s => elements.get(s) ?? null, createElement: element, body: element('body')};
globalThis.location = {port:'8767',pathname:'/v2/input'};
const calls=[];
globalThis.fetch = async (path, options) => {
  calls.push([path, new Uint8Array(options.body)]);
  assert.equal(path, calls.length === 1 ? '/v2/task/recover' : '/v2/task/approval/commit');
  const tag = mode === 'pending' && calls.length === 1 ? 8 : 7;
  const bytes = Uint8Array.of(0x83,tag,0x58,32,...new Uint8Array(32).fill(mode === 'wrong-receipt' ? 4 : 2),0x58,32,...new Uint8Array(32).fill(3));
  return {ok:true,status:200,arrayBuffer:async()=>bytes.buffer};
};
eval(browserScript);
const wait = async predicate => { for(let i=0;i<100;i++) { if(predicate()) return; await new Promise(r=>setTimeout(r,1)); } throw new Error('browser recovery did not complete: '+elements.get('#savana-status').textContent); };
(async()=>{
 await wait(()=>elements.has('#savana-task-recover'));
 elements.get('#savana-task-request').value = '02'.repeat(32);
 elements.get('#savana-task-recover').click();
 if (mode === 'wrong-receipt') {
   await wait(()=>elements.get('#savana-status').textContent === 'Task recovery response mismatch');
   assert.equal(calls.length,1); assert.equal(transfers.length,0);
   assert.equal(elements.get('#savana-task-recover').disabled,true);
   return;
 }
 if (mode === 'pending') {
   await wait(()=>elements.get('#savana-status').textContent.includes('Complete the separate task approval page'));
   assert.equal(calls.length,1, 'no implicit commit before the user checks approval');
   assert.deepEqual(transfers, ['http://localhost:8766/v2/ui-auth/accept']);
   assert.equal(elements.get('#savana-task-request').disabled,true);
   elements.get('#savana-task-recover').click();
 }
 await wait(()=>elements.get('#savana-status').textContent.includes('Recovered existing task authorization'));
 assert.equal(calls.length,mode === 'pending' ? 2 : 1); assert.equal(calls[0][1][0],0x84); assert.equal(calls[0][1][1],9);
 assert.deepEqual([...calls[0][1].slice(-32)], [...new Uint8Array(32).fill(2)]);
})().catch(e=>{console.error(e);process.exitCode=1;});
"####);
            let output = Command::new("node")
                .arg("-e")
                .arg(harness)
                .output()
                .expect("Node.js is required for browser behavior tests");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
