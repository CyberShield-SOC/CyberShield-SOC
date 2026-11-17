import { useCallback, useEffect, useState } from "react";
import { Copy, Download, KeyRound, RefreshCw, ShieldCheck, ShieldOff, Smartphone } from "lucide-react";
import { authClient } from "../../services/authClient";
import { SAMPLE_RECOVERY_CODES, SAMPLE_TOTP_SETUP } from "../data/sampleMfa";
import { downloadBlobFile, formatTimestamp } from "../utils/eventUtils";
import {
  formatSetupKey,
  isTotpCode,
  normalizeMfaState,
  normalizeTotpSetup,
  recoveryCodesFile,
  recoveryCodesWarning,
  sanitizeTotpCode,
  secondFactorInput,
  svgDataUrl,
} from "../utils/mfa";
import { InlineNotice, LoadingState, Panel, ValidationMessage } from "./Ui";

const wait = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));

// Sample data has no server to hold a secret, so this stand-in keeps the
// state for the page's lifetime and accepts any well-formed code. It exists
// so the screens can be seen and reviewed, not to protect anything.
let sampleEnabledAt = null;
const sampleMfaClient = {
  async getMfa() { await wait(90); return normalizeMfaState({ totp_enabled: Boolean(sampleEnabledAt), totp_enabled_at: sampleEnabledAt, recovery_codes_remaining: 8 }); },
  async beginTotpSetup() { await wait(120); return normalizeTotpSetup(SAMPLE_TOTP_SETUP); },
  async enableTotp() { await wait(140); sampleEnabledAt = new Date().toISOString(); return { recoveryCodes: [...SAMPLE_RECOVERY_CODES], state: await this.getMfa() }; },
  async disableTotp() { await wait(140); sampleEnabledAt = null; return this.getMfa(); },
  async regenerateRecoveryCodes() { await wait(140); return { recoveryCodes: [...SAMPLE_RECOVERY_CODES].reverse(), state: await this.getMfa() }; },
};

/**
 * A form-like group. The Settings page is itself one <form>, and a nested
 * <form> is dropped by the browser, so Enter would submit the page. This
 * group handles Enter (and its button) itself and stops it there.
 */
function SubmitGroup({ children, className, onSubmit }) {
  return (
    <div
      className={className}
      role="group"
      onKeyDown={(event) => {
        if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
          event.preventDefault();
          onSubmit(event);
        }
      }}
    >
      {children}
    </div>
  );
}

function CodeField({ describedBy, disabled, id, label, onChange, value, wide = false }) {
  return (
    <label className={`mfa-field${wide ? " wide" : ""}`} htmlFor={id}>
      <span>{label}</span>
      <input
        id={id}
        type="text"
        inputMode={wide ? "text" : "numeric"}
        autoComplete="one-time-code"
        autoCapitalize="off"
        spellCheck="false"
        maxLength={wide ? 14 : 6}
        placeholder={wide ? "123456 or xxxxx-xxxxx" : "123456"}
        value={value}
        disabled={disabled}
        aria-describedby={describedBy}
        onChange={(event) => onChange(wide ? event.target.value : sanitizeTotpCode(event.target.value))}
      />
    </label>
  );
}

function RecoveryCodes({ account, codes, onDone }) {
  const [copied, setCopied] = useState(false);

  async function copyCodes() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function downloadCodes() {
    downloadBlobFile(
      new Blob([recoveryCodesFile(codes, { account })], { type: "text/plain;charset=utf-8" }),
      "cybershield-recovery-codes.txt",
    );
  }

  return (
    <section className="mfa-recovery" aria-labelledby="mfa-recovery-title">
      <h3 id="mfa-recovery-title">Save your recovery codes</h3>
      <p>
        Each code signs you in once if your phone is lost or replaced. They are shown only now:
        once you leave this screen they cannot be displayed again, only replaced.
      </p>
      <ol className="mfa-recovery-codes">
        {codes.map((code) => <li key={code}><code>{code}</code></li>)}
      </ol>
      <div className="mfa-actions">
        <button className="soc-button secondary compact" type="button" onClick={copyCodes}>
          <Copy size={14} aria-hidden="true" /> {copied ? "Copied" : "Copy codes"}
        </button>
        <button className="soc-button secondary compact" type="button" onClick={downloadCodes}>
          <Download size={14} aria-hidden="true" /> Download .txt
        </button>
        <button className="soc-button primary compact" type="button" onClick={onDone}>I have saved them</button>
      </div>
    </section>
  );
}

/**
 * Enrol, review and remove an authenticator app (TOTP, RFC 6238) for the
 * signed-in account. The account's own MFA state is page-local: it belongs
 * to one user, not to the shared workspace data.
 */
export function MfaSettingsPanel({ account, repositoryMode }) {
  const client = repositoryMode === "api" ? authClient : sampleMfaClient;
  const [state, setState] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [view, setView] = useState("status"); // status | setup | disable | regenerate
  const [setup, setSetup] = useState(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState(null);

  const load = useCallback(async () => {
    setLoadError("");
    try {
      setState(await client.getMfa());
    } catch (requestError) {
      setLoadError(requestError.message || "Your sign-in verification settings could not be loaded.");
    }
  }, [client]);

  useEffect(() => {
    void load();
  }, [load]);

  function reset(nextView = "status") {
    setView(nextView);
    setCode("");
    setPassword("");
    setError("");
    setSetup(null);
  }

  async function run(action, fallbackMessage) {
    setError("");
    setBusy(true);
    try {
      await action();
    } catch (requestError) {
      setError(requestError.message || fallbackMessage);
    } finally {
      setBusy(false);
    }
  }

  const startSetup = () => run(async () => {
    setSetup(await client.beginTotpSetup());
    setCode("");
    setView("setup");
  }, "Authenticator setup could not be started.");

  function confirmSetup(event) {
    event.preventDefault();
    if (!isTotpCode(code)) {
      setError("Enter the six-digit code your authenticator app is showing.");
      return;
    }
    void run(async () => {
      const result = await client.enableTotp(code);
      setState(result.state);
      setRecoveryCodes(result.recoveryCodes);
      reset();
    }, "That code could not be checked.");
  }

  function confirmDisable(event) {
    event.preventDefault();
    const factor = secondFactorInput(code);
    if (!password || !factor.kind) {
      setError("Enter your password and a current authenticator code or recovery code.");
      return;
    }
    void run(async () => {
      setState(await client.disableTotp({ password, code: factor.code }));
      reset();
    }, "The authenticator app could not be turned off.");
  }

  function confirmRegenerate(event) {
    event.preventDefault();
    if (!isTotpCode(code)) {
      setError("Enter the six-digit code your authenticator app is showing.");
      return;
    }
    void run(async () => {
      const result = await client.regenerateRecoveryCodes(code);
      setState(result.state);
      setRecoveryCodes(result.recoveryCodes);
      reset();
    }, "New recovery codes could not be generated.");
  }

  const errorId = error ? "mfa-form-error" : undefined;
  const lowCodes = state?.totpEnabled ? recoveryCodesWarning(state.recoveryCodesRemaining) : "";

  return (
    <Panel
      title="Sign-in verification"
      subtitle="The second step after your password. An authenticator app works offline and does not depend on email delivery."
    >
      {repositoryMode !== "api" && (
        <InlineNotice tone="info" title="Sample data">
          These screens are a walkthrough. Nothing is enrolled and any six-digit code is accepted.
        </InlineNotice>
      )}
      {loadError && (
        <InlineNotice tone="error" title="Settings unavailable">{loadError}</InlineNotice>
      )}
      {!state && !loadError && <LoadingState label="Loading sign-in verification…" />}

      {recoveryCodes && (
        <RecoveryCodes account={account} codes={recoveryCodes} onDone={() => setRecoveryCodes(null)} />
      )}

      {state && !recoveryCodes && view === "status" && (
        <div className="mfa-status">
          <span className="mfa-status-icon" data-on={state.totpEnabled}>
            {state.totpEnabled ? <ShieldCheck size={18} aria-hidden="true" /> : <Smartphone size={18} aria-hidden="true" />}
          </span>
          <div className="mfa-status-copy">
            <strong>{state.totpEnabled ? "Authenticator app" : "Emailed code"}</strong>
            <small>
              {state.totpEnabled
                ? `On since ${formatTimestamp(state.totpEnabledAt)} · ${state.recoveryCodesRemaining} of 8 recovery codes unused`
                : "A six-digit code is emailed to you each time you sign in."}
            </small>
          </div>
          <div className="mfa-actions">
            {state.totpEnabled ? (
              <>
                <button className="soc-button secondary compact" type="button" onClick={() => reset("regenerate")}>
                  <RefreshCw size={14} aria-hidden="true" /> New recovery codes
                </button>
                <button className="soc-button danger compact" type="button" onClick={() => reset("disable")}>
                  <ShieldOff size={14} aria-hidden="true" /> Turn off
                </button>
              </>
            ) : (
              <button className="soc-button primary compact" type="button" onClick={startSetup} disabled={busy}>
                <KeyRound size={14} aria-hidden="true" /> {busy ? "Starting…" : "Set up authenticator app"}
              </button>
            )}
          </div>
        </div>
      )}
      {state && !recoveryCodes && view === "status" && lowCodes && (
        <InlineNotice tone="warning" title="Recovery codes running low">{lowCodes}</InlineNotice>
      )}
      {state && !recoveryCodes && view === "status" && error && (
        <InlineNotice tone="error" title="Setup failed" onDismiss={() => setError("")}>{error}</InlineNotice>
      )}

      {view === "setup" && setup && (
        <SubmitGroup className="mfa-setup" onSubmit={confirmSetup}>
          <ol className="mfa-steps">
            <li>
              <strong>Scan this code</strong>
              <span>Open Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app and add an account.</span>
              {svgDataUrl(setup.qrSvg) && (
                <img className="mfa-qr" src={svgDataUrl(setup.qrSvg)} width="176" height="176" alt="QR code for authenticator setup" />
              )}
              <span>Cannot scan? Enter this setup key by hand:</span>
              <code className="mfa-setup-key">{formatSetupKey(setup.secret)}</code>
            </li>
            <li>
              <strong>Enter the code the app shows</strong>
              <span>This confirms the app and the server agree before anything changes at sign-in.</span>
              <CodeField id="mfa-setup-code" label="Six-digit code" value={code} onChange={setCode} disabled={busy} describedBy={errorId} />
              <ValidationMessage id="mfa-form-error">{error}</ValidationMessage>
            </li>
          </ol>
          <div className="mfa-actions">
            <button className="soc-button secondary compact" type="button" onClick={() => reset()} disabled={busy}>Cancel</button>
            <button className="soc-button primary compact" type="button" onClick={confirmSetup} disabled={busy}>{busy ? "Checking…" : "Turn on authenticator app"}</button>
          </div>
        </SubmitGroup>
      )}

      {view === "disable" && (
        <SubmitGroup className="mfa-confirm" onSubmit={confirmDisable}>
          <p>Turning this off returns your sign-in to emailed codes and deletes your recovery codes.</p>
          <label className="mfa-field wide" htmlFor="mfa-disable-password">
            <span>Password</span>
            <input id="mfa-disable-password" type="password" autoComplete="current-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} aria-describedby={errorId} />
          </label>
          <CodeField id="mfa-disable-code" label="Authenticator code or recovery code" value={code} onChange={setCode} disabled={busy} describedBy={errorId} wide />
          <ValidationMessage id="mfa-form-error">{error}</ValidationMessage>
          <div className="mfa-actions">
            <button className="soc-button secondary compact" type="button" onClick={() => reset()} disabled={busy}>Keep it on</button>
            <button className="soc-button danger compact" type="button" onClick={confirmDisable} disabled={busy}>{busy ? "Turning off…" : "Turn off authenticator app"}</button>
          </div>
        </SubmitGroup>
      )}

      {view === "regenerate" && (
        <SubmitGroup className="mfa-confirm" onSubmit={confirmRegenerate}>
          <p>A new set replaces every existing recovery code, used or not.</p>
          <CodeField id="mfa-regenerate-code" label="Six-digit code" value={code} onChange={setCode} disabled={busy} describedBy={errorId} />
          <ValidationMessage id="mfa-form-error">{error}</ValidationMessage>
          <div className="mfa-actions">
            <button className="soc-button secondary compact" type="button" onClick={() => reset()} disabled={busy}>Cancel</button>
            <button className="soc-button primary compact" type="button" onClick={confirmRegenerate} disabled={busy}>{busy ? "Generating…" : "Generate new codes"}</button>
          </div>
        </SubmitGroup>
      )}
    </Panel>
  );
}
