import { useState } from "react";
import { ArrowRight, Building2, Check, ExternalLink, ShieldCheck } from "lucide-react";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";

export function SsoCard({ onBack }) {
  const [isReady, setIsReady] = useState(false);

  if (isReady) {
    return (
      <section className="auth-card" aria-labelledby="sso-ready-title">
        <AuthBackButton onClick={onBack} />
        <AuthCardIntro
          icon={Check}
          iconState="verified"
          kicker="Secure handoff"
          title="UTA sign-in is ready"
          titleId="sso-ready-title"
        >
          The production version continues to the university identity provider in a verified session.
        </AuthCardIntro>

        <div className="info-panel organization-summary">
          <ShieldCheck size={18} aria-hidden="true" />
          <span>
            <strong>University-managed authentication</strong>
            <small>Credentials stay with the approved identity provider.</small>
          </span>
        </div>
        <button className="primary-button auth-primary-action" type="button" onClick={onBack}>
          Return to sign in <ArrowRight size={17} aria-hidden="true" />
        </button>
      </section>
    );
  }

  return (
    <section className="auth-card" aria-labelledby="sso-title">
      <AuthBackButton onClick={onBack} />
      <AuthCardIntro
        icon={Building2}
        kicker="University access"
        title="Continue with UTA SSO"
        titleId="sso-title"
      >
        Use your university-managed account to continue to CyberShield SOC.
      </AuthCardIntro>

      <div className="organization-card">
        <span className="organization-icon" aria-hidden="true">
          <Building2 size={21} />
        </span>
        <span>
          <strong>University of Texas at Arlington</strong>
          <small>Organization-managed identity</small>
        </span>
        <ShieldCheck size={18} className="organization-shield" aria-hidden="true" />
      </div>

      <button
        className="primary-button auth-primary-action"
        type="button"
        onClick={() => setIsReady(true)}
      >
        Preview secure handoff
        <ExternalLink size={17} aria-hidden="true" />
      </button>
      <p className="assurance-copy">
        You will always verify the university domain before entering credentials.
      </p>
    </section>
  );
}
