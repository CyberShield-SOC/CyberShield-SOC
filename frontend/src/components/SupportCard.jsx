import { CircleAlert, Headphones, KeyRound, ShieldAlert } from "lucide-react";
import { AuthBackButton, AuthCardIntro } from "./AuthCardIntro";

const SUPPORT_TOPICS = [
  {
    icon: KeyRound,
    title: "Account access",
    copy: "Password, lockout, account status, and role-assignment help.",
  },
  {
    icon: Headphones,
    title: "Verification help",
    copy: "MFA device, backup-code, and trusted-device assistance.",
  },
  {
    icon: ShieldAlert,
    title: "Security concern",
    copy: "Lost devices, suspicious prompts, or suspected account compromise.",
  },
];

export function SupportCard({ onBack }) {
  return (
    <section className="auth-card" aria-labelledby="support-title">
      <AuthBackButton onClick={onBack} />
      <AuthCardIntro
        icon={Headphones}
        kicker="Security support"
        title="How can we help?"
        titleId="support-title"
      >
        Choose the support path that best matches your access issue.
      </AuthCardIntro>

      <div className="support-list">
        {SUPPORT_TOPICS.map(({ icon: Icon, title, copy }) => (
          <div className="support-item" key={title}>
            <span aria-hidden="true"><Icon size={18} /></span>
            <div>
              <strong>{title}</strong>
              <p>{copy}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="security-callout">
        <CircleAlert size={17} aria-hidden="true" />
        <p>
          Support will never ask for your password or verification code. Use only your
          organization&apos;s approved support channel.
        </p>
      </div>
    </section>
  );
}
