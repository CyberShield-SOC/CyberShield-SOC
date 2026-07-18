import { ArrowRight, CheckCircle2 } from "lucide-react";
import { AuthCardIntro } from "./AuthCardIntro";

export function LogoutSuccessCard({ onReturn }) {
  return (
    <section className="auth-card logout-card" aria-labelledby="logout-title">
      <AuthCardIntro
        icon={CheckCircle2}
        iconState="verified"
        kicker="Session ended"
        title="You’re signed out"
        titleId="logout-title"
      >
        Your SOC workspace session has ended successfully. Sign in again when you’re ready to continue.
      </AuthCardIntro>

      <div className="verified-panel" role="status">
        This browser no longer has access to protected workspace routes.
      </div>

      <button className="primary-button auth-primary-action" type="button" onClick={onReturn}>
        Back to login
        <ArrowRight size={17} aria-hidden="true" />
      </button>
    </section>
  );
}
