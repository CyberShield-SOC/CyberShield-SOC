import { Activity, Radio, ShieldCheck, Terminal } from "lucide-react";
import { SECURITY_EVENTS, SECURITY_FEATURES } from "../data/securityContent";
import { BrandLogo } from "./BrandLogo";

const FEATURE_ICONS = {
  monitoring: Radio,
  detection: Activity,
  response: ShieldCheck,
};

export function BrandMark({ adaptive = false }) {
  return (
    <div className={`brand-mark ${adaptive ? "is-adaptive" : ""}`} aria-label="CyberShield SOC">
      <BrandLogo size={adaptive ? "compact" : "default"} />
      <span className="brand-name">
        CyberShield <span>SOC</span>
      </span>
    </div>
  );
}

export function BrandPanel() {
  return (
    <section className="brand-panel" aria-labelledby="brand-heading">
      <header className="relative z-10">
        <BrandMark />
      </header>

      <div className="brand-hero relative z-10 my-auto max-w-[620px] py-12 lg:py-20">
        <p className="eyebrow">Security operations, reimagined</p>
        <h2
          id="brand-heading"
          className="mt-5 max-w-[560px] text-[clamp(2.3rem,4.5vw,4.5rem)] font-semibold leading-[1.02] tracking-[-0.055em] text-white"
        >
          Intelligent.
          <br />
          Proactive. <span className="text-gradient">Secure.</span>
        </h2>
        <p className="mt-6 max-w-[500px] text-[15px] leading-7 text-slate-300/80">
          Unified threat detection and response built to protect modern
          infrastructure—without the noise.
        </p>

        <div className="mt-9 grid gap-5">
          {SECURITY_FEATURES.map(({ icon, title, copy }) => {
            const Icon = FEATURE_ICONS[icon];
            return (
              <div className="feature-row" key={title}>
                <span className="feature-icon" aria-hidden="true">
                  <Icon size={16} />
                </span>
                <div>
                  <p className="text-[13px] font-medium text-slate-100">{title}</p>
                  <p className="mt-0.5 text-[11px] leading-5 text-slate-400">{copy}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="brand-footer relative z-10">
        <div className="event-console" aria-hidden="true">
          <div className="flex items-center justify-between border-b border-cyan-300/10 px-4 py-3">
            <div className="flex items-center gap-2">
              <Terminal size={13} className="text-teal-300" aria-hidden="true" />
              <span className="font-mono text-[9px] uppercase tracking-[0.17em] text-slate-300">
                Live security events
              </span>
            </div>
            <span className="flex items-center gap-1.5 font-mono text-[8px] uppercase text-teal-300">
              <i className="h-1.5 w-1.5 animate-pulse rounded-full bg-teal-300" />
              monitoring
            </span>
          </div>

          <div className="event-feed">
            {SECURITY_EVENTS.map(({ time, severity, service, message }) => (
              <div key={`${time}-${service}`} className="event-row">
                <span className="event-time">{time}</span>
                <span className="event-severity" data-severity={severity.toLowerCase()}>
                  {severity}
                </span>
                <span className="event-service">{service}</span>
                <span className="event-message">{message}</span>
              </div>
            ))}
          </div>
        </div>

        <p className="mt-5 font-mono text-[8px] tracking-[0.08em] text-slate-500">
          University of Texas at Arlington · CSE Senior Design Capstone · 2026
        </p>
      </div>
    </section>
  );
}
