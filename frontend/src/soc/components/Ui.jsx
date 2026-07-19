import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Info,
  RefreshCw,
  X,
} from "lucide-react";

const NOTICE_ICONS = {
  error: CircleAlert,
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
};

export function PageHeader({ title, description, actions }) {
  return (
    <header className="soc-page-header">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="soc-page-actions">{actions}</div>}
    </header>
  );
}

export function StatCard({ label, value, trend, tone = "default", direction }) {
  return (
    <article className="soc-stat-card" data-card-tone={tone}>
      <span>{label}</span>
      <strong data-tone={tone}>{value}</strong>
      {trend && (
        <small data-tone={tone === "default" ? undefined : tone}>
          {direction === "up" && "▲ "}
          {direction === "down" && "▼ "}
          {trend}
        </small>
      )}
    </article>
  );
}

export function Panel({ title, subtitle, actions, children, className = "", ...sectionProps }) {
  return (
    <section {...sectionProps} className={`soc-panel ${className}`.trim()}>
      {(title || actions) && (
        <header className="soc-panel-header">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {actions && <div className="soc-panel-actions">{actions}</div>}
        </header>
      )}
      <div className="soc-panel-body">{children}</div>
    </section>
  );
}

export function TablePagination({ label = "records", onPageChange, page, pageSize = 10, totalItems }) {
  const pageCount = Math.max(1, Math.ceil(totalItems / pageSize));
  const safePage = Math.min(pageCount, Math.max(1, Number(page) || 1));
  const [pageInput, setPageInput] = useState(String(safePage));

  useEffect(() => {
    setPageInput(String(safePage));
  }, [safePage]);

  function commitRequestedPage() {
    const requested = Number.parseInt(pageInput, 10);
    const nextPage = Math.min(pageCount, Math.max(1, Number.isFinite(requested) ? requested : safePage));
    setPageInput(String(nextPage));
    if (nextPage !== safePage) onPageChange(nextPage);
  }

  useEffect(() => {
    if (!pageInput) return undefined;
    const requested = Number.parseInt(pageInput, 10);
    if (!Number.isFinite(requested)) return undefined;
    const nextPage = Math.min(pageCount, Math.max(1, requested));
    if (nextPage === safePage && String(nextPage) === pageInput) return undefined;

    const timeoutId = window.setTimeout(() => {
      setPageInput(String(nextPage));
      if (nextPage !== safePage) onPageChange(nextPage);
    }, 350);
    return () => window.clearTimeout(timeoutId);
  }, [onPageChange, pageCount, pageInput, safePage]);

  if (totalItems <= pageSize) return null;

  const start = (safePage - 1) * pageSize + 1;
  const end = Math.min(safePage * pageSize, totalItems);

  return (
    <nav className="table-pagination" aria-label={`${label} pagination`}>
      <span className="table-pagination-summary">{start}–{end} of {totalItems.toLocaleString()}</span>
      <div className="table-pagination-controls">
        <button type="button" disabled={safePage === 1} onClick={() => onPageChange(safePage - 1)}><ChevronLeft size={14} />Previous</button>
        <form onSubmit={(event) => { event.preventDefault(); commitRequestedPage(); }}>
          <label><span>Page</span><input type="text" inputMode="numeric" pattern="[0-9]*" value={pageInput} aria-label={`Go to ${label} page`} onBlur={commitRequestedPage} onChange={(event) => setPageInput(event.target.value.replace(/\D/g, "").slice(0, 5))} /></label>
          <span>of {pageCount}</span>
        </form>
        <button type="button" disabled={safePage === pageCount} onClick={() => onPageChange(safePage + 1)}>Next<ChevronRight size={14} /></button>
      </div>
    </nav>
  );
}

export function SeverityBadge({ severity }) {
  const normalized = String(severity || "info").toLowerCase();
  return (
    <span className="soc-badge" data-severity={normalized}>
      <i aria-hidden="true" />
      {normalized}
    </span>
  );
}

export function StatusBadge({ status }) {
  const normalized = String(status || "new").toLowerCase();
  return (
    <span className="soc-badge" data-status={normalized}>
      <i aria-hidden="true" />
      {normalized}
    </span>
  );
}

export function LoadingState({ label = "Loading workspace data…" }) {
  return (
    <div className="soc-state" role="status">
      <span className="soc-spinner" aria-hidden="true" />
      <p>{label}</p>
    </div>
  );
}

export function ErrorState({ message, onRetry }) {
  return (
    <div className="soc-state soc-state-error" role="alert">
      <span className="soc-state-icon"><AlertTriangle size={21} aria-hidden="true" /></span>
      <div>
        <strong>Workspace unavailable</strong>
        <p>{message}</p>
      </div>
      <button className="soc-button secondary" type="button" onClick={onRetry}>
        <RefreshCw size={15} aria-hidden="true" />
        Try again
      </button>
    </div>
  );
}

export function InlineNotice({ children, className = "", onDismiss, title, tone = "info", ...noticeProps }) {
  const Icon = NOTICE_ICONS[tone] || Info;

  return (
    <div
      {...noticeProps}
      className={`soc-notice ${className}`.trim()}
      data-tone={tone}
      role={tone === "error" ? "alert" : "status"}
    >
      <span className="soc-notice-icon"><Icon size={16} aria-hidden="true" /></span>
      <div>
        {title && <strong>{title}</strong>}
        {children && <p>{children}</p>}
      </div>
      {onDismiss && (
        <button type="button" onClick={onDismiss} aria-label="Dismiss message">
          <X size={15} aria-hidden="true" />
        </button>
      )}
    </div>
  );
}

export function ValidationMessage({ children, id }) {
  if (!children) return null;

  return (
    <span className="soc-field-error" id={id} role="alert">
      <CircleAlert size={13} aria-hidden="true" />
      {children}
    </span>
  );
}

export function RiskMeter({ value, label = "Risk score" }) {
  const safeValue = Math.max(0, Math.min(100, Number(value) || 0));
  return (
    <div className="risk-meter">
      <div
        className="risk-meter-track"
        role="meter"
        aria-label={label}
        aria-valuemin="0"
        aria-valuemax="100"
        aria-valuenow={safeValue}
      >
        <span style={{ width: `${safeValue}%` }} />
      </div>
      <strong>{safeValue}/100</strong>
    </div>
  );
}
