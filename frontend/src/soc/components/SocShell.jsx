import { useEffect, useRef, useState } from "react";
import { canOpenUserManagement } from "../../utils/permissions";
import {
  Activity,
  AlertTriangle,
  Bell,
  Bot,
  ChevronDown,
  CircleCheck,
  CircleHelp,
  FileBarChart,
  FileSearch,
  Gauge,
  LogOut,
  Mail,
  MailOpen,
  Menu,
  Moon,
  Network,
  RefreshCw,
  Search,
  Settings,
  ShieldAlert,
  StickyNote,
  Sun,
  Trash2,
  UserRoundCog,
  Users,
  X,
  Zap,
} from "lucide-react";
import { SOC_ROUTES } from "../../hooks/useAuthRoute";
import { BrandLogo } from "../../components/BrandLogo";
import { useSocWorkspace } from "../context/SocWorkspaceContext";
import { searchShortcutLabel, shouldFocusGlobalSearch } from "../utils/searchShortcuts";
import { formatNavigationBadgeCount } from "../utils/countFormat";

const NAV_GROUPS = [
  {
    label: "Monitor",
    items: [
      [SOC_ROUTES.dashboard, "Dashboard", Gauge],
      [SOC_ROUTES.eventLogs, "Event Logs", FileSearch],
      [SOC_ROUTES.threatDetection, "Threat Detection", Activity],
      [SOC_ROUTES.alerts, "Alerts", AlertTriangle, "alerts"],
      [SOC_ROUTES.incidents, "Incidents", ShieldAlert, "incidents"],
      [SOC_ROUTES.incidentTracking, "Incident Tracking", Network],
    ],
  },
  {
    label: "Analyze",
    items: [
      [SOC_ROUTES.quickResolve, "Quick Resolve", Zap],
      [SOC_ROUTES.aiAnalysis, "AI Analysis", Bot],
      [SOC_ROUTES.analystNotes, "Analyst Notes", StickyNote],
      [SOC_ROUTES.reports, "Reports", FileBarChart],
    ],
  },
  {
    label: "Manage",
    items: [
      [SOC_ROUTES.manage, "Manage", UserRoundCog],
      [SOC_ROUTES.users, "Users", Users],
      [SOC_ROUTES.integrations, "Integrations", Network],
      [SOC_ROUTES.settings, "Settings", Settings],
    ],
  },
];

const ROUTE_LABELS = Object.fromEntries(
  NAV_GROUPS.flatMap((group) => group.items.map(([route, label]) => [route, label])),
);
ROUTE_LABELS[SOC_ROUTES.help] = "Help center";

export function SocShell({ children, expiresAt, navigate, onSignOut, route, theme, toggleTheme, user }) {
  const {
    activeAlertCount,
    apiHealth,
    dashboard,
    globalTimeRange,
    openIncidentCount,
    unreadNotificationCount,
    notifications,
    resources,
    mutation,
    markAllNotificationsRead,
    markAllNotificationsUnread,
    markNotificationRead,
    markNotificationUnread,
    clearAllNotifications,
    clearNotification,
    refresh,
    refreshAll,
    repositoryMode,
    settings,
    setGlobalTimeRange,
    setSelectedAlertId,
    setSelectedIncidentId,
  } = useSocWorkspace();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationFilter, setNotificationFilter] = useState("all");
  const [profileOpen, setProfileOpen] = useState(false);
  const searchRef = useRef(null);
  const platform = typeof navigator === "undefined"
    ? ""
    : navigator.userAgentData?.platform || navigator.platform;
  const shortcutLabel = searchShortcutLabel(platform);
  const isRefreshing = Object.values(resources).some((resource) => resource.loading);
  const apiStatus = resources.health.error ? "offline" : resources.health.loading ? "checking" : "online";
  const apiStatusCopy = apiStatus === "offline"
    ? { label: "Offline", detail: "Service is unreachable" }
    : apiStatus === "checking"
      ? { label: "Refreshing", detail: "Checking service health" }
      : apiHealth?.status === "demo"
        ? { label: "Demo mode", detail: "Using local sample data" }
        : { label: "Operational", detail: "Service responding normally" };
  const visibleNotifications = notificationFilter === "unread"
    ? notifications.filter((notification) => !notification.read)
    : notifications;
  const displayName = user?.full_name || user?.username || "Yugal P.";
  const avatarLabel = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "YP";

  useEffect(() => {
    function handleKeyboard(event) {
      if (shouldFocusGlobalSearch(event)) {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
      if (event.key === "Escape") {
        setSidebarOpen(false);
        setNotificationsOpen(false);
        setProfileOpen(false);
      }
    }

    window.addEventListener("keydown", handleKeyboard);
    return () => window.removeEventListener("keydown", handleKeyboard);
  }, []);

  useEffect(() => {
    setSidebarOpen(false);
    setNotificationsOpen(false);
    setProfileOpen(false);
  }, [route]);

  function submitSearch(event) {
    event.preventDefault();
    const query = String(new FormData(event.currentTarget).get("global-search") || "").trim().slice(0, 200);
    window.location.hash = query
      ? `#/${SOC_ROUTES.eventLogs}?q=${encodeURIComponent(query)}`
      : `#/${SOC_ROUTES.eventLogs}`;
  }

  return (
    <div
      className="soc-shell"
      data-theme={theme}
      data-density={settings?.workspace?.density || "comfortable"}
      data-text-size={settings?.workspace?.textSize || "standard"}
      data-contrast={settings?.workspace?.highContrast ? "high" : "standard"}
      data-motion={settings?.workspace?.reduceMotion ? "reduced" : "standard"}
    >
      <a className="skip-link" href="#soc-content">Skip to main content</a>
      <div className={`soc-sidebar-scrim ${sidebarOpen ? "visible" : ""}`} onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      <aside className={`soc-sidebar ${sidebarOpen ? "open" : ""}`} aria-label="Primary navigation">
        <div className="soc-brand">
          <BrandLogo size="sidebar" />
          <div><strong>CyberShield</strong><span>{settings?.workspace?.name || "SOC workspace"}</span></div>
          <button type="button" className="soc-icon-button sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation">
            <X size={18} />
          </button>
        </div>

        <nav className="soc-nav">
          {NAV_GROUPS.map((group) => (
            <div className="soc-nav-group" key={group.label}>
              <p>{group.label}</p>
              {group.items
                .filter(([itemRoute]) => itemRoute !== SOC_ROUTES.users || canOpenUserManagement(user))
                .map(([itemRoute, label, Icon, badge]) => {
                const badgeValue = badge === "alerts" ? activeAlertCount : badge === "incidents" ? openIncidentCount : null;
                const badgeDescription = badge === "alerts" ? "active alerts" : "open incidents";
                return (
                <button
                  type="button"
                  key={itemRoute}
                  className={route === itemRoute ? "active" : ""}
                  onClick={() => navigate(itemRoute)}
                  aria-current={route === itemRoute ? "page" : undefined}
                  aria-label={badgeValue > 0 ? `${label}, ${badgeValue} ${badgeDescription}` : undefined}
                >
                  <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
                  <span>{label}</span>
                  {badgeValue > 0 && <b aria-hidden="true">{formatNavigationBadgeCount(badgeValue)}</b>}
                </button>
                );
                })}
            </div>
          ))}
        </nav>

        <div className="soc-sidebar-footer">
          <div className="api-health-status" data-status={apiStatus} role="status" aria-live="polite" aria-label={`API status: ${apiStatusCopy.label}. ${apiStatusCopy.detail}.`}>
            <i aria-hidden="true" />
            <span>
              <strong>{repositoryMode === "api" ? "API status" : "Data service"}</strong>
              <small><b>{apiStatusCopy.label}</b><em>{apiStatusCopy.detail}</em></small>
            </span>
            <button type="button" onClick={() => refresh("health")} disabled={resources.health.loading} aria-label="Refresh API status" title="Refresh API status"><RefreshCw size={13} className={resources.health.loading ? "spinning" : ""} /></button>
          </div>
          <button className="soc-profile-trigger" type="button" onClick={() => setProfileOpen((current) => !current)} aria-expanded={profileOpen} aria-controls="soc-profile-menu">
            <span className="soc-avatar">{avatarLabel}</span>
            <span><strong>{displayName}</strong><small>{user?.role || "Administrator"}</small></span>
            <ChevronDown className="profile-menu-chevron" size={15} aria-hidden="true" />
          </button>
          {profileOpen && (
            <div className="soc-profile-menu" id="soc-profile-menu">
              <p className="session-expiry">{expiresAt && Number.isFinite(new Date(expiresAt).getTime()) ? `Session ends ${new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(expiresAt))}` : "Session managed securely by the server"}</p>
              <button type="button" onClick={onSignOut}><LogOut size={15} />Sign out</button>
            </div>
          )}
        </div>
      </aside>

      <div className="soc-main">
        <header className="soc-topbar">
          <button className="soc-icon-button menu-button" type="button" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
            <Menu size={19} />
          </button>
          <strong className="soc-route-title">{ROUTE_LABELS[route] || "CyberShield SOC"}</strong>
          <span className="live-pill"><i />{dashboard?.liveRateLabel || `Live · ${Number(dashboard?.liveRate || 0).toLocaleString()} events/min`}</span>
          <div className="soc-topbar-spacer" />
          <label className="time-control">
            <span className="sr-only">Global time range</span>
            <select value={globalTimeRange} onChange={(event) => setGlobalTimeRange(event.target.value)}>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
              <option value="all">All available</option>
            </select>
          </label>
          <form className="global-search" role="search" onSubmit={submitSearch}>
            <button type="submit" className="global-search-submit" aria-label="Run event search" title="Run search">
              <Search size={16} aria-hidden="true" />
            </button>
            <input ref={searchRef} name="global-search" type="search" maxLength="200" placeholder="Search events, IPs, rules…" aria-label="Search security events" aria-keyshortcuts="Control+K Meta+K /" title="Press Ctrl or Command + K, or /, to focus search" />
            <kbd aria-hidden="true">{shortcutLabel}</kbd>
          </form>
          <div className="soc-popover-anchor">
            <button className="soc-icon-button" type="button" onClick={() => setNotificationsOpen((current) => !current)} aria-label="Notifications" aria-expanded={notificationsOpen}>
              <Bell size={17} />
              {unreadNotificationCount > 0 && <span className="notification-count">{unreadNotificationCount}</span>}
            </button>
            {notificationsOpen && (
              <div className="soc-notification-popover">
                <header>
                  <div><strong>Notifications</strong><span>{unreadNotificationCount} unread · {notifications.length} total</span></div>
                  <div className="notification-header-actions">
                    {notifications.some((notification) => notification.read) && <button type="button" onClick={markAllNotificationsUnread}>Mark all unread</button>}
                    {unreadNotificationCount > 0 && <button type="button" onClick={markAllNotificationsRead}>Mark all read</button>}
                    {notifications.length > 0 && <button type="button" className="danger" onClick={clearAllNotifications}>Clear all</button>}
                  </div>
                </header>
                <div className="notification-filter" aria-label="Notification filters">
                  <button type="button" className={notificationFilter === "all" ? "active" : ""} onClick={() => setNotificationFilter("all")}>All <span>{notifications.length}</span></button>
                  <button type="button" className={notificationFilter === "unread" ? "active" : ""} onClick={() => setNotificationFilter("unread")}>Unread <span>{unreadNotificationCount}</span></button>
                </div>
                <div className="notification-list">
                  {visibleNotifications.map((notification) => (
                    <article className={notification.read ? "read" : ""} key={notification.id}>
                      <button
                        className="notification-main"
                        type="button"
                        onClick={() => {
                          markNotificationRead(notification.id);
                          if (notification.type === "alert") setSelectedAlertId(notification.recordId);
                          if (notification.type === "incident") setSelectedIncidentId(notification.recordId);
                          setNotificationsOpen(false);
                          navigate(notification.route);
                        }}
                      >
                        <i data-type={notification.type} />
                        <span><b>{notification.title}</b><small>{notification.detail}</small></span>
                      </button>
                      <div className="notification-actions">
                        <button type="button" onClick={() => notification.read ? markNotificationUnread(notification.id) : markNotificationRead(notification.id)} aria-label={`${notification.read ? "Mark unread" : "Mark read"}: ${notification.title}`} title={notification.read ? "Mark unread" : "Mark read"}>
                          {notification.read ? <Mail size={14} /> : <MailOpen size={14} />}
                        </button>
                        <button type="button" onClick={() => clearNotification(notification.id)} aria-label={`Clear notification: ${notification.title}`} title="Clear notification"><Trash2 size={14} /></button>
                      </div>
                    </article>
                  ))}
                  {!visibleNotifications.length && <p className="notification-empty">{notificationFilter === "unread" ? "You have no unread notifications." : "No active alert or incident notifications."}</p>}
                </div>
              </div>
            )}
          </div>
          <button className="soc-icon-button refresh-control" type="button" onClick={refreshAll} disabled={isRefreshing} aria-label="Refresh workspace data">
            <RefreshCw size={17} className={isRefreshing ? "spinning" : ""} />
          </button>
          <button className="soc-icon-button theme-control" type="button" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
            {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
          </button>
          <button className="soc-icon-button help-control" type="button" onClick={() => navigate(SOC_ROUTES.help)} aria-label="Open help center" title="Help center">
            <CircleHelp size={17} />
          </button>
        </header>

        <main className="soc-content" id="soc-content" tabIndex="-1">
          {children}
        </main>
        {(mutation.message || mutation.error) && (
          <div className={`mutation-toast ${mutation.error ? "error" : mutation.loading ? "loading" : "success"}`} role={mutation.error ? "alert" : "status"}>
            {mutation.loading ? <span className="soc-spinner small" /> : mutation.error ? <AlertTriangle size={16} aria-hidden="true" /> : <CircleCheck size={16} aria-hidden="true" />}
            <span>{mutation.error || mutation.message}</span>
          </div>
        )}
      </div>
    </div>
  );
}
