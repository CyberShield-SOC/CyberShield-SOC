import { lazy, Suspense, useEffect } from "react";
import { canAccessSocRoute, SOC_ROUTES } from "../hooks/useAuthRoute";
import { SocShell } from "./components/SocShell";
import { LoadingState } from "./components/Ui";
import { SocWorkspaceProvider } from "./context/SocWorkspaceContext";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const EventLogsPage = lazy(() => import("./pages/EventLogsPage"));
const ThreatDetectionPage = lazy(() => import("./pages/ThreatDetectionPage"));
const AlertsPage = lazy(() => import("./pages/AlertsPage"));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage"));
const IncidentTrackingPage = lazy(() => import("./pages/IncidentTrackingPage"));
const QuickResolvePage = lazy(() => import("./pages/QuickResolvePage"));
const AiAnalysisPage = lazy(() => import("./pages/AiAnalysisPage"));
const AnalystNotesPage = lazy(() => import("./pages/AnalystNotesPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const HelpPage = lazy(() => import("./pages/HelpPage"));
const ReportsPage = lazy(() => import("./pages/SecondaryPage"));
const UsersPage = lazy(() => import("./pages/UsersPage"));
const ManagementPage = lazy(() => import("./pages/ManagementPage"));

function RouteView({ navigate, route, theme, toggleTheme }) {
  switch (route) {
    case SOC_ROUTES.dashboard:
      return <DashboardPage navigate={navigate} />;
    case SOC_ROUTES.eventLogs:
      return <EventLogsPage navigate={navigate} />;
    case SOC_ROUTES.threatDetection:
      return <ThreatDetectionPage />;
    case SOC_ROUTES.alerts:
      return <AlertsPage navigate={navigate} />;
    case SOC_ROUTES.incidents:
      return <IncidentsPage navigate={navigate} />;
    case SOC_ROUTES.incidentTracking:
      return <IncidentTrackingPage navigate={navigate} />;
    case SOC_ROUTES.quickResolve:
      return <QuickResolvePage navigate={navigate} />;
    case SOC_ROUTES.aiAnalysis:
      return <AiAnalysisPage navigate={navigate} />;
    case SOC_ROUTES.analystNotes:
      return <AnalystNotesPage navigate={navigate} />;
    case SOC_ROUTES.settings:
      return <SettingsPage navigate={navigate} theme={theme} toggleTheme={toggleTheme} />;
    case SOC_ROUTES.help:
      return <HelpPage navigate={navigate} />;
    case SOC_ROUTES.reports:
      return <ReportsPage />;
    case SOC_ROUTES.users:
      return <UsersPage />;
    case SOC_ROUTES.manage:
    case SOC_ROUTES.integrations:
      return <ManagementPage navigate={navigate} route={route} />;
    default:
      return <DashboardPage navigate={navigate} />;
  }
}

export default function SocApp({ expiresAt, navigate, onSignOut, route, theme, toggleTheme, user }) {
  const allowedRoute = canAccessSocRoute(route, user) ? route : SOC_ROUTES.dashboard;

  useEffect(() => {
    if (allowedRoute !== route) navigate(allowedRoute);
  }, [allowedRoute, navigate, route]);

  return (
    <SocWorkspaceProvider user={user}>
      <SocShell
        expiresAt={expiresAt}
        navigate={navigate}
        onSignOut={onSignOut}
        route={allowedRoute}
        theme={theme}
        toggleTheme={toggleTheme}
        user={user}
      >
        <Suspense fallback={<LoadingState />}>
          <RouteView navigate={navigate} route={allowedRoute} theme={theme} toggleTheme={toggleTheme} />
        </Suspense>
      </SocShell>
    </SocWorkspaceProvider>
  );
}
