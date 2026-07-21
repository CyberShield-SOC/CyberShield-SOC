import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { canAdministerWorkspace, canMutateInvestigations } from "../../utils/permissions";
import { detectionRules } from "../data/mockData";
import { socRepository } from "../services/socRepository";
import { nextSequentialId } from "../utils/recordIds";
import { incidentTerminalAction, isTerminalIncidentStatus } from "../utils/incidentWorkflow";
import { filterRecordsByTimeRange, normalizeTimeRange } from "../utils/timeRange";
import { deriveWorkspaceCounts } from "../utils/workspaceSelectors";

const SocWorkspaceContext = createContext(null);
const NOTIFICATION_STATE_KEY = "cybershield-session-notifications";

function readNotificationState() {
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(NOTIFICATION_STATE_KEY) || "{}");
    const read = Array.isArray(parsed.read) ? parsed.read.filter((id) => typeof id === "string").slice(0, 500) : [];
    const dismissed = Array.isArray(parsed.dismissed) ? parsed.dismissed.filter((id) => typeof id === "string").slice(0, 500) : [];
    return {
      read: new Set(read),
      dismissed: new Set(dismissed),
    };
  } catch {
    return { read: new Set(), dismissed: new Set() };
  }
}

const RESOURCE_LOADERS = Object.freeze({
  health: () => socRepository.getHealth(),
  dashboard: () => socRepository.getDashboard(),
  events: () => socRepository.getEvents(),
  alerts: () => socRepository.getAlerts(),
  incidents: () => socRepository.getIncidents(),
  notes: () => socRepository.getNotes(),
  settings: () => socRepository.getSettings(),
});

const INITIAL_RESOURCE_STATE = Object.freeze(
  Object.fromEntries(
    Object.keys(RESOURCE_LOADERS).map((key) => [key, { loading: true, error: "", refreshedAt: null }]),
  ),
);

function friendlyResourceName(key) {
  return key === "notes" ? "analyst notes" : key;
}

export function SocWorkspaceProvider({ children, user }) {
  const [apiHealth, setApiHealth] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [notes, setNotes] = useState([]);
  const [settings, setSettings] = useState(null);
  const [resources, setResources] = useState(INITIAL_RESOURCE_STATE);
  const [mutation, setMutation] = useState({ loading: false, error: "", message: "" });
  const [notificationState, setNotificationState] = useState(readNotificationState);
  const [globalTimeRange, setGlobalTimeRangeState] = useState("24h");
  const [trackingIncidentId, setTrackingIncidentId] = useState(null);
  // Keep explicit investigation selections stable while route components
  // mount and unmount. They reset with the workspace provider on sign-out.
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedEventId, setSelectedEventId] = useState(null);
  const mountedRef = useRef(true);
  const refreshVersionsRef = useRef({});
  const pendingMutationsRef = useRef(new Set());
  const canWrite = canMutateInvestigations(user);
  const canAdminister = canAdministerWorkspace(user);
  const currentActor = user?.full_name || user?.username || user?.email || "Yugal P.";

  function rejectReadOnlyMutation() {
    if (canWrite) return false;
    setMutation({ loading: false, error: "Your Viewer role has read-only access.", message: "" });
    return true;
  }

  function acquireMutation(key) {
    // Keep the global mutation indicator truthful and prevent conflicting writes.
    if (pendingMutationsRef.current.size > 0) return false;
    pendingMutationsRef.current.add(key);
    return true;
  }

  function releaseMutation(key) {
    pendingMutationsRef.current.delete(key);
  }

  useEffect(() => {
    if (mutation.loading || (!mutation.message && !mutation.error)) return undefined;

    const timeoutId = window.setTimeout(() => {
      setMutation({ loading: false, error: "", message: "" });
    }, 3200);

    return () => window.clearTimeout(timeoutId);
  }, [mutation]);

  useEffect(() => {
    try {
      window.sessionStorage.setItem(NOTIFICATION_STATE_KEY, JSON.stringify({
        read: [...notificationState.read],
        dismissed: [...notificationState.dismissed],
      }));
    } catch {
      // Notification preferences remain available in memory when storage is blocked.
    }
  }, [notificationState]);
  const setters = useMemo(() => ({
    health: setApiHealth,
    dashboard: setDashboard,
    events: setEvents,
    alerts: setAlerts,
    incidents: setIncidents,
    notes: setNotes,
    settings: setSettings,
  }), []);

  const refresh = useCallback(async (key) => {
    const loader = RESOURCE_LOADERS[key];
    if (!loader) return;
    const requestVersion = (refreshVersionsRef.current[key] || 0) + 1;
    refreshVersionsRef.current[key] = requestVersion;

    setResources((current) => ({
      ...current,
      [key]: { ...current[key], loading: true, error: "" },
    }));

    try {
      const value = await loader();
      if (!mountedRef.current || refreshVersionsRef.current[key] !== requestVersion) return;
      setters[key](value);
      setResources((current) => ({
        ...current,
        [key]: { loading: false, error: "", refreshedAt: new Date().toISOString() },
      }));
      return value;
    } catch {
      if (!mountedRef.current || refreshVersionsRef.current[key] !== requestVersion) return;
      setResources((current) => ({
        ...current,
        [key]: {
          ...current[key],
          loading: false,
          error: `The ${friendlyResourceName(key)} could not be loaded. Try again.`,
        },
      }));
      return null;
    }
  }, [setters]);

  const refreshAll = useCallback(() => {
    return Promise.all(Object.keys(RESOURCE_LOADERS).map((key) => refresh(key)));
  }, [refresh]);

  const setGlobalTimeRange = useCallback((value) => {
    setGlobalTimeRangeState(normalizeTimeRange(value));
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    refreshAll();
    return () => {
      mountedRef.current = false;
    };
  }, [refreshAll]);

  useEffect(() => {
    if (settings?.workspace?.defaultTimeRange) {
      setGlobalTimeRange(settings.workspace.defaultTimeRange);
    }
  }, [setGlobalTimeRange, settings?.workspace?.defaultTimeRange]);

  useEffect(() => {
    // Background tabs should not create avoidable polling traffic. Refresh as
    // soon as the workspace becomes visible, then resume the normal cadence.
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") refresh("health");
    };
    const intervalId = window.setInterval(refreshWhenVisible, 60_000);
    document.addEventListener("visibilitychange", refreshWhenVisible);
    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, [refresh]);

  const commitNotes = useCallback(async (updater, successMessage) => {
    if (rejectReadOnlyMutation()) return false;
    const mutationKey = "notes";
    if (!acquireMutation(mutationKey)) return false;
    const previous = notes;
    const next = updater(previous);
    setNotes(next);
    setMutation({ loading: true, error: "", message: "Saving notes…" });
    try {
      const saved = await socRepository.saveNotes(next);
      setNotes(saved);
      setMutation({ loading: false, error: "", message: successMessage });
      return true;
    } catch (error) {
      setNotes(previous);
      await refresh("notes");
      setMutation({ loading: false, error: error.message || "The note change could not be saved.", message: "" });
      return false;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canWrite, notes, refresh]);

  const addNote = useCallback((input) => {
    if (input.linkedType === "incident" && notes.filter((item) => item.linkedType === "incident" && item.linkedId === input.linkedId).length >= 5) {
      setMutation({ loading: false, error: "This incident already has the maximum of 5 analyst notes. Delete a note before adding another.", message: "" });
      return Promise.resolve(false);
    }
    const now = new Date().toISOString();
    const note = {
      id: nextSequentialId(notes, "NOTE-", 1, 3),
      title: input.title.trim(),
      body: input.body.trim(),
      author: currentActor,
      createdAt: now,
      updatedAt: now,
      tags: input.tags || [],
      linkedType: input.linkedType || "workspace",
      linkedId: input.linkedId?.trim() || "SOC-DAY",
      pinned: false,
      archived: false,
      versions: [{ version: 1, at: now, author: currentActor, summary: "Note created" }],
    };
    return commitNotes((current) => [note, ...current], "Note saved");
  }, [commitNotes, currentActor, notes]);

  const updateNote = useCallback((noteId, updates) => {
    const now = new Date().toISOString();
    return commitNotes((current) => current.map((note) => {
      if (note.id !== noteId) return note;
      return {
        ...note,
        ...updates,
        updatedAt: now,
        versions: [
          ...note.versions,
          {
            version: note.versions.length + 1,
            at: now,
            author: currentActor,
            summary: updates.archived !== undefined ? (updates.archived ? "Note archived" : "Note restored") : "Content updated",
          },
        ],
      };
    }), "Note history updated");
  }, [commitNotes, currentActor]);

  const deleteNote = useCallback(async (noteId) => {
    if (rejectReadOnlyMutation()) return false;
    const mutationKey = "notes";
    if (!acquireMutation(mutationKey)) return false;
    setMutation({ loading: true, error: "", message: "Deleting analyst note…" });
    try {
      await socRepository.deleteNote(noteId);
      setNotes((current) => current.filter((note) => note.id !== noteId));
      setMutation({ loading: false, error: "", message: "Analyst note deleted" });
      return true;
    } catch (error) {
      await refresh("notes");
      setMutation({ loading: false, error: error.message || "The analyst note could not be deleted.", message: "" });
      return false;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canWrite, refresh]);

  const updateAlertStatus = useCallback(async (alertId, status) => {
    if (rejectReadOnlyMutation()) return false;
    const mutationKey = `alert:${alertId}`;
    if (!acquireMutation(mutationKey)) return false;
    const previousAlert = alerts.find((alert) => alert.id === alertId);
    setAlerts((current) => current.map((alert) => alert.id === alertId ? { ...alert, status } : alert));
    setMutation({ loading: true, error: "", message: "Updating alert…" });
    try {
      const updated = await socRepository.updateAlertStatus(alertId, status);
      setAlerts((current) => current.map((alert) => (
        alert.id === alertId ? { ...alert, status: updated.status } : alert
      )));
      setMutation({ loading: false, error: "", message: "Alert status updated" });
      return true;
    } catch (error) {
      if (previousAlert) {
        setAlerts((current) => current.map((alert) => (
          alert.id === alertId && alert.status === status
            ? { ...alert, status: previousAlert.status }
            : alert
        )));
      }
      setMutation({ loading: false, error: error.message || "The alert status could not be updated.", message: "" });
      return false;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [alerts, canWrite]);

  const updateIncidentStatus = useCallback(async (incidentId, status) => {
    if (rejectReadOnlyMutation()) return false;
    const mutationKey = `incident:${incidentId}`;
    if (!acquireMutation(mutationKey)) return false;
    const previousIncident = incidents.find((incident) => incident.id === incidentId);
    const changedAt = new Date().toISOString();
    const isTerminal = isTerminalIncidentStatus(status);
    const completedBy = isTerminal ? currentActor : null;
    const completedByUserId = isTerminal ? Number(user?.id) || null : null;
    setIncidents((current) => current.map((incident) => incident.id === incidentId ? {
      ...incident,
      status,
      updated: changedAt,
      completedAt: isTerminal ? changedAt : null,
      completedBy,
      completedByUserId,
    } : incident));
    setMutation({ loading: true, error: "", message: "Updating incident…" });
    try {
      const updated = await socRepository.updateIncidentStatus(incidentId, status);
      setIncidents((current) => current.map((incident) => (
        incident.id === incidentId
          ? {
            ...incident,
            status: updated.status,
            updated: updated.updated || changedAt,
            completedAt: isTerminalIncidentStatus(updated.status) ? updated.completedAt || updated.updated || changedAt : null,
            completedBy: isTerminalIncidentStatus(updated.status) ? updated.completedBy || completedBy : null,
            completedByUserId: isTerminalIncidentStatus(updated.status) ? updated.completedByUserId || completedByUserId : null,
          }
          : incident
      )));
      const terminalAction = incidentTerminalAction(updated.status);
      setMutation({
        loading: false,
        error: "",
        message: terminalAction
          ? `${incidentId} was ${terminalAction.successMessage}.`
          : "Incident status updated",
      });
      return true;
    } catch (error) {
      if (previousIncident) {
        setIncidents((current) => current.map((incident) => (
          incident.id === incidentId && incident.status === status
            ? {
              ...incident,
              status: previousIncident.status,
              updated: previousIncident.updated,
              completedAt: previousIncident.completedAt || null,
              completedBy: previousIncident.completedBy || null,
              completedByUserId: previousIncident.completedByUserId || null,
            }
            : incident
        )));
      }
      setMutation({ loading: false, error: error.message || "The incident status could not be updated.", message: "" });
      return false;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canWrite, currentActor, incidents, user?.id]);

  const updateIncidentAssignee = useCallback(async (incidentId, assignedUserId, assigneeLabel) => {
    if (rejectReadOnlyMutation()) return false;
    const mutationKey = `incident-assignee:${incidentId}`;
    if (!acquireMutation(mutationKey)) return false;
    const previousIncident = incidents.find((incident) => incident.id === incidentId);
    const nextOwner = assigneeLabel || (assignedUserId ? `User ${assignedUserId}` : "Unassigned");
    setIncidents((current) => current.map((incident) => incident.id === incidentId ? {
      ...incident,
      assignedUserId: assignedUserId || null,
      owner: nextOwner,
    } : incident));
    setMutation({ loading: true, error: "", message: "Updating assignee…" });
    try {
      const updated = await socRepository.updateIncidentAssignee(incidentId, assignedUserId);
      setIncidents((current) => current.map((incident) => (
        incident.id === incidentId
          ? { ...incident, assignedUserId: updated.assignedUserId ?? (assignedUserId || null), owner: nextOwner }
          : incident
      )));
      setMutation({ loading: false, error: "", message: "Assignee updated" });
      return true;
    } catch (error) {
      if (previousIncident) {
        setIncidents((current) => current.map((incident) => (
          incident.id === incidentId
            ? { ...incident, assignedUserId: previousIncident.assignedUserId, owner: previousIncident.owner }
            : incident
        )));
      }
      setMutation({ loading: false, error: error.message || "The assignee could not be updated.", message: "" });
      return false;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canWrite, incidents]);

  const createIncident = useCallback(async (incident) => {
    if (rejectReadOnlyMutation()) return null;
    const mutationKey = "create-incident";
    if (!acquireMutation(mutationKey)) return null;
    setMutation({ loading: true, error: "", message: "Creating incident…" });
    try {
      const created = await socRepository.createIncident(incident);
      setIncidents((current) => [created, ...current]);
      setMutation({ loading: false, error: "", message: `${created.id} created` });
      return created;
    } catch (error) {
      setMutation({ loading: false, error: error.message || "The incident could not be created.", message: "" });
      return null;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canWrite]);

  const uploadLogFile = useCallback(async (file) => {
    if (rejectReadOnlyMutation()) {
      throw new Error("Your Viewer role has read-only access.");
    }
    const mutationKey = "upload-log";
    if (!acquireMutation(mutationKey)) {
      throw new Error("A log upload is already in progress.");
    }
    setMutation({ loading: true, error: "", message: "Uploading and analyzing log…" });
    try {
      const result = await socRepository.uploadLog(file);
      await Promise.all([
        refresh("events"),
        refresh("alerts"),
        refresh("dashboard"),
      ]);
      // Imported SIEM exports often contain historical event timestamps. Show
      // the completed import immediately instead of hiding it behind 24h.
      setGlobalTimeRange("all");
      setMutation({
        loading: false,
        error: "",
        message: `${result.parsing?.stored_entries || 0} events ingested`,
      });
      return result;
    } catch (error) {
      setMutation({
        loading: false,
        error: error.message || "The log file could not be uploaded.",
        message: "",
      });
      throw error;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canWrite, refresh, setGlobalTimeRange]);

  const saveWorkspaceSettings = useCallback(async (nextSettings) => {
    if (!canAdminister) {
      setMutation({ loading: false, error: "Only an Admin can change workspace settings.", message: "" });
      return null;
    }
    const mutationKey = "settings";
    if (!acquireMutation(mutationKey)) return null;
    const previous = settings;
    setSettings(nextSettings);
    setMutation({ loading: true, error: "", message: "Saving workspace settings…" });
    try {
      const savedSettings = await socRepository.saveSettings(nextSettings);
      setSettings(savedSettings);
      setMutation({ loading: false, error: "", message: "Workspace settings saved" });
      return savedSettings;
    } catch (error) {
      setSettings(previous);
      setMutation({ loading: false, error: error.message || "The workspace settings could not be saved.", message: "" });
      return null;
    } finally {
      releaseMutation(mutationKey);
    }
  }, [canAdminister, settings]);

  const notifications = useMemo(() => {
    const preferences = settings?.notifications;
    const alertNotifications = alerts
      .filter((alert) => ["new", "triaging", "investigating"].includes(alert.status))
      .filter((alert) => alert.severity !== "critical" || preferences?.criticalAlerts !== false)
      .slice(0, 4)
      .map((alert) => ({
        id: `notification-alert-${alert.id}`,
        type: "alert",
        recordId: alert.id,
        title: `${alert.severity === "critical" ? "Critical" : "Active"} alert · ${alert.id}`,
        detail: alert.title,
        route: "alerts",
      }));
    const incidentNotifications = incidents
      .filter((incident) => (
        (incident.status === "escalated" && preferences?.incidentEscalations !== false)
        || (incident.status === "awaiting approval" && preferences?.approvalRequests !== false)
      ))
      .map((incident) => ({
        id: `notification-incident-${incident.id}`,
        type: "incident",
        recordId: incident.id,
        title: incident.status === "awaiting approval" ? "Approval required" : "Incident escalated",
        detail: `${incident.id} · ${incident.title}`,
        route: "incidents",
      }));
    return [...alertNotifications, ...incidentNotifications]
      .filter((notification) => !notificationState.dismissed.has(notification.id))
      .map((notification) => ({
        ...notification,
        read: notificationState.read.has(notification.id),
      }));
  }, [alerts, incidents, notificationState, settings]);

  const markNotificationRead = useCallback((notificationId) => {
    setNotificationState((current) => ({
      ...current,
      read: new Set([...current.read, notificationId]),
    }));
  }, []);

  const markNotificationUnread = useCallback((notificationId) => {
    setNotificationState((current) => {
      const read = new Set(current.read);
      read.delete(notificationId);
      return { ...current, read };
    });
  }, []);

  const markAllNotificationsRead = useCallback(() => {
    setNotificationState((current) => ({
      ...current,
      read: new Set([...current.read, ...notifications.map((notification) => notification.id)]),
    }));
  }, [notifications]);

  const markAllNotificationsUnread = useCallback(() => {
    const visibleIds = new Set(notifications.map((notification) => notification.id));
    setNotificationState((current) => ({
      ...current,
      read: new Set([...current.read].filter((id) => !visibleIds.has(id))),
    }));
  }, [notifications]);

  const clearNotification = useCallback((notificationId) => {
    setNotificationState((current) => ({
      ...current,
      dismissed: new Set([...current.dismissed, notificationId]),
    }));
    setMutation({ loading: false, error: "", message: "Notification cleared" });
  }, []);

  const clearAllNotifications = useCallback(() => {
    setNotificationState((current) => ({
      ...current,
      dismissed: new Set([...current.dismissed, ...notifications.map((notification) => notification.id)]),
    }));
    setMutation({ loading: false, error: "", message: "Notifications cleared" });
  }, [notifications]);

  const timeFilteredEvents = useMemo(
    () => filterRecordsByTimeRange(events, globalTimeRange, "timestamp"),
    [events, globalTimeRange],
  );
  const timeFilteredIngestedEvents = useMemo(
    () => filterRecordsByTimeRange(events, globalTimeRange, ["ingestedAt", "timestamp"]),
    [events, globalTimeRange],
  );
  const timeFilteredAlerts = useMemo(
    () => filterRecordsByTimeRange(alerts, globalTimeRange, "createdAt"),
    [alerts, globalTimeRange],
  );
  const displayIncidents = useMemo(() => incidents.map((incident) => {
    if (!isTerminalIncidentStatus(incident.status)) return incident;
    const belongsToCurrentUser = incident.completedByUserId && Number(incident.completedByUserId) === Number(user?.id);
    return {
      ...incident,
      completedBy: belongsToCurrentUser ? currentActor : incident.completedBy || "Unknown analyst",
    };
  }), [currentActor, incidents, user?.id]);
  const timeFilteredIncidents = useMemo(
    () => filterRecordsByTimeRange(displayIncidents, globalTimeRange, "updated"),
    [displayIncidents, globalTimeRange],
  );
  const counts = deriveWorkspaceCounts(timeFilteredAlerts, timeFilteredIncidents, notifications);
  const activeAlertCount = counts.activeAlerts;
  const openIncidentCount = counts.openIncidents;
  const unreadNotificationCount = counts.unreadNotifications;
  const storageUsed = useMemo(() => new TextEncoder().encode(JSON.stringify(notes)).length, [notes]);

  const value = useMemo(() => ({
    apiHealth,
    dashboard,
    repositoryMode: socRepository.mode,
    events,
    alerts,
    incidents: displayIncidents,
    notes,
    settings,
    detectionRules,
    resources,
    mutation,
    globalTimeRange,
    setGlobalTimeRange,
    timeFilteredEvents,
    timeFilteredIngestedEvents,
    timeFilteredAlerts,
    timeFilteredIncidents,
    trackingIncidentId,
    setTrackingIncidentId,
    selectedAlertId,
    setSelectedAlertId,
    selectedIncidentId,
    setSelectedIncidentId,
    selectedEventId,
    setSelectedEventId,
    canWrite,
    canAdminister,
    currentUser: user,
    currentActor,
    notifications,
    activeAlertCount,
    openIncidentCount,
    unreadNotificationCount,
    storage: { used: storageUsed, limit: 256 * 1024 },
    refresh,
    refreshAll,
    addNote,
    updateNote,
    deleteNote,
    updateAlertStatus,
    updateIncidentStatus,
    updateIncidentAssignee,
    createIncident,
    uploadLogFile,
    saveWorkspaceSettings,
    markNotificationRead,
    markNotificationUnread,
    markAllNotificationsRead,
    markAllNotificationsUnread,
    clearNotification,
    clearAllNotifications,
  }), [
    activeAlertCount,
    addNote,
    alerts,
    apiHealth,
    canAdminister,
    canWrite,
    user,
    currentActor,
    createIncident,
    dashboard,
    deleteNote,
    displayIncidents,
    events,
    globalTimeRange,
    incidents,
    settings,
    clearAllNotifications,
    clearNotification,
    markAllNotificationsRead,
    markAllNotificationsUnread,
    markNotificationRead,
    markNotificationUnread,
    mutation,
    notes,
    notifications,
    openIncidentCount,
    refresh,
    refreshAll,
    resources,
    saveWorkspaceSettings,
    setGlobalTimeRange,
    storageUsed,
    timeFilteredAlerts,
    timeFilteredEvents,
    timeFilteredIngestedEvents,
    timeFilteredIncidents,
    trackingIncidentId,
    selectedAlertId,
    selectedIncidentId,
    selectedEventId,
    unreadNotificationCount,
    updateAlertStatus,
    updateIncidentStatus,
    updateIncidentAssignee,
    updateNote,
    uploadLogFile,
  ]);

  return <SocWorkspaceContext.Provider value={value}>{children}</SocWorkspaceContext.Provider>;
}

export function useSocWorkspace() {
  const context = useContext(SocWorkspaceContext);
  if (!context) throw new Error("useSocWorkspace must be used inside SocWorkspaceProvider");
  return context;
}
