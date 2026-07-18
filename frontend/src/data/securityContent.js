export const SECURITY_FEATURES = Object.freeze([
  {
    icon: "monitoring",
    title: "24/7 threat monitoring",
    copy: "Continuous protection across your environment",
  },
  {
    icon: "detection",
    title: "AI-powered detection",
    copy: "Identify suspicious behavior before it escalates",
  },
  {
    icon: "response",
    title: "Rapid incident response",
    copy: "Contain threats with automated playbooks",
  },
]);

export const SECURITY_EVENTS = Object.freeze([
  {
    time: "14:32:08",
    severity: "CRITICAL",
    service: "web-01",
    message: "ssh: Failed password for root (47th attempt)",
  },
  {
    time: "14:32:09",
    severity: "MEDIUM",
    service: "ai-engine",
    message: "anomaly score 87/100 - above threshold",
  },
  {
    time: "14:32:09",
    severity: "OK",
    service: "alerts",
    message: "ALT-0912 created - rule R-101 brute-force",
  },
  {
    time: "14:33:02",
    severity: "INFO",
    service: "incidents",
    message: "INC-016 opened - escalated to supervisor",
  },
]);
