import { Component } from "react";

/**
 * Last-resort recovery surface for render and lazy-loading failures. Error
 * details are intentionally not rendered because they may contain internal
 * paths or security data; operational telemetry can be connected separately.
 */
export class AppErrorBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;

    return (
      <main className="fatal-error" role="alert">
        <div>
          <span aria-hidden="true">CS</span>
          <p>CyberShield SOC</p>
          <h1>The workspace could not be displayed</h1>
          <p>Your session data was not changed. Reload the application to reconnect and try again.</p>
          <button type="button" onClick={() => window.location.reload()}>Reload workspace</button>
        </div>
      </main>
    );
  }
}
