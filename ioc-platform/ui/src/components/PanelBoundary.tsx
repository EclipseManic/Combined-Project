import { Component, type ReactNode } from "react";

interface Props {
  /** Human-readable name of the panel, shown in the degraded state. */
  label: string;
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Panel-level error isolation.
 *
 * The page-level ErrorBoundary in App.tsx unmounts the ENTIRE result view when
 * any descendant throws, which is the "UI is dead" symptom: one malformed edge
 * in the relationship graph, or one unexpected enrichment shape, blanks the
 * whole lookup. PanelBoundary contains the failure to a single panel and shows
 * a small, self-contained notice so the rest of the result stays usable.
 *
 * Unlike the app-level boundary, this resets automatically when its children
 * change (keyed by the panel it wraps), so navigating to a new lookup clears a
 * stale error without a manual "Try Again" click.
 */
export default class PanelBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error(`Panel "${this.props.label}" failed to render:`, error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          className="rounded-xl border border-verdict-malicious/30 bg-verdict-malicious/5 p-5 text-center"
          role="alert"
        >
          <p className="text-xs font-semibold text-verdict-malicious mb-1">
            {this.props.label} could not be displayed
          </p>
          <p className="text-xs text-text-secondary mb-3">
            This panel hit an unexpected data shape. The rest of the result is
            unaffected.
          </p>
          <button
            type="button"
            onClick={() => this.setState({ hasError: false, error: null })}
            className="px-3 py-1 text-xs bg-bg-elevated text-text-primary border border-border rounded-lg hover:border-accent transition-colors"
          >
            Retry panel
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
