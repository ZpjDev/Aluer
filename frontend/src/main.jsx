import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

class RootErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error("Aluer Nebula Console crashed", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="fatal-shell">
          <div className="fatal-card">
            <p className="eyebrow">ALUER UI RECOVERY</p>
            <h1>界面加载失败</h1>
            <p>前端捕获到了运行时错误，但主程序仍可能正常运行。请刷新页面，或替换为最新构建包。</p>
            <pre>{String(this.state.error?.message || this.state.error)}</pre>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <App />
    </RootErrorBoundary>
  </React.StrictMode>
);
