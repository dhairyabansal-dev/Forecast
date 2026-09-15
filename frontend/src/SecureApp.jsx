import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import App from "./AppFinal.jsx";
import { getCurrentUser, login, logout, register } from "./services/auth.js";

const ROLE_ACCESS = {
  "/dashboard/simulation": ["ADMIN", "DATA_SCIENTIST", "ANALYST"],
};

function AuthScreen({ initialMode = "login" }) {
  const navigate = useNavigate();
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = mode === "login"
        ? await login(email, password)
        : await register(email, password, name);
      window.dispatchEvent(new CustomEvent("foreflow:authenticated", { detail: result.user }));
      navigate("/dashboard", { replace: true });
    } catch (err) {
      const detail = err.response?.data?.detail;
      setError(Array.isArray(detail) ? detail.join(". ") : detail || "Unable to authenticate. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return <div className="landing" style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
    <div className="modal-backdrop" style={{ position: "relative", inset: "auto", background: "transparent" }}>
      <div className="auth-modal" onClick={(e) => e.stopPropagation()}>
        <div className="auth-icon">◈</div>
        <div className="eyebrow">SECURE ANALYST ACCESS</div>
        <h2>{mode === "login" ? "Welcome back" : "Create analyst account"}</h2>
        <p>{mode === "login" ? "Initialize a secure ForeFlow console session." : "Create a viewer account. Privileged roles are assigned by an administrator."}</p>
        <form onSubmit={submit}>
          {mode === "register" && <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Full name" autoComplete="name" />}
          <input required value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="Analyst email" autoComplete="username" />
          <div style={{ position: "relative" }}>
            <input required value={password} onChange={(e) => setPassword(e.target.value)} type={showPassword ? "text" : "password"} placeholder="Password" minLength={8} autoComplete={mode === "login" ? "current-password" : "new-password"} style={{ width: "100%" }} />
            <button type="button" className="tiny-btn" onClick={() => setShowPassword((v) => !v)} style={{ position: "absolute", right: 8, top: 8 }}>{showPassword ? "Hide" : "Show"}</button>
          </div>
          {mode === "register" && <small>Password: 8+ chars, uppercase, lowercase, number and special character.</small>}
          {error && <div className="toast" style={{ position: "relative", margin: "10px 0", inset: "auto" }}>{error}</div>}
          <button className="primary-btn large full" disabled={loading} type="submit">{loading ? "AUTHENTICATING..." : mode === "login" ? "Enter Console →" : "Create Account →"}</button>
        </form>
        <button className="ghost-btn" type="button" onClick={() => { setMode((v) => v === "login" ? "register" : "login"); setError(""); }}>
          {mode === "login" ? "Need an account? Register" : "Already have an account? Login"}
        </button>
      </div>
    </div>
  </div>;
}

function AccessDenied() {
  const navigate = useNavigate();
  return <div className="landing" style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}><div className="auth-modal"><div className="eyebrow">ACCESS CONTROL</div><h2>Insufficient permissions</h2><p>Your current role does not have access to this workspace.</p><button className="primary-btn large" onClick={() => navigate("/dashboard")}>Return to Console →</button></div></div>;
}

export default function SecureApp() {
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(true);
  const [expired, setExpired] = useState(false);
  const needsAuth = location.pathname.startsWith("/dashboard");
  const requiredRoles = Object.entries(ROLE_ACCESS).find(([path]) => location.pathname.startsWith(path))?.[1];

  useEffect(() => {
    let active = true;
    getCurrentUser().then((result) => { if (active) setUser(result); }).catch(() => { if (active) setUser(null); }).finally(() => { if (active) setChecking(false); });
    const onAuth = (event) => setUser(event.detail);
    const onExpired = () => { setUser(null); setExpired(true); };
    window.addEventListener("foreflow:authenticated", onAuth);
    window.addEventListener("foreflow:session-expired", onExpired);
    return () => { active = false; window.removeEventListener("foreflow:authenticated", onAuth); window.removeEventListener("foreflow:session-expired", onExpired); };
  }, [location.pathname]);

  useEffect(() => {
    if (!location.pathname.startsWith("/")) return undefined;
    const handler = (event) => {
      const target = event.target?.closest?.("button");
      if (!target) return;
      const text = target.textContent?.trim().toLowerCase() || "";
      if (["login", "register →", "start monitoring →"].includes(text)) {
        event.preventDefault();
        event.stopPropagation();
        window.history.pushState({}, "", "#/login");
        window.dispatchEvent(new PopStateEvent("popstate"));
      }
    };
    document.addEventListener("click", handler, true);
    return () => document.removeEventListener("click", handler, true);
  }, [location.pathname]);

  if (location.pathname === "/login") return <AuthScreen initialMode="login" />;
  if (location.pathname === "/register") return <AuthScreen initialMode="register" />;
  if (needsAuth && checking) return <div className="landing" style={{ minHeight: "100vh", display: "grid", placeItems: "center" }}><div className="eyebrow">AUTHENTICATING SESSION...</div></div>;
  if (needsAuth && !user) return <AuthScreen initialMode="login" />;
  if (needsAuth && requiredRoles && !requiredRoles.includes(user.role)) return <AccessDenied />;

  return <>
    {user && <button className="ghost-btn" onClick={async () => { await logout().catch(() => {}); setUser(null); window.location.hash = "#/"; }} style={{ position: "fixed", top: 16, right: 16, zIndex: 10001 }}>Logout · {user.role}</button>}
    {expired && <div className="toast" style={{ zIndex: 10002 }}>Session expired. Please sign in again.</div>}
    <App />
  </>;
}
