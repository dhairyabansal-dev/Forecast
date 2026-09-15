import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import App from "./AppFinal.jsx";

export default function SecureApp() {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (location.pathname === "/" || location.pathname === "/login" || location.pathname === "/register") {
      navigate("/dashboard", { replace: true });
    }
  }, [location.pathname, navigate]);

  return <App />;
}
