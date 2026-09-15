import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import SecureApp from "./SecureApp.jsx";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <HashRouter>
      <SecureApp />
    </HashRouter>
  </React.StrictMode>
);
