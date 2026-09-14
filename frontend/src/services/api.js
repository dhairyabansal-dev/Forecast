import axios from "axios";

const api = axios.create({
  baseURL: "/api/v1",
  headers: { "Content-Type": "application/json" },
});

// ---------- Health ----------
export const getHealth = () => api.get("/health").then((r) => r.data);
export const getDbHealth = () => api.get("/health/db").then((r) => r.data);
export const getBlockchainHealth = () => api.get("/health/blockchain").then((r) => r.data);

// ---------- Detection / Anomalies ----------
export const listAnomalies = (params = {}) =>
  api.get("/detection/anomalies", { params }).then((r) => r.data);

export const getAnomaly = (id) =>
  api.get(`/detection/anomalies/${id}`).then((r) => r.data);

export const updateAnomaly = (id, payload) =>
  api.patch(`/detection/anomalies/${id}`, payload).then((r) => r.data);

// ---------- Forecast ----------
export const generateForecast = (payload) =>
  api.post("/forecast/generate", payload).then((r) => r.data);

export const startLiveForecast = (payload = {}) =>
  api.post("/forecast/live", payload).then((r) => r.data);

export const getLiveForecastStatus = (jobId) =>
  api.get(`/forecast/live/${jobId}`).then((r) => r.data);

export const getLatestForecast = (networkSegment) =>
  api.get("/forecast/latest", { params: { network_segment: networkSegment } }).then((r) => r.data);

export const listForecasts = (params = {}) =>
  api.get("/forecast", { params }).then((r) => r.data);

// ---------- Threats ----------
export const listThreats = (params = {}) =>
  api.get("/threats", { params }).then((r) => r.data);

export const getThreat = (id) => api.get(`/threats/${id}`).then((r) => r.data);

export const createThreat = (payload) =>
  api.post("/threats", payload).then((r) => r.data);

export const resolveThreat = (id) =>
  api.post(`/threats/${id}/resolve`).then((r) => r.data);

export const deleteThreat = (id) => api.delete(`/threats/${id}`);

// ---------- Evidence ----------
export const listEvidence = (params = {}) =>
  api.get("/evidence", { params }).then((r) => r.data);

export const getEvidence = (id) => api.get(`/evidence/${id}`).then((r) => r.data);

export const createEvidence = (payload) =>
  api.post("/evidence", payload).then((r) => r.data);

export const anchorEvidence = (id) =>
  api.post(`/evidence/${id}/anchor`).then((r) => r.data);

export const verifyEvidence = (id) =>
  api.get(`/evidence/${id}/verify`).then((r) => r.data);

export default api;