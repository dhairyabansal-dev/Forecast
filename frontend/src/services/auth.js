import axios from "axios";

const authApi = axios.create({
  baseURL: "/api/auth",
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

export const getCurrentUser = () => authApi.get("/me").then((r) => r.data);
export const login = (username, password) => authApi.post("/login", { username, password }).then((r) => r.data);
export const register = (email, password, full_name) => authApi.post("/register", { email, password, full_name }).then((r) => r.data);
export const logout = () => authApi.post("/logout").then((r) => r.data);

export default authApi;
