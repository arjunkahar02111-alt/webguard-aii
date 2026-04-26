// src/App.jsx
import { BrowserRouter, Routes, Route } from "react-router-dom";
import LandingPage from "./pages/LandingPage";
import DashboardLayout from "./layouts/DashboardLayout";
import Overview from "./pages/dashboard/Overview";
import LiveMonitoring from "./pages/dashboard/LiveMonitoring";
import ThreatLogs from "./pages/dashboard/ThreatLogs";
import DeployProtection from "./pages/dashboard/DeployProtection";
import AIAssistantPopup from "./components/AIAssistantPopup";

import { AuthProvider } from "./contexts/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Login from "./pages/Login";
import Signup from "./pages/Signup";

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
      {/* Background stays persistent across routes */}
      <div className="cyber-grid-bg" />
      
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        
        {/* Dashboard Pages wrapper */}
        <Route path="/dashboard" element={
          <ProtectedRoute>
            <DashboardLayout />
          </ProtectedRoute>
        }>
          <Route index element={<Overview />} />
          <Route path="live" element={<LiveMonitoring />} />
          <Route path="logs" element={<ThreatLogs />} />
          <Route path="deploy" element={<DeployProtection />} />
        </Route>
      </Routes>
      <AIAssistantPopup />
      </AuthProvider>
    </BrowserRouter>
  );
}
