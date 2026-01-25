import { useState, useEffect } from "react";
import { api } from "@/lib/api";

interface ServiceHealth {
  service_type: string;
  service_name: string;
  status: string;
  last_check: string;
}

interface HealthCheckLog {
  service_type: string;
  service_name: string;
  status: string;
  error_message: string | null;
  checked_at: string;
}

interface HealthStatusResponse {
  services: ServiceHealth[];
  recent_checks: HealthCheckLog[];
}

export function useHealthStatus() {
  const [healthData, setHealthData] = useState<HealthStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealthStatus = async () => {
    try {
      const data = await api.get<HealthStatusResponse>("/health/status");
      setHealthData(data);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch health status:", err);
      setError("Failed to fetch health status");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthStatus();
    // Poll every 30 seconds
    const interval = setInterval(fetchHealthStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const unhealthyCount = healthData?.services.filter(
    (s) => s.status === "unhealthy" || s.status === "warning"
  ).length ?? 0;

  return {
    healthData,
    isLoading,
    error,
    unhealthyCount,
    refetch: fetchHealthStatus,
  };
}
