/**
 * SOC 2 — Monitoring Controls (CC7.1 – CC7.2)
 *
 * Defines security monitoring controls and alerting thresholds for
 * continuous monitoring of system security and availability.
 */

export interface MonitoringControl {
  id: string;
  name: string;
  description: string;
  metric: string;
  threshold: number;
  comparison: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  enabled: boolean;
  checkIntervalSeconds: number;
}

export interface MonitoringAlert {
  id: string;
  controlId: string;
  controlName: string;
  triggeredAt: number;
  value: number;
  threshold: number;
  severity: 'warning' | 'critical';
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: number;
}

export const SOC2_MONITORING_CONTROLS: MonitoringControl[] = [
  {
    id: 'failed_logins_5min',
    name: 'Failed Login Rate',
    description: 'Alert when failed login attempts exceed 10 in 5 minutes',
    metric: 'auth.failed_logins.count',
    threshold: 10,
    comparison: 'gt',
    enabled: true,
    checkIntervalSeconds: 300,
  },
  {
    id: 'api_error_rate',
    name: 'API Error Rate',
    description: 'Alert when API 5xx error rate exceeds 5%',
    metric: 'api.errors.5xx_rate',
    threshold: 5,
    comparison: 'gt',
    enabled: true,
    checkIntervalSeconds: 60,
  },
  {
    id: 'latency_p95',
    name: 'API Latency P95',
    description: 'Alert when p95 latency exceeds 2000ms',
    metric: 'api.latency.p95_ms',
    threshold: 2000,
    comparison: 'gt',
    enabled: true,
    checkIntervalSeconds: 60,
  },
  {
    id: 'db_pool_utilization',
    name: 'DB Pool Utilization',
    description: 'Alert when DB connection pool utilization exceeds 80%',
    metric: 'db.pool.utilization_pct',
    threshold: 80,
    comparison: 'gt',
    enabled: true,
    checkIntervalSeconds: 30,
  },
  {
    id: 'audit_chain_integrity',
    name: 'Audit Chain Integrity',
    description: 'Alert when audit chain verification fails',
    metric: 'audit.chain.valid',
    threshold: 1,
    comparison: 'lt',
    enabled: true,
    checkIntervalSeconds: 3600,
  },
  {
    id: 'unauthorized_access_attempts',
    name: 'Unauthorized Access Attempts',
    description: 'Alert when unauthorized access attempts exceed 5 in 10 minutes',
    metric: 'security.access_denied.count',
    threshold: 5,
    comparison: 'gt',
    enabled: true,
    checkIntervalSeconds: 600,
  },
];

export class MonitoringControlsService {
  private alerts: MonitoringAlert[] = [];
  private lastValues: Map<string, number> = new Map();

  getControls(): MonitoringControl[] {
    return SOC2_MONITORING_CONTROLS.filter((c) => c.enabled);
  }

  /**
   * Evaluate a metric value against the configured controls.
   * Returns any alerts that were triggered.
   */
  evaluateMetric(metric: string, value: number): MonitoringAlert[] {
    this.lastValues.set(metric, value);
    const triggeredAlerts: MonitoringAlert[] = [];

    for (const control of SOC2_MONITORING_CONTROLS) {
      if (!control.enabled || control.metric !== metric) continue;

      const breached = this.checkThreshold(value, control.threshold, control.comparison);
      if (breached) {
        const alert: MonitoringAlert = {
          id: crypto.randomUUID(),
          controlId: control.id,
          controlName: control.name,
          triggeredAt: Date.now(),
          value,
          threshold: control.threshold,
          severity: this.determineSeverity(control, value),
          acknowledged: false,
        };
        this.alerts.push(alert);
        triggeredAlerts.push(alert);
      }
    }

    return triggeredAlerts;
  }

  private checkThreshold(value: number, threshold: number, comparison: string): boolean {
    switch (comparison) {
      case 'gt':
        return value > threshold;
      case 'lt':
        return value < threshold;
      case 'eq':
        return value === threshold;
      case 'gte':
        return value >= threshold;
      case 'lte':
        return value <= threshold;
      default:
        return false;
    }
  }

  private determineSeverity(control: MonitoringControl, value: number): 'warning' | 'critical' {
    // If the value exceeds 2x the threshold, it's critical
    if (control.comparison === 'gt' && value > control.threshold * 2) {
      return 'critical';
    }
    if (control.comparison === 'lt' && value < control.threshold * 0.5) {
      return 'critical';
    }
    return 'warning';
  }

  acknowledgeAlert(alertId: string, userId: string): boolean {
    const alert = this.alerts.find((a) => a.id === alertId);
    if (!alert || alert.acknowledged) return false;
    alert.acknowledged = true;
    alert.acknowledgedBy = userId;
    alert.acknowledgedAt = Date.now();
    return true;
  }

  getActiveAlerts(): MonitoringAlert[] {
    return this.alerts.filter((a) => !a.acknowledged);
  }

  getAllAlerts(): MonitoringAlert[] {
    return [...this.alerts];
  }

  getLastValue(metric: string): number | undefined {
    return this.lastValues.get(metric);
  }
}
