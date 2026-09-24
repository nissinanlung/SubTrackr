/**
 * SOC 2 — Incident Response (CC7.3 – CC7.4)
 *
 * Provides a structured incident response workflow with severity
 * classification, escalation paths, and post-incident documentation.
 */

export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  reportedBy: string;
  assignedTo?: string;
  createdAt: number;
  updatedAt: number;
  containedAt?: number;
  resolvedAt?: number;
  closedAt?: number;
  timeline: IncidentTimelineEntry[];
  rootCause?: string;
  remediationActions?: string[];
}

export interface IncidentTimelineEntry {
  timestamp: number;
  action: string;
  actorId: string;
  details?: string;
}

export const SOC2_INCIDENT_RESPONSE_CONFIG = {
  escalationTimeoutsMinutes: {
    low: 240,
    medium: 60,
    high: 15,
    critical: 5,
  } as Record<IncidentSeverity, number>,
  requireRootCauseAnalysis: true,
  requireRemediationPlan: true,
  autoNotifyOnSeverity: ['high', 'critical'] as IncidentSeverity[],
};

export class IncidentResponseService {
  private incidents: Map<string, Incident> = new Map();

  reportIncident(input: {
    title: string;
    description: string;
    severity: IncidentSeverity;
    reportedBy: string;
  }): Incident {
    const now = Date.now();
    const incident: Incident = {
      id: crypto.randomUUID(),
      title: input.title,
      description: input.description,
      severity: input.severity,
      status: 'open',
      reportedBy: input.reportedBy,
      createdAt: now,
      updatedAt: now,
      timeline: [
        {
          timestamp: now,
          action: 'incident_reported',
          actorId: input.reportedBy,
          details: input.description,
        },
      ],
    };
    this.incidents.set(incident.id, incident);
    return incident;
  }

  assignIncident(id: string, assigneeId: string, assignedBy: string): Incident | null {
    const inc = this.incidents.get(id);
    if (!inc) return null;
    inc.assignedTo = assigneeId;
    inc.status = 'investigating';
    inc.updatedAt = Date.now();
    inc.timeline.push({
      timestamp: Date.now(),
      action: 'incident_assigned',
      actorId: assignedBy,
      details: `Assigned to ${assigneeId}`,
    });
    return inc;
  }

  containIncident(id: string, actorId: string, details?: string): Incident | null {
    const inc = this.incidents.get(id);
    if (!inc) return null;
    inc.status = 'contained';
    inc.containedAt = Date.now();
    inc.updatedAt = Date.now();
    inc.timeline.push({
      timestamp: Date.now(),
      action: 'incident_contained',
      actorId,
      details,
    });
    return inc;
  }

  resolveIncident(
    id: string,
    actorId: string,
    rootCause: string,
    remediationActions: string[],
  ): Incident | null {
    const inc = this.incidents.get(id);
    if (!inc) return null;
    inc.status = 'resolved';
    inc.resolvedAt = Date.now();
    inc.updatedAt = Date.now();
    inc.rootCause = rootCause;
    inc.remediationActions = remediationActions;
    inc.timeline.push({
      timestamp: Date.now(),
      action: 'incident_resolved',
      actorId,
      details: `Root cause: ${rootCause}`,
    });
    return inc;
  }

  closeIncident(id: string, actorId: string): Incident | null {
    const inc = this.incidents.get(id);
    if (!inc || inc.status !== 'resolved') return null;
    inc.status = 'closed';
    inc.closedAt = Date.now();
    inc.updatedAt = Date.now();
    inc.timeline.push({
      timestamp: Date.now(),
      action: 'incident_closed',
      actorId,
    });
    return inc;
  }

  getIncident(id: string): Incident | null {
    return this.incidents.get(id) ?? null;
  }

  listIncidents(status?: IncidentStatus): Incident[] {
    const all = [...this.incidents.values()];
    if (status) {
      return all.filter((i) => i.status === status);
    }
    return all.sort((a, b) => b.createdAt - a.createdAt);
  }

  /**
   * Check if an incident has exceeded its escalation timeout.
   */
  checkEscalation(id: string): { shouldEscalate: boolean; minutesOverdue: number } {
    const inc = this.incidents.get(id);
    if (!inc || inc.status === 'resolved' || inc.status === 'closed') {
      return { shouldEscalate: false, minutesOverdue: 0 };
    }
    const timeout = SOC2_INCIDENT_RESPONSE_CONFIG.escalationTimeoutsMinutes[inc.severity];
    const elapsed = (Date.now() - inc.createdAt) / 60000;
    const overdue = elapsed - timeout;
    return {
      shouldEscalate: overdue > 0,
      minutesOverdue: Math.max(0, Math.floor(overdue)),
    };
  }
}
