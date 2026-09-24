/**
 * SOC 2 — Change Management (CC8.1)
 *
 * Tracks configuration and code changes with an approval workflow,
 * ensuring all modifications to production systems are reviewed and
 * documented.
 */

export type ChangeRequestStatus = 'draft' | 'submitted' | 'approved' | 'rejected' | 'deployed' | 'rolled_back';

export interface ChangeRequest {
  id: string;
  title: string;
  description: string;
  requestedBy: string;
  status: ChangeRequestStatus;
  riskLevel: 'low' | 'medium' | 'high';
  affectedSystems: string[];
  createdAt: number;
  submittedAt?: number;
  approvedBy?: string;
  approvedAt?: number;
  rejectionReason?: string;
  deployedAt?: number;
  rolledBackAt?: number;
  rollbackReason?: string;
  approvers: string[];
}

export const SOC2_CHANGE_MANAGEMENT_CONFIG = {
  requireApproval: true,
  minApprovers: 1,
  requireRiskAssessment: true,
  autoExpireDays: 30,
  requireRollbackPlan: true,
};

export class ChangeManagementService {
  private requests: Map<string, ChangeRequest> = new Map();

  createChangeRequest(input: {
    title: string;
    description: string;
    requestedBy: string;
    riskLevel: 'low' | 'medium' | 'high';
    affectedSystems: string[];
    approvers: string[];
  }): ChangeRequest {
    const request: ChangeRequest = {
      id: crypto.randomUUID(),
      title: input.title,
      description: input.description,
      requestedBy: input.requestedBy,
      status: 'draft',
      riskLevel: input.riskLevel,
      affectedSystems: input.affectedSystems,
      createdAt: Date.now(),
      approvers: input.approvers,
    };
    this.requests.set(request.id, request);
    return request;
  }

  submitChangeRequest(id: string): ChangeRequest | null {
    const req = this.requests.get(id);
    if (!req || req.status !== 'draft') return null;
    req.status = 'submitted';
    req.submittedAt = Date.now();
    return req;
  }

  approveChangeRequest(id: string, approverId: string): ChangeRequest | null {
    const req = this.requests.get(id);
    if (!req || req.status !== 'submitted') return null;
    if (!req.approvers.includes(approverId)) return null;
    req.status = 'approved';
    req.approvedBy = approverId;
    req.approvedAt = Date.now();
    return req;
  }

  rejectChangeRequest(id: string, approverId: string, reason: string): ChangeRequest | null {
    const req = this.requests.get(id);
    if (!req || req.status !== 'submitted') return null;
    if (!req.approvers.includes(approverId)) return null;
    req.status = 'rejected';
    req.approvedBy = approverId;
    req.rejectionReason = reason;
    return req;
  }

  markDeployed(id: string): ChangeRequest | null {
    const req = this.requests.get(id);
    if (!req || req.status !== 'approved') return null;
    req.status = 'deployed';
    req.deployedAt = Date.now();
    return req;
  }

  rollbackChange(id: string, reason: string): ChangeRequest | null {
    const req = this.requests.get(id);
    if (!req || req.status !== 'deployed') return null;
    req.status = 'rolled_back';
    req.rolledBackAt = Date.now();
    req.rollbackReason = reason;
    return req;
  }

  getChangeRequest(id: string): ChangeRequest | null {
    return this.requests.get(id) ?? null;
  }

  listChangeRequests(status?: ChangeRequestStatus): ChangeRequest[] {
    const all = [...this.requests.values()];
    if (status) {
      return all.filter((r) => r.status === status);
    }
    return all.sort((a, b) => b.createdAt - a.createdAt);
  }
}
