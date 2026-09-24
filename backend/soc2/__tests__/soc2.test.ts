import { AccessControlManager, SOC2_ACCESS_CONTROL_POLICIES, type Role } from '../accessControl';
import { ChangeManagementService } from '../changeManagement';
import { IncidentResponseService, SOC2_INCIDENT_RESPONSE_CONFIG } from '../incidentResponse';
import { MonitoringControlsService, SOC2_MONITORING_CONTROLS } from '../monitoringControls';
import { SOC2ComplianceReport } from '../soc2Report';

describe('SOC 2 Access Control', () => {
  let manager: AccessControlManager;

  beforeEach(() => {
    manager = new AccessControlManager();
  });

  it('should define policies for all roles', () => {
    const roles: Role[] = ['viewer', 'member', 'admin', 'super_admin', 'service'];
    for (const role of roles) {
      expect(SOC2_ACCESS_CONTROL_POLICIES[role]).toBeDefined();
      expect(SOC2_ACCESS_CONTROL_POLICIES[role].permissions.length).toBeGreaterThan(0);
    }
  });

  it('should assign and check roles', () => {
    manager.assignRole('user-1', 'member');
    expect(manager.getUserRole('user-1')).toBe('member');
    expect(manager.hasPermission('user-1', 'write:subscriptions')).toBe(true);
    expect(manager.hasPermission('user-1', 'write:config')).toBe(false);
  });

  it('should enforce MFA for admin roles', () => {
    manager.assignRole('admin-1', 'admin');
    const result = manager.enforceMfaRequirement('admin-1');
    expect(result.compliant).toBe(false);
    manager.enableMfa('admin-1');
    const result2 = manager.enforceMfaRequirement('admin-1');
    expect(result2.compliant).toBe(true);
  });

  it('should not require MFA for viewer role', () => {
    manager.assignRole('viewer-1', 'viewer');
    const result = manager.enforceMfaRequirement('viewer-1');
    expect(result.compliant).toBe(true);
  });

  it('should validate session duration', () => {
    manager.assignRole('admin-1', 'admin');
    const maxSession = SOC2_ACCESS_CONTROL_POLICIES['admin'].maxSessionMinutes;
    expect(manager.validateSession('admin-1', maxSession).valid).toBe(true);
    expect(manager.validateSession('admin-1', maxSession + 1).valid).toBe(false);
  });

  it('should conduct access reviews', () => {
    manager.assignRole('user-1', 'admin');
    manager.assignRole('user-2', 'member');
    manager.assignRole('user-3', 'viewer');

    const result = manager.conductAccessReview('super-admin', [
      { userId: 'user-1', role: 'admin', decision: 'retain' },
      { userId: 'user-2', role: 'member', decision: 'modify', newRole: 'viewer' },
      { userId: 'user-3', role: 'viewer', decision: 'revoke' },
    ]);

    expect(result.reviewedCount).toBe(3);
    expect(result.retained).toContain('user-1');
    expect(result.modified).toHaveLength(1);
    expect(result.modified[0].newRole).toBe('viewer');
    expect(result.revoked).toContain('user-3');
    expect(manager.getUserRole('user-3')).toBeUndefined();
    expect(manager.getUserRole('user-2')).toBe('viewer');
  });
});

describe('SOC 2 Change Management', () => {
  let service: ChangeManagementService;

  beforeEach(() => {
    service = new ChangeManagementService();
  });

  it('should create and track change requests', () => {
    const req = service.createChangeRequest({
      title: 'Update billing API',
      description: 'Add new pricing tier',
      requestedBy: 'dev-1',
      riskLevel: 'medium',
      affectedSystems: ['billing-api', 'database'],
      approvers: ['admin-1'],
    });
    expect(req.status).toBe('draft');
    expect(req.id).toBeDefined();

    const submitted = service.submitChangeRequest(req.id);
    expect(submitted?.status).toBe('submitted');

    const approved = service.approveChangeRequest(req.id, 'admin-1');
    expect(approved?.status).toBe('approved');
    expect(approved?.approvedBy).toBe('admin-1');

    const deployed = service.markDeployed(req.id);
    expect(deployed?.status).toBe('deployed');
  });

  it('should reject approval from non-approver', () => {
    const req = service.createChangeRequest({
      title: 'Test',
      description: 'Test',
      requestedBy: 'dev-1',
      riskLevel: 'low',
      affectedSystems: ['api'],
      approvers: ['admin-1'],
    });
    service.submitChangeRequest(req.id);
    const result = service.approveChangeRequest(req.id, 'random-user');
    expect(result).toBeNull();
  });

  it('should support rollback', () => {
    const req = service.createChangeRequest({
      title: 'Deploy v2',
      description: 'Major version',
      requestedBy: 'dev-1',
      riskLevel: 'high',
      affectedSystems: ['api', 'db'],
      approvers: ['admin-1'],
    });
    service.submitChangeRequest(req.id);
    service.approveChangeRequest(req.id, 'admin-1');
    service.markDeployed(req.id);
    const rolled = service.rollbackChange(req.id, 'Bug found in production');
    expect(rolled?.status).toBe('rolled_back');
    expect(rolled?.rollbackReason).toBe('Bug found in production');
  });
});

describe('SOC 2 Incident Response', () => {
  let service: IncidentResponseService;

  beforeEach(() => {
    service = new IncidentResponseService();
  });

  it('should report and track incidents through lifecycle', () => {
    const inc = service.reportIncident({
      title: 'API outage',
      description: 'API returning 500s',
      severity: 'high',
      reportedBy: 'monitoring-bot',
    });
    expect(inc.status).toBe('open');
    expect(inc.timeline).toHaveLength(1);

    service.assignIncident(inc.id, 'oncall-1', 'monitoring-bot');
    expect(service.getIncident(inc.id)?.status).toBe('investigating');

    service.containIncident(inc.id, 'oncall-1', 'Restarted service');
    expect(service.getIncident(inc.id)?.status).toBe('contained');

    service.resolveIncident(inc.id, 'oncall-1', 'Memory leak', ['Increase memory limit', 'Add monitoring']);
    expect(service.getIncident(inc.id)?.status).toBe('resolved');
    expect(service.getIncident(inc.id)?.rootCause).toBe('Memory leak');

    service.closeIncident(inc.id, 'admin-1');
    expect(service.getIncident(inc.id)?.status).toBe('closed');
  });

  it('should check escalation for overdue incidents', () => {
    const inc = service.reportIncident({
      title: 'Critical breach',
      description: 'Security incident',
      severity: 'critical',
      reportedBy: 'alert-system',
    });
    // Since it was just created, it shouldn't be overdue yet
    const esc = service.checkEscalation(inc.id);
    expect(esc.shouldEscalate).toBe(false);
  });

  it('should not escalate resolved incidents', () => {
    const inc = service.reportIncident({
      title: 'Minor issue',
      description: 'Small bug',
      severity: 'low',
      reportedBy: 'user-1',
    });
    service.assignIncident(inc.id, 'dev-1', 'user-1');
    service.containIncident(inc.id, 'dev-1');
    service.resolveIncident(inc.id, 'dev-1', 'Bug', ['Fix']);
    const esc = service.checkEscalation(inc.id);
    expect(esc.shouldEscalate).toBe(false);
  });
});

describe('SOC 2 Monitoring Controls', () => {
  let service: MonitoringControlsService;

  beforeEach(() => {
    service = new MonitoringControlsService();
  });

  it('should have monitoring controls defined', () => {
    expect(SOC2_MONITORING_CONTROLS.length).toBeGreaterThanOrEqual(5);
    expect(service.getControls().length).toBeGreaterThanOrEqual(5);
  });

  it('should trigger alerts when thresholds are breached', () => {
    const alerts = service.evaluateMetric('auth.failed_logins.count', 15);
    expect(alerts.length).toBe(1);
    expect(alerts[0].severity).toBe('critical');
  });

  it('should not trigger alerts within threshold', () => {
    const alerts = service.evaluateMetric('auth.failed_logins.count', 5);
    expect(alerts.length).toBe(0);
  });

  it('should acknowledge alerts', () => {
    const alerts = service.evaluateMetric('api.errors.5xx_rate', 10);
    expect(alerts.length).toBe(1);
    expect(service.getActiveAlerts().length).toBe(1);
    service.acknowledgeAlert(alerts[0].id, 'admin-1');
    expect(service.getActiveAlerts().length).toBe(0);
  });
});

describe('SOC 2 Compliance Report', () => {
  it('should generate a compliance report', () => {
    const accessControl = new AccessControlManager();
    const changeManagement = new ChangeManagementService();
    const incidentResponse = new IncidentResponseService();
    const monitoring = new MonitoringControlsService();
    const report = new SOC2ComplianceReport(accessControl, changeManagement, incidentResponse, monitoring);

    const result = report.generate();
    expect(result.totalControls).toBeGreaterThanOrEqual(9);
    expect(result.implementedControls).toBe(result.totalControls);
    expect(result.summary).toContain('SOC 2');
  });
});
