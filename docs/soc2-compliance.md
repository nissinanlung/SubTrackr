# SOC 2 Compliance Controls

## Overview

SubTrackr implements SOC 2 Common Criteria controls across four domains:
access control, change management, incident response, and security monitoring.

## Implemented Controls

### Access Control (CC6.1 – CC6.3)
- Role-based access control with 5 predefined roles
- Least-privilege enforcement per role
- MFA requirement for admin and super_admin roles
- Session duration limits per role
- Periodic access review workflow

### Monitoring (CC7.1 – CC7.2)
- 6 monitoring controls covering auth, API, database, and audit integrity
- Threshold-based alerting with severity classification
- Alert acknowledgment workflow

### Incident Response (CC7.3 – CC7.4)
- Incident lifecycle: open → investigating → contained → resolved → closed
- Severity-based escalation timeouts (5 min for critical)
- Root cause analysis and remediation tracking
- Complete audit timeline per incident

### Change Management (CC8.1)
- Change request workflow: draft → submitted → approved → deployed
- Risk level assessment for all changes
- Approver validation (only designated approvers can approve)
- Rollback support with reason tracking

## Usage

```typescript
import { AccessControlManager, ChangeManagementService, IncidentResponseService, MonitoringControlsService, SOC2ComplianceReport } from './soc2';

const report = new SOC2ComplianceReport(
  new AccessControlManager(),
  new ChangeManagementService(),
  new IncidentResponseService(),
  new MonitoringControlsService(),
);
console.log(report.generate());
```
