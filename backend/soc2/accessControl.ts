/**
 * SOC 2 — Access Control (CC6.1 – CC6.3)
 *
 * Implements role-based access control with least-privilege enforcement,
 * periodic access reviews, and multi-factor authentication tracking.
 */

export type Role = 'viewer' | 'member' | 'admin' | 'super_admin' | 'service';

export interface AccessPolicy {
  role: Role;
  permissions: string[];
  description: string;
  requiresMfa: boolean;
  maxSessionMinutes: number;
}

export interface AccessReviewEntry {
  userId: string;
  role: Role;
  reviewedAt: number;
  reviewerId: string;
  decision: 'retain' | 'revoke' | 'modify';
  newRole?: Role;
  notes?: string;
}

export const SOC2_ACCESS_CONTROL_POLICIES: Record<Role, AccessPolicy> = {
  viewer: {
    role: 'viewer',
    permissions: ['read:subscriptions', 'read:plans'],
    description: 'Read-only access to subscription data',
    requiresMfa: false,
    maxSessionMinutes: 480,
  },
  member: {
    role: 'member',
    permissions: ['read:subscriptions', 'write:subscriptions', 'read:plans', 'write:profile'],
    description: 'Standard user with own-data management',
    requiresMfa: false,
    maxSessionMinutes: 480,
  },
  admin: {
    role: 'admin',
    permissions: [
      'read:subscriptions', 'write:subscriptions',
      'read:plans', 'write:plans',
      'read:users', 'write:users',
      'read:billing', 'write:billing',
    ],
    description: 'Administrative access to user and billing data',
    requiresMfa: true,
    maxSessionMinutes: 120,
  },
  super_admin: {
    role: 'super_admin',
    permissions: [
      'read:subscriptions', 'write:subscriptions',
      'read:plans', 'write:plans',
      'read:users', 'write:users', 'delete:users',
      'read:billing', 'write:billing',
      'read:config', 'write:config',
      'read:audit', 'manage:audit',
    ],
    description: 'Full system access including configuration and audit management',
    requiresMfa: true,
    maxSessionMinutes: 60,
  },
  service: {
    role: 'service',
    permissions: ['read:subscriptions', 'read:plans', 'write:subscriptions'],
    description: 'Machine-to-machine service account',
    requiresMfa: false,
    maxSessionMinutes: 60,
  },
};

export type AccessReviewResult = {
  reviewedCount: number;
  revoked: string[];
  modified: { userId: string; oldRole: Role; newRole: Role }[];
  retained: string[];
};

export class AccessControlManager {
  private userRoles: Map<string, Role> = new Map();
  private mfaEnabled: Set<string> = new Set();
  private accessReviews: AccessReviewEntry[] = [];

  assignRole(userId: string, role: Role): void {
    this.userRoles.set(userId, role);
  }

  getUserRole(userId: string): Role | undefined {
    return this.userRoles.get(userId);
  }

  revokeRole(userId: string): boolean {
    return this.userRoles.delete(userId);
  }

  enableMfa(userId: string): void {
    this.mfaEnabled.add(userId);
  }

  disableMfa(userId: string): void {
    this.mfaEnabled.delete(userId);
  }

  isMfaEnabled(userId: string): boolean {
    return this.mfaEnabled.has(userId);
  }

  /**
   * Check if a user has a specific permission based on their role.
   */
  hasPermission(userId: string, permission: string): boolean {
    const role = this.userRoles.get(userId);
    if (!role) return false;
    const policy = SOC2_ACCESS_CONTROL_POLICIES[role];
    return policy.permissions.includes(permission);
  }

  /**
   * Enforce MFA requirement — returns false if the user's role requires MFA
   * but MFA is not enabled.
   */
  enforceMfaRequirement(userId: string): { compliant: boolean; reason?: string } {
    const role = this.userRoles.get(userId);
    if (!role) {
      return { compliant: false, reason: 'User has no assigned role' };
    }
    const policy = SOC2_ACCESS_CONTROL_POLICIES[role];
    if (policy.requiresMfa && !this.mfaEnabled.has(userId)) {
      return {
        compliant: false,
        reason: `Role "${role}" requires MFA but it is not enabled for user ${userId}`,
      };
    }
    return { compliant: true };
  }

  /**
   * Validate session duration against the role's max session time.
   */
  validateSession(userId: string, sessionDurationMinutes: number): { valid: boolean; reason?: string } {
    const role = this.userRoles.get(userId);
    if (!role) {
      return { valid: false, reason: 'User has no assigned role' };
    }
    const policy = SOC2_ACCESS_CONTROL_POLICIES[role];
    if (sessionDurationMinutes > policy.maxSessionMinutes) {
      return {
        valid: false,
        reason: `Session exceeded max duration of ${policy.maxSessionMinutes} minutes for role "${role}"`,
      };
    }
    return { valid: true };
  }

  /**
   * Conduct a periodic access review. Records decisions and applies
   * revoke/modify actions.
   */
  conductAccessReview(
    reviewerId: string,
    entries: Omit<AccessReviewEntry, 'reviewedAt' | 'reviewerId'>[],
  ): AccessReviewResult {
    const reviewedAt = Date.now();
    const revoked: string[] = [];
    const modified: { userId: string; oldRole: Role; newRole: Role }[] = [];
    const retained: string[] = [];

    for (const entry of entries) {
      const fullEntry: AccessReviewEntry = { ...entry, reviewedAt, reviewerId };
      this.accessReviews.push(fullEntry);

      switch (entry.decision) {
        case 'revoke':
          this.revokeRole(entry.userId);
          revoked.push(entry.userId);
          break;
        case 'modify':
          if (entry.newRole) {
            const oldRole = this.userRoles.get(entry.userId);
            this.assignRole(entry.userId, entry.newRole);
            if (oldRole) {
              modified.push({ userId: entry.userId, oldRole, newRole: entry.newRole });
            }
          }
          break;
        case 'retain':
          retained.push(entry.userId);
          break;
      }
    }

    return {
      reviewedCount: entries.length,
      revoked,
      modified,
      retained,
    };
  }

  getAccessReviewHistory(): AccessReviewEntry[] {
    return [...this.accessReviews];
  }
}
