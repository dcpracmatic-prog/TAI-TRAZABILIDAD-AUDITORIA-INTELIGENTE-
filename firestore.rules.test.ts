/**
 * Security Rules Specification Verification Runner for TAI
 * Validates the "Dirty Dozen" adversarial payloads against Firestore rules invariants.
 */

export interface DirtyDozenCase {
  id: string;
  description: string;
  targetPath: string;
  operation: 'create' | 'update' | 'delete' | 'get' | 'list';
  expected: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_TESTS: DirtyDozenCase[] = [
  { id: 'P01', description: 'Spoofing ownerId on package create', targetPath: '/packages/pkg_spoof', operation: 'create', expected: 'PERMISSION_DENIED' },
  { id: 'P02', description: 'Unverified admin email spoof', targetPath: '/packages/pkg_unverified', operation: 'create', expected: 'PERMISSION_DENIED' },
  { id: 'P03', description: 'Shadow ghost field injection', targetPath: '/packages/pkg_shadow', operation: 'update', expected: 'PERMISSION_DENIED' },
  { id: 'P04', description: 'Oversized or invalid packageId path', targetPath: '/packages/' + 'x'.repeat(160), operation: 'create', expected: 'PERMISSION_DENIED' },
  { id: 'P05', description: 'Forged client timestamp', targetPath: '/packages/pkg_time', operation: 'create', expected: 'PERMISSION_DENIED' },
  { id: 'P06', description: 'Orphan TraceEvent without parent package', targetPath: '/packages/missing_pkg/events/ev1', operation: 'create', expected: 'PERMISSION_DENIED' },
  { id: 'P07', description: 'Attempted delete on immutable auditLogs', targetPath: '/auditLogs/log_1', operation: 'delete', expected: 'PERMISSION_DENIED' },
  { id: 'P08', description: 'Reverting CSG-invalidated CVV back to valid', targetPath: '/packages/pkg_1/events/ev_1', operation: 'update', expected: 'PERMISSION_DENIED' },
  { id: 'P09', description: 'Cross-tenant list query on packages', targetPath: '/packages', operation: 'list', expected: 'PERMISSION_DENIED' },
  { id: 'P10', description: 'Cross-user read on pilotConfigs', targetPath: '/pilotConfigs/other_uid', operation: 'get', expected: 'PERMISSION_DENIED' },
  { id: 'P11', description: 'Payload size overflow (>500 chars observations)', targetPath: '/packages/pkg_1', operation: 'update', expected: 'PERMISSION_DENIED' },
  { id: 'P12', description: 'Mutating immutable ownerId or createdAt', targetPath: '/packages/pkg_1', operation: 'update', expected: 'PERMISSION_DENIED' },
];
