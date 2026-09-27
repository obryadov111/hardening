import { apiFetch } from "./client";

export async function getSnapshotsByOrganization(organizationId) {
  return apiFetch(`/organizations/${organizationId}/snapshots`);
}

export async function compareSnapshots(beforeSnapshotId, afterSnapshotId) {
  const query = new URLSearchParams({
    before_snapshot_id: beforeSnapshotId,
    after_snapshot_id: afterSnapshotId,
  });

  return apiFetch(`/snapshots/compare?${query.toString()}`);
}