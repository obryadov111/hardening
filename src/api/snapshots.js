import { apiFetch } from "./client";

/** Страница сканов организации, новые сначала: { items, total, limit, offset, summary: { total, completed, failed, latest } }. */
export async function getSnapshotsByOrganization(organizationId, { host = "", limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (host) params.set("host", host);
  return apiFetch(`/organizations/${organizationId}/snapshots?${params}`);
}

export async function compareSnapshots(beforeSnapshotId, afterSnapshotId) {
  const query = new URLSearchParams({
    before_snapshot_id: beforeSnapshotId,
    after_snapshot_id: afterSnapshotId,
  });

  return apiFetch(`/snapshots/compare?${query.toString()}`);
}
