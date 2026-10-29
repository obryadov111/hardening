import { apiFetch } from "./client";

export async function getAssets() {
  return apiFetch("/assets");
}

export async function getAssetsByOrganization(organizationId) {
  if (!organizationId) {
    return [];
  }

  return apiFetch(`/organizations/${organizationId}/assets`);
}

export async function getAssetById(assetId) {
  return apiFetch(`/assets/${assetId}`);
}

export async function getInventoryByAsset(assetId) {
  return apiFetch(`/assets/${assetId}/inventory`);
}
