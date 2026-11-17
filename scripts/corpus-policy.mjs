// A release must adopt the newest eligible Hex version. Ordinary CI checks only the named release.
import semver from "semver";
import { API, assertReleaseSource, fetchJson, releaseMetadata } from "./corpus-artifact.mjs";

// Hex's published policy: https://hex.pm/docs/faq#packages.
// a version's revert window is 60 minutes; the package's initial window is 24 hours.
export const VERSION_WINDOW_MS = 60 * 60 * 1000;
export const PACKAGE_WINDOW_MS = 24 * VERSION_WINDOW_MS;
const timestamp = (value) => { const n = typeof value === "string" ? Date.parse(value) : NaN; if (!Number.isFinite(n)) throw new Error("Hex: invalid publication timestamp"); return n; };
export const stableVersion = value => typeof value === "string" && semver.valid(value) === value && semver.prerelease(value) === null && !value.includes("+");
export function adoptionDecision(source, newest) {
  if (!stableVersion(source.version) || !stableVersion(newest.version)) throw new Error("adoption requires stable versions without build metadata");
  if (source.version === newest.version) { assertCurrent(source, newest); return "same"; }
  return semver.gt(newest.version, source.version) ? "adopt" : "ahead";
}
export function newestEligible(metadata, now) {
  if (!Array.isArray(metadata.releases) || !metadata.retirements || !Number.isFinite(now)) throw new Error("Hex: invalid package release inventory");
  const packageClosed = timestamp(metadata.inserted_at) + PACKAGE_WINDOW_MS;
  const releases = metadata.releases.filter(r => {
    if (!semver.valid(r.version)) throw new Error("Hex: invalid release version");
    if (!stableVersion(r.version)) return false;
    const closed = Math.max(timestamp(r.inserted_at) + VERSION_WINDOW_MS, packageClosed);
    return !Object.hasOwn(metadata.retirements, r.version) && closed <= now;
  }).sort((a, b) => semver.rcompare(a.version, b.version));
  if (!releases.length) throw new Error("Hex: no non-retired release has closed its revert window");
  return releases[0].version;
}
export function assertCurrent(source, newest) {
  assertReleaseSource(source);
  if (!stableVersion(source.version) || !stableVersion(newest.version)) throw new Error("release requires stable versions without build metadata");
  if (source.version !== newest.version) throw new Error(`stale SOURCE: ${source.version}; newest eligible Hex release is ${newest.version}`);
  if (source.checksum !== newest.checksum) throw new Error("release SOURCE checksum differs from registry");
}
export async function eligibleRelease(now = Date.now()) {
  const metadata = await fetchJson(API);
  return releaseMetadata(newestEligible(metadata, now));
}
