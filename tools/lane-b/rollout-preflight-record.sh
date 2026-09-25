#!/usr/bin/env bash
# rollout-preflight-record.sh <pod> <volumesnapshot-name> <out-dir>
#
# The rollback target for ONE validator, recorded BEFORE the Stage 1 image is
# set on it (docs/operations/stage1-rollout-runbook.md section 4.1). Writes
# <out-dir>/<pod>.preflight. tools/lane-b/rollout-preflight.py decides from the
# records; this script only reads.
#
# Every field is read and validated before anything is written, and the record
# is written atomically. Any failure exits non-zero and leaves NO record.
#
# Why each field matters:
#   old_image_id     the exact digest the pod pulled. The manifests ship a
#                    mutable tag, so "the old tag" may no longer be the old
#                    binary. A rollback starts THIS digest or nothing.
#   pvc / pv         the volume the snapshot must come from.
#   pv_reclaim       Retain, so replacing the claim during a restore cannot
#                    delete the post-upgrade volume (evidence) with it.
#   snapshot_*       a snapshot of THIS claim that is readyToUse, and its
#                    immutable handle in the storage backend. A name alone can
#                    be deleted and recreated.
#   stage1_opened    "no", proven from the logs: the Stage 1 binary logs its
#                    application journal format when it opens a database, and
#                    0.2.0 never does. A snapshot taken after Stage 1 opened
#                    the volume is not a rollback target: 0.2.0 must never open
#                    a volume Stage 1 has touched (runbook section 0.2).
set -euo pipefail
[[ $# -eq 3 ]] || { echo "usage: rollout-preflight-record.sh <pod> <volumesnapshot> <out-dir>" >&2; exit 2; }
POD=$1 SNAP=$2 OUT=$3 NS=${NS:-sumchain}
fail() { echo "FAIL [$POD]: $*; no preflight record written" >&2; exit 1; }
for c in kubectl grep; do
  command -v "$c" >/dev/null || fail "required command '$c' not found"
done
k() { kubectl -n "$NS" "$@"; }
jp() { k get "$1" "$2" -o "jsonpath=$3"; }

uid=$(jp pod "$POD" '{.metadata.uid}') || fail "reading the pod failed"
[[ -n $uid ]] || fail "the pod has no uid"

img=$(jp pod "$POD" '{.status.containerStatuses[0].imageID}') || fail "reading the pod's imageID failed"
[[ $img =~ @sha256:[0-9a-f]{64}$ ]] || fail "old_image_id '$img' is not pinned by digest"

pvc=$(jp pod "$POD" '{.spec.volumes[?(@.persistentVolumeClaim)].persistentVolumeClaim.claimName}') \
  || fail "reading the pod's volume claim failed"
[[ -n $pvc && $pvc != *" "* ]] || fail "expected exactly one PersistentVolumeClaim on the pod, got '$pvc'"
pv=$(jp pvc "$pvc" '{.spec.volumeName}') || fail "reading claim $pvc failed"
[[ -n $pv ]] || fail "claim $pvc is not bound to a volume"
reclaim=$(kubectl get pv "$pv" -o 'jsonpath={.spec.persistentVolumeReclaimPolicy}') \
  || fail "reading volume $pv failed"
[[ $reclaim == Retain ]] || fail "volume $pv reclaim policy is '$reclaim', not Retain"

src=$(jp volumesnapshot "$SNAP" '{.spec.source.persistentVolumeClaimName}') \
  || fail "reading VolumeSnapshot $SNAP failed"
[[ $src == "$pvc" ]] || fail "VolumeSnapshot $SNAP is of claim '$src', not this pod's claim $pvc"
ready=$(jp volumesnapshot "$SNAP" '{.status.readyToUse}') || fail "reading $SNAP status failed"
[[ $ready == true ]] || fail "VolumeSnapshot $SNAP is not readyToUse (got '$ready')"
created=$(jp volumesnapshot "$SNAP" '{.status.creationTime}') || fail "reading $SNAP creationTime failed"
[[ -n $created ]] || fail "VolumeSnapshot $SNAP has no creationTime"
size=$(jp volumesnapshot "$SNAP" '{.status.restoreSize}') || fail "reading $SNAP restoreSize failed"
[[ -n $size ]] || fail "VolumeSnapshot $SNAP has no restoreSize"
content=$(jp volumesnapshot "$SNAP" '{.status.boundVolumeSnapshotContentName}') \
  || fail "reading $SNAP content binding failed"
[[ -n $content ]] || fail "VolumeSnapshot $SNAP is bound to no content"
handle=$(kubectl get volumesnapshotcontent "$content" -o 'jsonpath={.status.snapshotHandle}') \
  || fail "reading VolumeSnapshotContent $content failed"
[[ -n $handle ]] || fail "VolumeSnapshotContent $content carries no snapshotHandle"

# Both the current and the previous container: a Stage 1 start that crashed
# and was replaced by the old image again still touched the volume.
logs=$(k logs "$POD" 2>/dev/null) || fail "reading the pod's log failed"
prev=$(k logs "$POD" --previous 2>/dev/null) || prev=""
if grep -q 'Application journal format' <<<"$logs$prev"; then
  fail "the Stage 1 binary has already opened this volume; this snapshot is not a rollback target"
fi

mkdir -p "$OUT"
tmp=$(mktemp "$OUT/.$POD.preflight.XXXXXX")
{
echo "pod:               $POD"
echo "pod_uid:           $uid"
echo "old_image_id:      $img"
echo "pvc:               $pvc"
echo "pv:                $pv"
echo "pv_reclaim:        $reclaim"
echo "snapshot_name:     $SNAP"
echo "snapshot_source:   $src"
echo "snapshot_ready:    $ready"
echo "snapshot_created:  $created"
echo "snapshot_size:     $size"
echo "snapshot_handle:   $handle"
echo "stage1_opened:     no"
} > "$tmp"
mv "$tmp" "$OUT/$POD.preflight"
echo "recorded $OUT/$POD.preflight" >&2
