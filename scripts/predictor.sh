#!/usr/bin/env bash
# Offline recurrence-predictor runner (train + predict pass).
#
# Runs the OFFLINE predictor jobs in a throwaway tools container against the
# live data volume, so the serving image stays dark. Safe to cron: predict_pass
# writes predictive_score into indicator metadata, which the scorer only
# consumes when predictor.enabled is true — so this is inert until you flip that
# switch, and never blocks the app (WAL + chunked writes + a memory cap).
#
# Usage:
#   scripts/predictor.sh train     # retrain the model from the churn log
#   scripts/predictor.sh predict   # score live IPs -> metadata.predictive_score
#   scripts/predictor.sh both      # train then predict (default)
#
# Env overrides:
#   TFM_VOLUME     data volume name           (default: threatfeedme-data)
#   TFM_IMAGE      tools image tag            (default: threat-feed-me-predictor:latest)
#   TFM_APP_IMAGE  base app image for build   (default: alexlinos/threat-feed-me:latest)
#   TFM_MODEL      model path inside /app     (default: data/predictor_model.txt)
#   TFM_MEM        container memory cap       (default: 3g)
set -euo pipefail

CMD="${1:-both}"
VOLUME="${TFM_VOLUME:-threatfeedme-data}"
IMAGE="${TFM_IMAGE:-threat-feed-me-predictor:latest}"
APP_IMAGE="${TFM_APP_IMAGE:-alexlinos/threat-feed-me:latest}"
MODEL="${TFM_MODEL:-data/predictor_model.txt}"
MEM="${TFM_MEM:-3g}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Build the tools image when it is absent OR when the app image has moved
# since it was built. It layers numpy/lightgbm onto the app image, so it
# carries that image's code AND config.yaml; a stale one trains/scores with
# yesterday's feature contract and exclusions (a new churn_log_exclude entry
# never reached training until the old image was deleted by hand). The build
# is stamped with the app image id it came from, and rebuilt on mismatch.
APP_ID="$(docker image inspect -f '{{.Id}}' "$APP_IMAGE" 2>/dev/null || true)"
BUILT_FROM="$(docker image inspect -f '{{index .Config.Labels "tfm.app_image_id"}}' "$IMAGE" 2>/dev/null || true)"
if [ -z "$BUILT_FROM" ] || [ "$BUILT_FROM" != "$APP_ID" ]; then
  echo "[predictor] building $IMAGE from $APP_IMAGE (${APP_ID:-unknown}) ..."
  docker build -f "$HERE/Dockerfile.predictor" --build-arg "APP_IMAGE=$APP_IMAGE" \
    --label "tfm.app_image_id=$APP_ID" -t "$IMAGE" "$HERE"
fi

# The config the APP serves with, not the one baked into the image: an
# operator who mounts ./config.yaml into the app container (the compose
# file's optional mount) edits churn_log_exclude and the predictor block
# there, and training on the image's copy reintroduces the train/serve skew
# v2.4.18 closed. TFM_CONFIG overrides; default is the repo's config.yaml.
CFG="${TFM_CONFIG:-$HERE/config.yaml}"
CFG_MOUNT=()
if [ -f "$CFG" ]; then
  CFG_MOUNT=(-v "$CFG":/app/config.yaml:ro)
else
  echo "[predictor] no config at $CFG; using the image's config.yaml" >&2
fi

run() {  # run <module-and-args...>
  docker run --rm --memory="$MEM" --cpus=2 \
    -v "$VOLUME":/app/data \
    "${CFG_MOUNT[@]}" \
    -e THREATFEED_DB=/app/data/threatfeedme.db \
    -e THREATFEED_CONFIG=/app/config.yaml \
    "$IMAGE" python -m "$@"
}

do_train()   { echo "[predictor] train  -> $MODEL"; run threatfeedme.train_predictor "$MODEL"; }
do_predict() { echo "[predictor] predict-> metadata.predictive_score"; run threatfeedme.predict_pass "$MODEL"; }

case "$CMD" in
  train)   do_train ;;
  predict) do_predict ;;
  both)    do_train && do_predict ;;
  *) echo "usage: $0 {train|predict|both}" >&2; exit 64 ;;
esac
