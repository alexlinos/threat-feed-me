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

# Build the tools image if absent. It layers numpy/lightgbm onto the app image;
# rebuild it whenever the app image moves so the feature contract stays in step.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[predictor] building $IMAGE from $APP_IMAGE ..."
  docker build -f "$HERE/Dockerfile.predictor" --build-arg "APP_IMAGE=$APP_IMAGE" \
    -t "$IMAGE" "$HERE"
fi

run() {  # run <module-and-args...>
  docker run --rm --memory="$MEM" --cpus=2 \
    -v "$VOLUME":/app/data \
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
