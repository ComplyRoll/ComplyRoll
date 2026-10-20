#!/bin/sh
# ******************************************************************************
# *Title: ComplyRoll CI Gate*
# *Author: Kyle Versluis*
# *Description: Compiles, validates and gates the three VER reports (ADR 0017).*
# ******************************************************************************

# Usage: sh complyroll-gate.sh ARTIFACT...   Inputs: the CR_* variables in README.md.
# Exit 0: no system-generated record, or coverage gaps only under warn-gaps. Exit 1: a command
# refused its input, a report failed schema validation, or a gate input is wrong. Exit 3: a
# system-generated VDR-CSO-FAV record the policy fails on. The gate reads exit codes only.

# *--- Configuration ---*

# No errexit: every report is attempted, and each exit code is read below.
set -u
out=${CR_OUT:-complyroll-reports}
log=$out/diagnostics.log
policy=${CR_SYSTEM_RECORDS:-fail}

disclaimer="This gate reads ComplyRoll exit codes only. Its result is not a FedRAMP"
disclaimer="$disclaimer determination and not evidence that any KSI is met; open, overdue and"
disclaimer="$disclaimer KEV past-due records are not gated (ADR 0017)."
where="Every record is listed in historical.json in the uploaded artifact, under"
where="$where x-complyroll.detectionFailures and x-complyroll.coverage.windows, including any"
where="$where detected after the period end that vdt.json leaves out."
gap="A window closed with no verification. A coverage gap records an absence of"
gap="$gap verification, not a vulnerability in the resource."

# *--- Input Checks ---*

# SECURITY: messages here name the input, never echo it, and stop before any ComplyRoll call.
case $policy in
  fail|warn-gaps) ;;
  *) echo "error: CR_SYSTEM_RECORDS is fail or warn-gaps" >&2; exit 1 ;;
esac
[ "$#" -gt 0 ] || { echo "error: name at least one artifact" >&2; exit 1; }
for artifact in "$@"; do
  case $artifact in
    -*) echo "error: an artifact argument starts with -; prefix it with ./" >&2; exit 1 ;;
  esac
done
case $out in
  -*) echo "error: CR_OUT starts with -; prefix it with ./" >&2; exit 1 ;;
esac
missing=
[ -n "${CR_CLASS:-}" ] || missing="$missing CR_CLASS"
[ -n "${CR_PACKAGE_URI:-}" ] || missing="$missing CR_PACKAGE_URI"
[ -n "${CR_FROM:-}" ] || missing="$missing CR_FROM"
[ -n "${CR_TO:-}" ] || missing="$missing CR_TO"
[ -z "$missing" ] || { echo "error: set$missing" >&2; exit 1; }
# A refused run must never upload an earlier run's reports as its own, and the CLI's
# output_is_symlink refusal must still fire, so nothing is deleted: a used CR_OUT is refused.
if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
  echo "error: CR_OUT exists and is not empty; name a fresh directory" >&2; exit 1
fi

# One instant for every call, so the three reports and the probe share one as-of.
if [ -n "${CR_AS_OF:-}" ]; then
  as_of=${CR_AS_OF}
  echo "as-of: CR_AS_OF"
else
  as_of=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "as-of: $as_of, resolved once at start"
fi
mkdir -p "$out" || exit 1
: > "$log" || exit 1

# *--- Commands ---*

# compile KIND ARTIFACT...: artifacts first and contiguous, since the CLI reads them as one run.
compile() {
  kind=$1
  shift
  set -- "$@" --class "$CR_CLASS" --package-uri "$CR_PACKAGE_URI" --record-failed-imports
  set -- "$@" --as-of "$as_of"
  [ "$kind" = historical ] || set -- "$@" --from "$CR_FROM" --to "$CR_TO"
  [ -z "${CR_DETECTED_AT:-}" ] || set -- "$@" --detected-at "$CR_DETECTED_AT"
  [ -z "${CR_CALENDAR_TZ:-}" ] || set -- "$@" --calendar-tz "$CR_CALENDAR_TZ"
  [ -z "${CR_EVALUATIONS:-}" ] || set -- "$@" --evaluations "$CR_EVALUATIONS"
  [ -z "${CR_KEV:-}" ] || set -- "$@" --kev "$CR_KEV"
  [ -z "${CR_INVENTORY:-}" ] || set -- "$@" --inventory "$CR_INVENTORY" --record-coverage-gaps
  complyroll report "$kind" "$@" -o "$out/$kind.json" --markdown "$out/$kind.md" 2>>"$log"
}

# probe ARTIFACT...: failures only. No evaluations, catalog or inventory, so exit 3 means a
# detection process failure and nothing else (ADR 0017 Decision 6).
probe() {
  set -- "$@" --class "$CR_CLASS" --package-uri "$CR_PACKAGE_URI" --record-failed-imports
  set -- "$@" --as-of "$as_of"
  [ -z "${CR_DETECTED_AT:-}" ] || set -- "$@" --detected-at "$CR_DETECTED_AT"
  [ -z "${CR_CALENDAR_TZ:-}" ] || set -- "$@" --calendar-tz "$CR_CALENDAR_TZ"
  complyroll report historical "$@" >/dev/null 2>>"$log"
}

# *--- Compile and Validate ---*

# Each exit line is also kept for the job summary, which holds gate text only.
lines=
refused=0
system=0
for kind in vdt avi historical; do
  compile "$kind" "$@"
  rc=$?
  echo "report $kind: exit $rc"
  lines="$lines
report $kind: exit $rc"
  case $rc in
    0|3)
      [ "$rc" -eq 0 ] || system=1
      case $kind in
        vdt) schema=vulnerability-detail ;;
        avi) schema=accepted-vulnerability ;;
        historical) schema=historical-activity ;;
      esac
      complyroll validate "$out/$kind.json" --schema "$schema" >>"$log" 2>&1
      vrc=$?
      echo "validate $kind: exit $vrc"
      lines="$lines
validate $kind: exit $vrc"
      [ "$vrc" -eq 0 ] || refused=1
      ;;
    *) refused=1 ;;
  esac
done

# A report exit 3 with an inventory may be gaps, failures or both; the probe tells them apart.
found=none
if [ "$refused" -eq 0 ] && [ "$system" -eq 1 ]; then
  if [ -z "${CR_INVENTORY:-}" ]; then
    found=failure-only
  else
    probe "$@"
    prc=$?
    echo "failure probe: exit $prc"
    lines="$lines
failure probe: exit $prc"
    case $prc in
      3) found=failure ;;
      0) found=gap ;;
      *) found=probe-refused ;;
    esac
  fi
fi

# *--- Verdict ---*

# Every verdict line is fixed text: no path, event text or report text reaches it.
if [ "$refused" -eq 1 ]; then
  status=1
  verdict="Gate exit 1: a command refused its input, or a report failed validation against"
  verdict="$verdict its pinned official schema; see diagnostics.log in the uploaded artifact."
  detail=
  annotation="::error::ComplyRoll gate exit 1: a command refused its input or a report failed"
  annotation="$annotation schema validation; see diagnostics.log in the uploaded artifact."
elif [ "$found" = probe-refused ]; then
  status=1
  verdict="Gate exit 1: the failure-only compile refused its input; see diagnostics.log in"
  verdict="$verdict the uploaded artifact."
  detail=
  annotation="::error::ComplyRoll gate exit 1: the failure-only compile refused its input;"
  annotation="$annotation see diagnostics.log in the uploaded artifact."
elif [ "$found" = failure-only ]; then
  status=3
  verdict="Gate exit 3: a detection process failure was recorded (ADR 0014)."
  detail=$where
  annotation="::error::ComplyRoll gate exit 3: a detection process failure was recorded;"
  annotation="$annotation see historical.json in the uploaded artifact."
elif [ "$found" = failure ]; then
  status=3
  verdict="Gate exit 3: a detection process failure was recorded; coverage gaps may also be"
  verdict="$verdict recorded."
  detail=$where
  annotation="::error::ComplyRoll gate exit 3: a detection process failure was recorded;"
  annotation="$annotation see historical.json in the uploaded artifact."
elif [ "$found" = gap ] && [ "$policy" = fail ]; then
  status=3
  verdict="Gate exit 3: a coverage gap was recorded (ADR 0015). $gap"
  detail=$where
  annotation="::error::ComplyRoll gate exit 3: a coverage gap was recorded;"
  annotation="$annotation see historical.json in the uploaded artifact."
elif [ "$found" = gap ]; then
  status=0
  verdict="Gate exit 0: a coverage gap was recorded (ADR 0015), and warn-gaps makes it a"
  verdict="$verdict warning. $gap"
  detail=$where
  annotation="::warning::ComplyRoll gate: a coverage gap was recorded and warn-gaps makes it"
  annotation="$annotation a warning; see historical.json in the uploaded artifact."
else
  status=0
  verdict="Gate exit 0: each report compiled and validated against its pinned official"
  verdict="$verdict schema, and none holds a system-generated record."
  detail=
  annotation=
fi

echo "$verdict"
[ -z "$detail" ] || echo "$detail"
[ -z "$annotation" ] || echo "$annotation"
echo "$disclaimer"

# *--- Job Summary ---*

# SECURITY: the summary renders as Markdown, so it holds gate text only, never a report twin.
summary="${GITHUB_STEP_SUMMARY:-}"
if [ -n "$summary" ]; then
  {
    echo "## ComplyRoll gate"
    echo
    echo "$verdict"
    echo
    [ -z "$detail" ] || { echo "$detail"; echo; }
    echo '```text'
    printf '%s\n' "$lines" | sed '/^$/d'
    echo '```'
    echo
    echo "$disclaimer"
  } >>"$summary"
fi
exit "$status"
