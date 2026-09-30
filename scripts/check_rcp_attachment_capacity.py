#!/usr/bin/env python3
"""Check planned RCP attachments against AWS Organizations target limits."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_RCP_ATTACHMENTS = 5
ATTACHMENT_RESOURCE_TYPE = "aws_organizations_policy_attachment"


class PreflightError(Exception):
    """Raised when the plan or AWS response cannot be checked reliably."""


def attachment_deltas(plan: dict[str, Any]) -> dict[str, int]:
    """Return planned RCP attachment count changes keyed by target ID."""
    deltas: dict[str, int] = {}
    for resource_change in plan.get("resource_changes", []):
        if resource_change.get("type") != ATTACHMENT_RESOURCE_TYPE:
            continue

        change = resource_change.get("change", {})
        actions = change.get("actions", [])
        before = change.get("before") or {}
        after = change.get("after") or {}

        if "delete" in actions:
            target_id = before.get("target_id")
            if not target_id:
                raise PreflightError(
                    f"Cannot determine the prior target for {resource_change.get('address', 'an attachment')}"
                )
            deltas[target_id] = deltas.get(target_id, 0) - 1

        if "create" in actions:
            target_id = after.get("target_id")
            if not target_id:
                raise PreflightError(
                    f"Cannot determine the planned target for {resource_change.get('address', 'an attachment')}"
                )
            deltas[target_id] = deltas.get(target_id, 0) + 1

        if actions == ["update"] and before.get("target_id") != after.get("target_id"):
            before_target = before.get("target_id")
            after_target = after.get("target_id")
            if not before_target or not after_target:
                raise PreflightError(
                    f"Cannot determine the target change for {resource_change.get('address', 'an attachment')}"
                )
            deltas[before_target] = deltas.get(before_target, 0) - 1
            deltas[after_target] = deltas.get(after_target, 0) + 1

    return {target_id: delta for target_id, delta in deltas.items() if delta != 0}


def run_json_command(command: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "AWS_PAGER": ""},
        )
    except FileNotFoundError as error:
        raise PreflightError(f"Required command not found: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        message = error.stderr.strip() or error.stdout.strip() or str(error)
        raise PreflightError(f"Command failed ({' '.join(command)}): {message}") from error

    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PreflightError(f"Command returned invalid JSON: {' '.join(command)}") from error
    if not isinstance(value, dict):
        raise PreflightError(f"Command returned unexpected JSON: {' '.join(command)}")
    return value


def current_rcp_count(target_id: str, profile: str | None) -> int:
    command = [
        "aws",
        "organizations",
        "list-policies-for-target",
        "--target-id",
        target_id,
        "--filter",
        "RESOURCE_CONTROL_POLICY",
        "--output",
        "json",
        "--no-cli-pager",
    ]
    if profile:
        command.extend(["--profile", profile])

    response = run_json_command(command)
    policies = response.get("Policies")
    if not isinstance(policies, list):
        raise PreflightError(f"AWS response for target {target_id} has no Policies list")
    return len(policies)


def check_plan(plan_path: Path, profile: str | None) -> int:
    plan = run_json_command(["terraform", "show", "-json", str(plan_path)])
    deltas = attachment_deltas(plan)
    if not deltas:
        print("No net RCP attachment changes in the Terraform plan.")
        return 0

    failed = False
    for target_id, delta in sorted(deltas.items()):
        current_count = current_rcp_count(target_id, profile)
        projected_count = current_count + delta
        print(
            f"{target_id}: {current_count} currently attached, "
            f"{delta:+d} planned, {projected_count} projected (limit {MAX_RCP_ATTACHMENTS})"
        )
        if projected_count < 0:
            print(
                f"ERROR: planned removals exceed current RCP attachments for {target_id}; "
                "check for out-of-band changes or stale state.",
                file=sys.stderr,
            )
            failed = True
        elif projected_count > MAX_RCP_ATTACHMENTS:
            print(
                f"ERROR: target {target_id} would exceed the RCP attachment limit.",
                file=sys.stderr,
            )
            failed = True

    if failed:
        return 1
    print("RCP attachment capacity check passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="Saved Terraform plan file (created with terraform plan -out=...)")
    parser.add_argument("--profile", help="AWS CLI profile to use; defaults to the normal AWS CLI credential chain")
    args = parser.parse_args()

    if not args.plan.is_file():
        parser.error(f"plan file does not exist: {args.plan}")

    try:
        return check_plan(args.plan, args.profile)
    except PreflightError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())