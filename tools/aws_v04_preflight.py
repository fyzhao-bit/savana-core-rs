#!/usr/bin/env python3
"""Read-only EC2 prerequisites, NOT a Savana startup/hardware authority.

No resource creation, user data, remote command, credential export, deployment,
or model endpoint. Missing/ambiguous AWS inventory fails closed.
"""
import argparse
import json
import os
import re
import subprocess


class InventoryError(Exception):
    pass


class AwsReadOnly:
    ALLOWED = {
        ("sts", "get-caller-identity"),
        ("ec2", "describe-instances"),
        ("ec2", "describe-images"),
        ("ec2", "describe-instance-types"),
        ("ec2", "describe-security-groups"),
        ("ec2", "describe-volumes"),
    }

    def __init__(self, profile, region):
        self.profile = profile
        self.region = region

    def call(self, service, operation, *arguments):
        if (service, operation) not in self.ALLOWED:
            raise InventoryError("operation_not_read_only")
        env = os.environ.copy()
        # Do not prompt, page output, or silently send authenticated requests to
        # an endpoint override. The chosen profile remains the credential source.
        env.update(AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off",
                   AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
        try:
            result = subprocess.run(
                ["aws", f"--profile={self.profile}", f"--region={self.region}",
                 "--output=json", "--no-cli-pager", "--cli-connect-timeout=10",
                 "--cli-read-timeout=20", service, operation, *arguments],
                capture_output=True, timeout=45, check=False, env=env,
            )
            if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
                raise InventoryError("inventory_unavailable")
            document = json.loads(result.stdout)
            if not isinstance(document, dict):
                raise InventoryError("inventory_shape_invalid")
            return document
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            # CLI stderr can contain local paths or credential-provider details.
            raise InventoryError("inventory_unavailable") from error


def one(items, field, expected):
    if not isinstance(items, list) or len(items) != 1:
        raise InventoryError("inventory_not_exact")
    item = items[0]
    if not isinstance(item, dict) or item.get(field) != expected:
        raise InventoryError("inventory_binding_mismatch")
    return item


def exact_set(items, field, expected):
    if (not isinstance(items, list) or len(items) != len(expected)
            or any(not isinstance(item, dict) for item in items)
            or {item.get(field) for item in items} != set(expected)):
        raise InventoryError("inventory_not_exact")
    return items


def inspect(aws, account, instance_id):
    if aws.call("sts", "get-caller-identity").get("Account") != account:
        raise InventoryError("account_mismatch")
    reservations = aws.call("ec2", "describe-instances", "--instance-ids", instance_id).get("Reservations")
    if not isinstance(reservations, list) or len(reservations) != 1:
        raise InventoryError("inventory_not_exact")
    reservation = reservations[0]
    if reservation.get("OwnerId") != account:
        raise InventoryError("account_mismatch")
    instance = one(reservation.get("Instances"), "InstanceId", instance_id)
    image_id = instance.get("ImageId", "")
    instance_type = instance.get("InstanceType", "")
    if not re.fullmatch(r"ami-[0-9a-f]{8,17}", image_id) or not re.fullmatch(r"[a-z0-9-]+\.[a-z0-9]+", instance_type):
        raise InventoryError("inventory_binding_mismatch")
    image = one(aws.call("ec2", "describe-images", "--image-ids", image_id).get("Images"), "ImageId", image_id)
    shape = one(aws.call("ec2", "describe-instance-types", "--instance-types", instance_type).get("InstanceTypes"), "InstanceType", instance_type)
    group_ids = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
    volume_ids = [b["Ebs"]["VolumeId"] for b in instance.get("BlockDeviceMappings", []) if "Ebs" in b]
    if (not group_ids or len(group_ids) != len(set(group_ids))
            or any(not re.fullmatch(r"sg-[0-9a-f]{8,17}", g) for g in group_ids)
            or not volume_ids or len(volume_ids) != len(set(volume_ids))
            or any(not re.fullmatch(r"vol-[0-9a-f]{8,17}", v) for v in volume_ids)):
        raise InventoryError("inventory_binding_mismatch")
    groups = exact_set(aws.call("ec2", "describe-security-groups", "--group-ids", *group_ids).get("SecurityGroups"), "GroupId", group_ids)
    volumes = exact_set(aws.call("ec2", "describe-volumes", "--volume-ids", *volume_ids).get("Volumes"), "VolumeId", volume_ids)
    metadata = instance.get("MetadataOptions", {})
    checks = {
        "instance_running": instance.get("State", {}).get("Name") == "running",
        "linux_image": image.get("PlatformDetails") == "Linux/UNIX" and image.get("State") == "available",
        "architecture_matches": instance.get("Architecture") in ("arm64", "x86_64") and image.get("Architecture") == instance.get("Architecture"),
        "uefi_boot": instance.get("CurrentInstanceBootMode") == "uefi" and image.get("BootMode") == "uefi" and "uefi" in shape.get("SupportedBootModes", []),
        "nitrotpm_configured": image.get("TpmSupport") == "v2.0" and shape.get("NitroTpmSupport") == "supported" and "2.0" in shape.get("NitroTpmInfo", {}).get("SupportedVersions", []),
        "imdsv2_required": metadata.get("HttpEndpoint") == "enabled" and metadata.get("HttpTokens") == "required" and metadata.get("HttpPutResponseHopLimit") == 1,
        # This acceptance profile uses SSM/local port forwarding, never a public
        # web approval endpoint. An existing inbound SSH rule is a failed check,
        # not permission to delete or change it.
        "no_inbound_network_rules": all(g.get("IpPermissions") == [] and g.get("OwnerId") == account for g in groups),
        "all_ebs_encrypted": all(v.get("Encrypted") is True and v.get("State") == "in-use" and any(a.get("InstanceId") == instance_id and a.get("State") == "attached" for a in v.get("Attachments", [])) for v in volumes),
    }
    return {"schema": 1, "checks": checks,
            "instance_prerequisites_passed": all(checks.values()),
            "production_acceptance": "not_run",
            "hardware_authority_verified": False,
            "rollback_protection_verified": False,
            "cloud_models_enabled": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--account", required=True, help="expected 12-digit AWS account ID")
    parser.add_argument("--instance-id", required=True)
    args = parser.parse_args()
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+", args.profile)
            or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", args.region)
            or not re.fullmatch(r"[0-9]{12}", args.account)
            or not re.fullmatch(r"i-[0-9a-f]{8,17}", args.instance_id)):
        parser.error("invalid explicit AWS target")
    try:
        report = inspect(AwsReadOnly(args.profile, args.region), args.account, args.instance_id)
    except (InventoryError, KeyError, TypeError, AttributeError):
        print(json.dumps({"schema": 1, "error": "inventory_unavailable_or_mismatched", "production_acceptance": "not_run"}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["instance_prerequisites_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
