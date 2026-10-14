#!/usr/bin/python3
"""Root-only B-profile administration; never performs a passkey ceremony."""
import argparse
import os
import subprocess


def invocation(action):
    if action in {"owner-health", "prepare-ingress"}:
        return owner_invocation(action)
    if action not in {"health", "enroll"}:
        raise ValueError("unsupported integration administration action")
    command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect",
               "--unit=savana-approvalctl.service", "--service-type=exec"]
    # Pipe output only to the invoking administrator, not the system journal.
    # The fixed unit name matches approvalctl's closed credential-directory name.
    properties = ["User=root", "Group=root", "UMask=0077", "RuntimeMaxSec=30",
                  "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes",
                  "PrivateTmp=yes", "PrivateDevices=yes", "RestrictAddressFamilies=AF_UNIX",
                  "IPAddressDeny=any", "SupplementaryGroups=savana-identity"]
    for name in ["approval-admin-v2.seed", "approvalctl-boot-v2.id", "approvald-boot-v2.id"]:
        properties.append(f"LoadCredentialEncrypted={name}:/etc/savana/credentials/approvalctl/{name}.cred")
    for property_value in properties:
        command += ["--property=" + property_value]
    command += ["--", "/usr/libexec/savana/savana-approvalctl"]
    command += ["health"] if action == "health" else ["create-enrollment", "1"]
    return command


def owner_invocation(action):
    """Unprivileged measured peer; boot IDs only, no signing keys or state."""
    if action not in {"owner-health", "prepare-ingress"}:
        raise ValueError("unsupported owner control action")
    command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect",
               "--unit=savana-ownerctl.service", "--service-type=exec"]
    properties = ["User=savana-jarvis", "Group=savana-jarvis", "UMask=0077", "RuntimeMaxSec=30",
                  "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                  "PrivateDevices=yes", "RestrictAddressFamilies=AF_UNIX", "IPAddressDeny=any",
                  "SupplementaryGroups=savana-identity", "CapabilityBoundingSet=", "LimitCORE=0"]
    for name in ["jarvis-boot-v2.id", "agentd-boot-v2.id"]:
        properties.append(f"LoadCredentialEncrypted={name}:/etc/savana/credentials/ownerctl/{name}.cred")
    command += ["--property=" + value for value in properties]
    command += ["--", "/usr/libexec/savana/savana-ownerctl",
                "health" if action == "owner-health" else "prepare-ingress"]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["health", "enroll", "owner-health", "prepare-ingress"])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("root-only integration administration required")
    # Do not retry a timeout: code creation may have committed already.
    subprocess.run(invocation(args.action), check=True, timeout=40)


if __name__ == "__main__":
    main()
