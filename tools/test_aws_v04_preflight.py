import copy
import unittest
from unittest.mock import patch

from aws_v04_preflight import AwsReadOnly, InventoryError, inspect

ACCOUNT = "123456789012"
INSTANCE = "i-0123456789abcdef0"


class FakeAws:
    def __init__(self):
        self.calls = []
        self.data = {
            "get-caller-identity": {"Account": ACCOUNT},
            "describe-instances": {"Reservations": [{"OwnerId": ACCOUNT, "Instances": [{
                "InstanceId": INSTANCE, "ImageId": "ami-0123456789abcdef0", "InstanceType": "m6i.large",
                "Architecture": "x86_64", "State": {"Name": "running"}, "CurrentInstanceBootMode": "uefi",
                "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "required", "HttpPutResponseHopLimit": 1},
                "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0"}],
                "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-0123456789abcdef0"}}],
            }]}]},
            "describe-images": {"Images": [{"ImageId": "ami-0123456789abcdef0", "Architecture": "x86_64", "BootMode": "uefi", "TpmSupport": "v2.0", "PlatformDetails": "Linux/UNIX", "State": "available"}]},
            "describe-instance-types": {"InstanceTypes": [{"InstanceType": "m6i.large", "SupportedBootModes": ["uefi"], "NitroTpmSupport": "supported", "NitroTpmInfo": {"SupportedVersions": ["2.0"]}}]},
            "describe-security-groups": {"SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "OwnerId": ACCOUNT, "IpPermissions": []}]},
            "describe-volumes": {"Volumes": [{"VolumeId": "vol-0123456789abcdef0", "Encrypted": True, "State": "in-use", "Attachments": [{"InstanceId": INSTANCE, "State": "attached"}]}]},
        }

    def call(self, service, operation, *arguments):
        assert (service, operation) in AwsReadOnly.ALLOWED
        self.calls.append((service, operation, arguments))
        return copy.deepcopy(self.data[operation])


class PreflightTests(unittest.TestCase):
    def test_inventory_success_is_never_production_acceptance(self):
        aws = FakeAws()
        report = inspect(aws, ACCOUNT, INSTANCE)
        self.assertTrue(report["instance_prerequisites_passed"])
        self.assertEqual(report["production_acceptance"], "not_run")
        self.assertFalse(report["hardware_authority_verified"])
        self.assertFalse(report["rollback_protection_verified"])
        self.assertFalse(report["cloud_models_enabled"])
        self.assertEqual(len(aws.calls), 6)

    def test_wrong_account_stops_before_ec2(self):
        aws = FakeAws()
        with self.assertRaises(InventoryError):
            inspect(aws, "999999999999", INSTANCE)
        self.assertEqual(len(aws.calls), 1)

    def test_missing_tpm_uefi_imds_or_encryption_fails(self):
        for operation, collection, field, replacement in [
            ("describe-images", "Images", "TpmSupport", None),
            ("describe-images", "Images", "BootMode", "uefi-preferred"),
            ("describe-images", "Images", "Architecture", "arm64"),
            ("describe-instance-types", "InstanceTypes", "NitroTpmSupport", "unsupported"),
            ("describe-instance-types", "InstanceTypes", "NitroTpmInfo", {}),
            ("describe-volumes", "Volumes", "Encrypted", False),
            ("describe-volumes", "Volumes", "Attachments", []),
            ("describe-security-groups", "SecurityGroups", "IpPermissions", [{"IpProtocol": "-1"}]),
        ]:
            with self.subTest(field=field):
                aws = FakeAws()
                aws.data[operation][collection][0][field] = replacement
                self.assertFalse(inspect(aws, ACCOUNT, INSTANCE)["instance_prerequisites_passed"])
        aws = FakeAws()
        aws.data["describe-instances"]["Reservations"][0]["Instances"][0]["MetadataOptions"] = {}
        self.assertFalse(inspect(aws, ACCOUNT, INSTANCE)["instance_prerequisites_passed"])

    def test_incomplete_or_extra_inventory_is_rejected(self):
        for operation, collection in [("describe-images", "Images"), ("describe-instance-types", "InstanceTypes"), ("describe-security-groups", "SecurityGroups"), ("describe-volumes", "Volumes")]:
            for duplicate in [False, True]:
                aws = FakeAws()
                rows = aws.data[operation][collection]
                aws.data[operation][collection] = rows + rows if duplicate else []
                with self.assertRaises(InventoryError):
                    inspect(aws, ACCOUNT, INSTANCE)

    def test_write_commands_are_not_callable(self):
        with patch("subprocess.run") as runner:
            for operation in ["run-instances", "terminate-instances", "modify-instance-attribute", "create-tags"]:
                with self.assertRaises(InventoryError):
                    AwsReadOnly("personal", "us-east-1").call("ec2", operation)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
