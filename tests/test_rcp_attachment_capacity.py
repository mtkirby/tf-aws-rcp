import unittest

from scripts.check_rcp_attachment_capacity import PreflightError, attachment_deltas


def attachment_change(actions, before=None, after=None):
    return {
        "type": "aws_organizations_policy_attachment",
        "address": "aws_organizations_policy_attachment.this[\"policy/target\"]",
        "change": {"actions": actions, "before": before, "after": after},
    }


class AttachmentDeltasTests(unittest.TestCase):
    def test_new_and_removed_attachments_adjust_their_targets(self):
        plan = {
            "resource_changes": [
                attachment_change(["create"], after={"target_id": "ou-new"}),
                attachment_change(["delete"], before={"target_id": "ou-old"}),
            ]
        }

        self.assertEqual(attachment_deltas(plan), {"ou-new": 1, "ou-old": -1})

    def test_replacement_on_same_target_has_no_net_capacity_change(self):
        plan = {
            "resource_changes": [
                attachment_change(
                    ["delete", "create"],
                    before={"target_id": "ou-same"},
                    after={"target_id": "ou-same"},
                )
            ]
        }

        self.assertEqual(attachment_deltas(plan), {})

    def test_target_change_moves_attachment_between_targets(self):
        plan = {
            "resource_changes": [
                attachment_change(
                    ["update"],
                    before={"target_id": "ou-old"},
                    after={"target_id": "ou-new"},
                )
            ]
        }

        self.assertEqual(attachment_deltas(plan), {"ou-old": -1, "ou-new": 1})

    def test_non_attachment_changes_are_ignored(self):
        plan = {
            "resource_changes": [
                {"type": "aws_organizations_policy", "change": {"actions": ["create"]}}
            ]
        }

        self.assertEqual(attachment_deltas(plan), {})

    def test_unknown_create_target_fails_closed(self):
        plan = {"resource_changes": [attachment_change(["create"], after={})]}

        with self.assertRaises(PreflightError):
            attachment_deltas(plan)


if __name__ == "__main__":
    unittest.main()