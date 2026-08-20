from __future__ import annotations

import unittest

from complyroll.policy import RuleSourceManifest, load_bundled_rule_source_manifest


class RuleSourceManifestTests(unittest.TestCase):
    def test_bundled_manifest_is_pinned_and_valid(self) -> None:
        manifest = load_bundled_rule_source_manifest()
        self.assertEqual(manifest.repository, "https://github.com/FedRAMP/rules")
        self.assertEqual(manifest.commit, "58efbf3d898496dd4a3a419eba78e458bbad5cb6")
        self.assertEqual(manifest.dataset_version, "2026.07.14.01")
        self.assertEqual(len(manifest.dataset_sha256), 64)
        self.assertEqual(len(manifest.schema_sha256), 64)

    def test_manifest_rejects_symbolic_git_reference(self) -> None:
        value = load_bundled_rule_source_manifest().to_dict()
        value["commit"] = "main"
        with self.assertRaisesRegex(ValueError, "full 40-character Git commit"):
            RuleSourceManifest.from_dict(value)


if __name__ == "__main__":
    unittest.main()
