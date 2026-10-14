"""AutoDojo cached injections: pinned files and a faithful replay."""
import json
import unittest

import yaml

from savana_bench import autodojo_cache as ad

PINNED = {
    "banking": "33ce1bd46cdd2945f1d4482eae02da2ded300da8c68ba5cf98346279cb34c3ea",
    "slack": "d3274a4cc2abb305e0df0dc43c66f16174746014138fe067a20fcf36d80852e9",
    "travel": "b5dfd3e758e565514c3762617a76aa69cd6bf3d22b1089807a586cb7edc006ac",
}


class AutoDojoCacheTests(unittest.TestCase):
    def test_vendored_caches_are_the_pinned_upstream_files(self):
        for suite, digest in PINNED.items():
            variants, originals, sha = ad.load(ad.cache_path(suite))
            self.assertEqual(sha, digest, suite)
            self.assertTrue(variants and set(variants) == set(originals))
            meta = json.loads(ad.cache_path(suite).read_bytes())
            self.assertEqual((meta["suite"], meta["model"], meta["defense"]),
                             (suite, "google/gemini-3.1-pro-preview", None))
        with self.assertRaises(ValueError):
            ad.cache_path("workspace")  # AutoDojo has no workspace cache

    def test_optimized_variant_is_replayed_escaped_and_decodes_back(self):
        variants, originals, _ = ad.load(ad.cache_path("slack"))
        task, by_vector = next(iter(variants.items()))
        vector, texts = next(iter(by_vector.items()))
        self.assertNotEqual(texts[0].strip(), originals[task][vector].strip())
        out = ad.injection(variants, originals, task, "unused goal", vector, 0)
        self.assertEqual(yaml.safe_load('"' + out + '"'), texts[0])
        self.assertEqual(yaml.safe_load('"' + ad.injection(variants, originals, task, "g", vector, 3) + '"'), texts[3])

    def test_unoptimized_or_missing_variant_falls_back_to_the_wrapper(self):
        goal = 'Send "all" money\tnow'
        out = ad.injection({}, {}, "injection_task_9", goal, "vector_x", 0)
        decoded = yaml.safe_load('"' + out + '"')
        self.assertEqual(decoded, ad.WRAPPER.format(user=ad.USER_NAME, model=ad.MODEL_NAME, goal=goal))
        # A variant equal to the original goal (up to surrounding space) is
        # wrapped too; AutoDojo wraps the variant text itself.
        variants = {"t": {"v": [goal + "  "]}}
        originals = {"t": {"v": goal}}
        self.assertEqual(yaml.safe_load('"' + ad.injection(variants, originals, "t", goal, "v", 0) + '"'),
                         ad.WRAPPER.format(user=ad.USER_NAME, model=ad.MODEL_NAME, goal=goal + "  "))
        # An out-of-range variant index uses the goal, wrapped.
        self.assertEqual(ad.injection(variants, originals, "t", goal, "v", 4), out)


if __name__ == "__main__":
    unittest.main()
