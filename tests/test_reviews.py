"""Short-lived CLI review snapshots are private, root-bound, and single-use."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from guardkit import provision, reviews


class ReviewCacheTests(unittest.TestCase):
    def test_review_is_private_outside_project_and_single_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / 'project'; project.mkdir()
            cache = base / 'private-cache'; cache.mkdir()
            plans = [{'kind': 'example', 'finding_ids': ['f1']}]
            with patch.object(provision, 'cache_dir', return_value=cache):
                review_id = reviews.create(project, plans)
                review_directory = cache / 'reviews'
                review_file = review_directory / (review_id + '.json')
                self.assertFalse((project / 'reviews').exists())
                if os.name != 'nt':
                    self.assertEqual(review_directory.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(review_file.stat().st_mode & 0o777, 0o600)
                payload = json.loads(review_file.read_text())
                self.assertEqual(payload['root'], str(project.resolve()))
                self.assertGreater(payload['expires'], 0)
                self.assertEqual(reviews.consume(project, review_id), plans)
                self.assertFalse(review_file.exists())
                with self.assertRaisesRegex(reviews.ReviewError, 'already consumed'):
                    reviews.consume(project, review_id)

    def test_expired_and_other_root_reviews_are_rejected_and_consumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project, other, cache = base / 'project', base / 'other', base / 'cache'
            project.mkdir(); other.mkdir(); cache.mkdir()
            with patch.object(provision, 'cache_dir', return_value=cache):
                review_id = reviews.create(project, [{'finding_ids': ['f1']}])
                with self.assertRaisesRegex(ValueError, 'belongs to another project'):
                    reviews.consume(other, review_id)
                self.assertFalse((cache / 'reviews' / (review_id + '.json')).exists())

                review_id = reviews.create(project, [{'finding_ids': ['f1']}])
                review_file = cache / 'reviews' / (review_id + '.json')
                payload = json.loads(review_file.read_text())
                payload['expires'] = 1
                review_file.write_text(json.dumps(payload))
                with patch.object(reviews.time, 'time', return_value=2):
                    with self.assertRaisesRegex(ValueError, 'expired'):
                        reviews.consume(project, review_id)
                self.assertFalse(review_file.exists())

    def test_invalid_review_id_is_rejected_before_cache_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(reviews, '_directory') as directory:
                with self.assertRaisesRegex(reviews.ReviewError, 'Invalid review ID'):
                    reviews.consume(Path(tmp), '../bad')
                directory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
