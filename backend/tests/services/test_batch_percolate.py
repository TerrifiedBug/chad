"""Tests for batch percolation service."""

from unittest.mock import MagicMock

import pytest


class TestBatchPercolate:
    """Tests for batch percolation."""

    def test_batch_percolate_single_opensearch_call(self):
        """Batch percolate should make one OpenSearch call for multiple logs."""
        from app.services.batch_percolate import batch_percolate_logs

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"rule_id": "rule-1"}, "fields": {"_percolator_document_slot": [0]}},
                    {"_source": {"rule_id": "rule-2"}, "fields": {"_percolator_document_slot": [1]}},
                ]
            }
        }

        logs = [{"message": "log1"}, {"message": "log2"}, {"message": "log3"}]
        result = batch_percolate_logs(mock_client, "percolator-index", logs)

        # Should make exactly ONE call
        assert mock_client.search.call_count == 1

        # Should return matches indexed by log position
        assert 0 in result  # log1 matched rule-1
        assert 1 in result  # log2 matched rule-2
        assert 2 not in result  # log3 no matches

    def test_batch_percolate_one_rule_matching_multiple_logs(self):
        """A single rule hit can carry multiple document slots; each maps to its log."""
        from app.services.batch_percolate import batch_percolate_logs

        mock_client = MagicMock()
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"rule_id": "rule-1"}, "fields": {"_percolator_document_slot": [0, 2]}},
                ]
            }
        }

        logs = [{"m": "a"}, {"m": "b"}, {"m": "c"}]
        result = batch_percolate_logs(mock_client, "idx", logs)

        assert result[0][0]["rule_id"] == "rule-1"
        assert result[2][0]["rule_id"] == "rule-1"
        assert 1 not in result

    def test_batch_percolate_empty_logs(self):
        """Empty logs list should return empty results."""
        from app.services.batch_percolate import batch_percolate_logs

        mock_client = MagicMock()

        result = batch_percolate_logs(mock_client, "index", [])

        assert result == {}
        mock_client.search.assert_not_called()

    def test_batch_percolate_raises_on_exception(self):
        """Batch percolate must PROPAGATE OpenSearch errors, not swallow them.

        Returning {} on failure would look identical to "no rules matched", so the
        worker would acknowledge and drop the batch — silently losing detections
        under cluster pressure. Raising lets the worker leave the batch
        unacknowledged for retry/dead-lettering.
        """
        from app.services.batch_percolate import batch_percolate_logs

        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("OpenSearch error")

        logs = [{"message": "test"}]
        with pytest.raises(Exception, match="OpenSearch error"):
            batch_percolate_logs(mock_client, "index", logs)
