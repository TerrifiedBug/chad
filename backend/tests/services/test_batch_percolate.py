"""Tests for batch percolation service."""

import pytest
from unittest.mock import MagicMock


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

    def test_batch_percolate_empty_logs(self):
        """Empty logs list should return empty results."""
        from app.services.batch_percolate import batch_percolate_logs

        mock_client = MagicMock()

        result = batch_percolate_logs(mock_client, "index", [])

        assert result == {}
        mock_client.search.assert_not_called()

    def test_batch_percolate_handles_exception(self):
        """Batch percolate should return empty dict on exception."""
        from app.services.batch_percolate import batch_percolate_logs

        mock_client = MagicMock()
        mock_client.search.side_effect = Exception("OpenSearch error")

        logs = [{"message": "test"}]
        result = batch_percolate_logs(mock_client, "index", logs)

        assert result == {}
