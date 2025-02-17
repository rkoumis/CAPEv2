from lib.cuckoo.core.reporting.types import SearchCategories


class TestSearchCategories:
    def test_valid_values(self):
        """Test SearchCategories keys and values."""
        assert "FILE" in SearchCategories.__members__
        assert "PCAP" in SearchCategories.__members__
        assert "STATIC" in SearchCategories.__members__
        assert "URL" in SearchCategories.__members__

        assert len(SearchCategories.__members__.keys()) == 4

        assert SearchCategories.FILE.value == "file"
        assert SearchCategories.PCAP.value == "pcap"
        assert SearchCategories.STATIC.value == "static"
        assert SearchCategories.URL.value == "url"
