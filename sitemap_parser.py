import logging

logger = logging.getLogger(__name__)


def fetch_historical_from_sitemap(base_url, source_name, category, 
                                   filter_patterns=None, max_urls=500, 
                                   provided_sitemap=None):
    logger.warning(
        "fetch_historical_from_sitemap is a stub function. "
        "Use FeedParser.parse() with feed_type='sitemap' instead."
    )
    
    # Return empty list - the actual parsing should be done via FeedParser
    return []
