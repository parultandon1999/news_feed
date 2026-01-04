import mysql.connector
import logging
import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_all_sources():
    """Return all data sources to be configured"""
    
    sources = []
    
    # ========================================================================
    # NEWS SOURCES - RSS FEEDS
    # ========================================================================
    news_rss_sources = [
        ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews'),
        ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/'),
        ('Dark Reading', 'https://www.darkreading.com/rss_simple.asp'),
        ('SecurityWeek', 'https://feeds.feedburner.com/Securityweek'),
        ('SC Media', 'https://www.scmagazine.com/feed/'),
        ('Threatpost', 'https://threatpost.com/feed/'),
        ('Infosecurity Magazine', 'https://www.infosecurity-magazine.com/rss/news/'),
        ('Krebs on Security', 'https://krebsonsecurity.com/feed/'),
        ('The Record', 'https://therecord.media/feed'),
        ('Help Net Security', 'https://www.helpnetsecurity.com/feed/'),
        ('CyberScoop', 'https://www.cyberscoop.com/feed/'),
        ('BankInfoSecurity', 'https://www.bankinfosecurity.com/rss-feeds'),
        ('IT Security Guru', 'https://www.itsecurityguru.org/feed/'),
        ('Ars Technica Security', 'https://feeds.arstechnica.com/arstechnica/index'),
        ('Packet Storm', 'https://packetstormsecurity.com/feeds/'),
        ('Wired Security', 'https://www.wired.com/feed/category/security/latest/rss'),
        ('HackerNoon Cybersecurity', 'https://hackernoon.com/tagged/cybersecurity/feed'),
    ]
    
    for name, url in news_rss_sources:
        sources.append({
            'source_name': name,
            'feed_url': url,
            'feed_type': 'rss',
            'category': 'news'
        })
    
    # ========================================================================
    # NEWS SOURCES - SITEMAPS
    # ========================================================================
    
    # The Hacker News Sitemaps (20 pages)
    for i in range(1, 21):
        sources.append({
            'source_name': f'The Hacker News Sitemap {i}',
            'feed_url': f'https://thehackernews.com/sitemap.xml?page={i}',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # BleepingComputer Sitemap
    sources.append({
        'source_name': 'BleepingComputer Sitemap',
        'feed_url': 'https://www.bleepingcomputer.com/sitemaps/news1.txt.gz',
        'feed_type': 'sitemap',
        'category': 'news'
    })
    
    # SecurityWeek Sitemaps (33 pages)
    for i in range(1, 34):
        sources.append({
            'source_name': f'SecurityWeek Sitemap {i}',
            'feed_url': f'https://www.securityweek.com/post-sitemap{i}.xml' if i > 1 else 'https://www.securityweek.com/post-sitemap.xml',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # Help Net Security Sitemaps (57 pages)
    for i in range(1, 58):
        sources.append({
            'source_name': f'Help Net Security Sitemap {i}',
            'feed_url': f'https://www.helpnetsecurity.com/post-sitemap{i}.xml' if i > 1 else 'https://www.helpnetsecurity.com/post-sitemap.xml',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # Infosecurity Magazine Sitemaps
    infosec_sitemaps = [1, 15, 18, 19, 20, 21, 23, 24, 25, 26, 27, 30, 33, 39, 40, 42, 43, 44]
    for i in infosec_sitemaps:
        sources.append({
            'source_name': f'Infosecurity Magazine Sitemap {i}' if i > 1 else 'Infosecurity Magazine Sitemap',
            'feed_url': f'https://www.infosecurity-magazine.com/sitemap-{i}.xml' if i > 1 else 'https://www.infosecurity-magazine.com/sitemap.xml',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # Krebs on Security Sitemaps
    for i in range(1, 3):
        sources.append({
            'source_name': f'Krebs on Security Sitemap {i}',
            'feed_url': f'https://krebsonsecurity.com/wp-sitemap-posts-post-{i}.xml',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # Schneier on Security Sitemaps
    for i in range(1, 11):
        sources.append({
            'source_name': f'Schneier on Security Sitemap {i}',
            'feed_url': f'https://www.schneier.com/post-sitemap{i}.xml' if i > 1 else 'https://www.schneier.com/post-sitemap.xml',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # HackRead Sitemaps
    for i in range(1, 12):
        sources.append({
            'source_name': f'HackRead Sitemap {i}',
            'feed_url': f'https://hackread.com/post-sitemap{i}.xml' if i > 1 else 'https://hackread.com/post-sitemap.xml',
            'feed_type': 'sitemap',
            'category': 'news'
        })
    
    # ========================================================================
    # CERT / ADVISORY SOURCES
    # ========================================================================
    cert_sources = [
        # Government CERT
        ('CERT-EU', 'https://cert.europa.eu/publications/security-advisories-rss', 'rss'),
        ('UK NCSC', 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', 'rss'),
        ('CISA Alerts', 'https://www.cisa.gov/uscert/ncas/alerts.xml', 'xml'),
        ('US-CERT Alerts', 'https://www.us-cert.gov/ncas/alerts.xml', 'xml'),
        ('US-CERT Bulletins', 'https://www.us-cert.gov/ncas/bulletins.xml', 'xml'),
        ('US-CERT Current Activity', 'https://www.us-cert.gov/ncas/current-activity.xml', 'xml'),
        ('Canadian Centre for Cyber Security', 'https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en', 'atom'),
        
        # Vendor Security Blogs
        ('Qualys Security Alerts', 'https://blog.qualys.com/feed', 'rss'),
        ('CrowdStrike Blog', 'https://www.crowdstrike.com/blog/feed/', 'rss'),
        ('Microsoft Security Blog', 'https://www.microsoft.com/en-us/security/blog/feed/', 'rss'),
        ('Google Security Blog', 'https://security.googleblog.com/feeds/posts/default', 'rss'),
        ('FortiGuard Labs', 'https://www.fortiguard.com/rss/ir.xml', 'rss'),
        ('Check Point Research', 'https://research.checkpoint.com/feed/', 'rss'),
        ('Palo Alto', 'https://security.paloaltonetworks.com/rss.xml', 'rss'),
        ('Palo Alto Unit 42', 'https://unit42.paloaltonetworks.com/feed/', 'rss'),
        ('Cisco Talos Intelligence', 'https://blog.talosintelligence.com/feeds/posts/default', 'rss'),
    ]
    
    for name, url, feed_type in cert_sources:
        sources.append({
            'source_name': name,
            'feed_url': url,
            'feed_type': feed_type,
            'category': 'cert'
        })
    
    # ========================================================================
    # CERT-IN / INDIAN GOVERNMENT SOURCES
    # ========================================================================
    cert_in_sources = [
        ('CERT-In', 'https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST', 'html'),
        ('RBI Directions', 'https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx', 'html'),
        ('IRDAI', 'https://irdai.gov.in/department/it', 'html'),
    ]
    
    for name, url, feed_type in cert_in_sources:
        sources.append({
            'source_name': name,
            'feed_url': url,
            'feed_type': feed_type,
            'category': 'cert-in'
        })
    
    # ========================================================================
    # RANSOMWARE SOURCES
    # ========================================================================
    ransomware_sources = [
        ('Ransomware.live', 'https://www.ransomware.live/sitemap.xml', 'sitemap'),
    ]
    
    for name, url, feed_type in ransomware_sources:
        sources.append({
            'source_name': name,
            'feed_url': url,
            'feed_type': feed_type,
            'category': 'ransomware'
        })
    
    return sources


def initialize_sources():
    """Initialize all data sources in the database"""
    try:
        conn = mysql.connector.connect(**config.MYSQL_CONFIG)
        cursor = conn.cursor()
        
        logger.info("="*80)
        logger.info("INITIALIZING DATA SOURCES")
        logger.info("="*80)
        
        sources = get_all_sources()
        
        added = 0
        updated = 0
        errors = 0
        
        for source in sources:
            try:
                # Check if source already exists
                cursor.execute("""
                    SELECT id FROM data_sources 
                    WHERE source_name = %s AND feed_url = %s
                """, (source['source_name'], source['feed_url']))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing source
                    cursor.execute("""
                        UPDATE data_sources 
                        SET feed_type = %s, category = %s, enabled = TRUE
                        WHERE source_name = %s AND feed_url = %s
                    """, (source['feed_type'], source['category'], 
                          source['source_name'], source['feed_url']))
                    updated += 1
                else:
                    # Insert new source
                    cursor.execute("""
                        INSERT INTO data_sources 
                        (source_name, feed_url, feed_type, category, enabled)
                        VALUES (%s, %s, %s, %s, TRUE)
                    """, (source['source_name'], source['feed_url'], 
                          source['feed_type'], source['category']))
                    added += 1
                    logger.info(f"✓ Added: {source['source_name']}")
                
            except Exception as e:
                errors += 1
                logger.error(f"✗ Error with {source['source_name']}: {e}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("="*80)
        logger.info(f"INITIALIZATION COMPLETE")
        logger.info(f"  Added: {added} new sources")
        logger.info(f"  Updated: {updated} existing sources")
        logger.info(f"  Errors: {errors}")
        logger.info(f"  Total: {added + updated} sources configured")
        logger.info("="*80)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize sources: {e}")
        return False


if __name__ == "__main__":
    initialize_sources()
