import hashlib
import json
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, Any, List

import config

logger = logging.getLogger(__name__)

# Try importing mysql.connector, fall back to pymysql
try:
    import mysql.connector
    from mysql.connector import Error
    from mysql.connector.cursor import MySQLCursorDict
    MYSQL_LIBRARY = 'mysql.connector'
    mysql_connector_module = mysql.connector
except ImportError:
    try:
        import pymysql
        import pymysql.cursors  # Needed for DictCursor
        MYSQL_LIBRARY = 'pymysql'
        mysql_connector_module = pymysql
        Error = Exception
        MySQLCursorDict = None
    except ImportError:
        logger.error("=" * 80)
        logger.error("CRITICAL: MySQL connector not found!")
        logger.error("=" * 80)
        logger.error("MySQL is REQUIRED for this application.")
        logger.error("Please install one of:")
        logger.error("  pip install mysql-connector-python")
        logger.error("  OR")
        logger.error("  pip install pymysql")
        logger.error("=" * 80)
        sys.exit(1)


class Database:
    def __init__(self):
        self.mysql_config = config.MYSQL_CONFIG.copy()
        self._connection_pool = None
        self._pool_initialized = False
        
        try:
            test_conn = self.get_connection()
            test_conn.close()
            logger.info(f"✓ MySQL connection successful using {MYSQL_LIBRARY}")
        except Exception as e:
            logger.error("=" * 80)
            logger.error("CRITICAL: Cannot connect to MySQL database!")
            logger.error("=" * 80)
            logger.error(f"Error: {e}")
            logger.error("")
            logger.error("Please verify:")
            logger.error(f"  1. MySQL is running on {self.mysql_config['host']}:{self.mysql_config['port']}")
            logger.error(f"  2. Database '{self.mysql_config['database']}' exists")
            logger.error(f"  3. User '{self.mysql_config['user']}' has access")
            logger.error("  4. Password is correct")
            logger.error("")
            logger.error("Run the SQL setup commands from COPY_PASTE_SETUP.md first!")
            logger.error("=" * 80)
            raise RuntimeError(f"MySQL connection failed: {e}") from e
        
        self.init_database()

    def get_connection(self):
        """Get MySQL database connection - use connection pooling to prevent too many connections"""
        try:
            if MYSQL_LIBRARY == 'mysql.connector':
                pool_name = 'cyberfeed_pool'
                try:
                    conn = mysql_connector_module.connect(pool_name=pool_name)
                except (mysql_connector_module.Error, AttributeError, TypeError):
                    try:
                        pool_config = self.mysql_config.copy()
                        pool_config.update({
                            'pool_name': pool_name,
                            'pool_size': 10,
                            'pool_reset_session': True
                        })
                        # Initialize pool
                        mysql_connector_module.connect(**pool_config).close()
                        conn = mysql_connector_module.connect(pool_name=pool_name)
                    except Exception:
                        conn = mysql_connector_module.connect(**self.mysql_config)
            else:
                conn = mysql_connector_module.connect(
                    host=self.mysql_config['host'],
                    port=self.mysql_config['port'],
                    user=self.mysql_config['user'],
                    password=self.mysql_config['password'],
                    database=self.mysql_config['database'],
                    charset=self.mysql_config.get('charset', 'utf8mb4'),
                    connect_timeout=5,
                    max_allowed_packet=16777216
                )
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to MySQL: {e}")
            raise

    def get_cursor(self, conn):
        try:
            if MYSQL_LIBRARY == 'mysql.connector':
                return conn.cursor(dictionary=True, buffered=True)
            else:
                return conn.cursor(pymysql.cursors.DictCursor)
        except Exception:
            return conn.cursor()

    def _execute_fetchall(self, cursor):
        rows = cursor.fetchall()
        if rows and isinstance(rows[0], dict):
            return rows
        
        result = []
        for row in rows:
            if isinstance(row, dict):
                result.append(row)
            elif hasattr(row, 'keys'):
                result.append(dict(row))
            else:
                logger.warning(f"Unexpected row type: {type(row)}")
                result.append(dict(row))
        return result

    def _execute_fetchone(self, cursor):
        """Convert fetchone result to dict"""
        row = cursor.fetchone()
        if row:
            if isinstance(row, dict):
                return row
            elif hasattr(row, 'keys'):
                return dict(row)
            else:
                logger.warning(f"Unexpected row type: {type(row)}")
                return dict(row)
        return None

    def _get_param_placeholder(self):
        """Get MySQL parameter placeholder"""
        return "%s"

    def init_database(self):
        """Initialize MySQL database schema"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        try:
            self._init_mysql_schema(conn, cursor)
            conn.commit()
            logger.info("✓ Database schema initialized/verified")
            logger.info("✓ Enhanced NVD features active (CWE, CVSS v2/v3/v4, CPE mapping, change tracking)")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error initializing database schema: {e}", exc_info=True)
            raise
        finally:
            cursor.close()
            conn.close()

    def _init_mysql_schema(self, conn, cursor):
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intelligence_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                hash_id VARCHAR(255) UNIQUE NOT NULL,
                category VARCHAR(50) NOT NULL,
                title TEXT NOT NULL,
                description LONGTEXT,
                meta_description TEXT,
                image_url TEXT,
                source VARCHAR(255) NOT NULL,
                source_url TEXT,
                published_date VARCHAR(50),
                severity VARCHAR(20),
                cve_id VARCHAR(50),
                tags TEXT,
                raw_data LONGTEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                cwe_id VARCHAR(50) DEFAULT NULL COMMENT 'CWE ID',
                cwe_name VARCHAR(255) DEFAULT NULL COMMENT 'CWE name',
                cvss_v2_score DECIMAL(3,1) DEFAULT NULL COMMENT 'CVSS v2 score',
                cvss_v3_score DECIMAL(3,1) DEFAULT NULL COMMENT 'CVSS v3.1 score',
                cvss_v4_score DECIMAL(3,1) DEFAULT NULL COMMENT 'CVSS v4.0 score',
                cvss_vector VARCHAR(255) DEFAULT NULL COMMENT 'CVSS vector',
                cve_status VARCHAR(50) DEFAULT NULL COMMENT 'CVE status',
                last_modified_date VARCHAR(50) DEFAULT NULL COMMENT 'Last modified',
                references_json LONGTEXT DEFAULT NULL COMMENT 'References JSON',
                affected_products_json LONGTEXT DEFAULT NULL COMMENT 'Products JSON',
                exploitability_score DECIMAL(3,1) DEFAULT NULL COMMENT 'Exploitability',
                impact_score DECIMAL(3,1) DEFAULT NULL COMMENT 'Impact score',
                INDEX idx_category (category),
                INDEX idx_hash_id (hash_id),
                INDEX idx_published_date (published_date),
                INDEX idx_cve_id (cve_id),
                INDEX idx_created_at (created_at),
                INDEX idx_updated_at (updated_at),
                INDEX idx_source (source),
                INDEX idx_severity (severity),
                INDEX idx_category_created (category, created_at DESC),
                INDEX idx_category_severity (category, severity),
                INDEX idx_source_category (source, category),
                INDEX idx_cve_severity (cve_id, severity),
                INDEX idx_cwe_id (cwe_id),
                INDEX idx_cvss_v3_score (cvss_v3_score),
                INDEX idx_cve_status (cve_status),
                INDEX idx_last_modified_date (last_modified_date),
                INDEX idx_category_cvss (category, cvss_v3_score),
                FULLTEXT idx_fts (title, description, tags)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fetch_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                source_name VARCHAR(255) NOT NULL,
                last_fetch_date TIMESTAMP NOT NULL,
                fetch_type VARCHAR(50) NOT NULL,
                last_item_date TIMESTAMP NULL,
                items_fetched INT DEFAULT 0,
                items_inserted INT DEFAULT 0,
                items_updated INT DEFAULT 0,
                fetch_duration_seconds DECIMAL(10,2) DEFAULT 0,
                error_message TEXT NULL,
                UNIQUE KEY unique_source_type (source_name, fetch_type),
                INDEX idx_source_name (source_name),
                INDEX idx_fetch_type (fetch_type),
                INDEX idx_last_fetch_date (last_fetch_date),
                INDEX idx_source_fetch_date (source_name, last_fetch_date DESC)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                setting_key VARCHAR(255) UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_setting_key (setting_key)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS source_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                source_name VARCHAR(255) UNIQUE NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                category VARCHAR(50),
                fetch_interval_minutes INT DEFAULT 30,
                last_successful_fetch TIMESTAMP NULL,
                custom_name VARCHAR(255) NULL,
                custom_url TEXT NULL,
                custom_type VARCHAR(50) NULL,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_source_name (source_name),
                INDEX idx_enabled (enabled),
                INDEX idx_category (category),
                INDEX idx_enabled_category (enabled, category)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS custom_feeds (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                url TEXT NOT NULL,
                category VARCHAR(50) NOT NULL,
                feed_type VARCHAR(50) NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                last_fetch TIMESTAMP NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_category (category),
                INDEX idx_feed_type (feed_type),
                INDEX idx_enabled (enabled),
                INDEX idx_category_enabled (category, enabled)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS advisories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                topic TEXT NOT NULL,
                sent_date DATE NOT NULL,
                sent_by VARCHAR(255) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_sent_date (sent_date DESC),
                INDEX idx_sent_by (sent_by),
                INDEX idx_created_at (created_at DESC)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS advisory_clients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                advisory_id INT NOT NULL,
                client_id INT NOT NULL,
                sent_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (advisory_id) REFERENCES advisories(id) ON DELETE CASCADE,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
                UNIQUE KEY unique_advisory_client (advisory_id, client_id),
                INDEX idx_advisory_id (advisory_id),
                INDEX idx_client_id (client_id),
                INDEX idx_sent_date (sent_date DESC)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS news_articles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                hash_id VARCHAR(255) UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description LONGTEXT,
                meta_description TEXT,
                image_url TEXT,
                source VARCHAR(255) NOT NULL,
                source_url TEXT,
                published_date VARCHAR(50),
                tags TEXT,
                raw_data LONGTEXT,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_hash_id (hash_id),
                INDEX idx_published_date (published_date),
                INDEX idx_created_at (created_at),
                INDEX idx_updated_at (updated_at),
                INDEX idx_source (source),
                INDEX idx_source_created (source, created_at DESC),
                FULLTEXT idx_fts (title, description, meta_description, tags)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255),
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_name (name),
                INDEX idx_enabled (enabled)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS data_sources (
                id INT AUTO_INCREMENT PRIMARY KEY,
                source_name VARCHAR(255) NOT NULL,
                feed_url TEXT NOT NULL,
                feed_type VARCHAR(50) NOT NULL DEFAULT 'rss',
                category VARCHAR(50) NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                api_key TEXT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_source_url (source_name, feed_url(255)),
                INDEX idx_source_name (source_name),
                INDEX idx_category (category),
                INDEX idx_enabled (enabled),
                INDEX idx_feed_type (feed_type),
                INDEX idx_category_enabled (category, enabled)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        
        # Enhanced NVD Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_change_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                cve_id VARCHAR(50) NOT NULL,
                intelligence_item_id INT NOT NULL,
                change_type VARCHAR(50) NOT NULL,
                old_value LONGTEXT DEFAULT NULL,
                new_value LONGTEXT DEFAULT NULL,
                changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_cve_id (cve_id),
                INDEX idx_item_id (intelligence_item_id),
                INDEX idx_change_type (change_type),
                INDEX idx_changed_at (changed_at DESC)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_cpe_mapping (
                id INT AUTO_INCREMENT PRIMARY KEY,
                cve_id VARCHAR(50) NOT NULL,
                intelligence_item_id INT NOT NULL,
                cpe_uri VARCHAR(500) NOT NULL,
                vendor VARCHAR(255) DEFAULT NULL,
                product VARCHAR(255) DEFAULT NULL,
                version VARCHAR(100) DEFAULT NULL,
                version_start VARCHAR(100) DEFAULT NULL,
                version_end VARCHAR(100) DEFAULT NULL,
                vulnerable BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_cve_id (cve_id),
                INDEX idx_item_id (intelligence_item_id),
                INDEX idx_cpe_uri (cpe_uri(255)),
                INDEX idx_vendor (vendor),
                INDEX idx_product (product),
                INDEX idx_vendor_product (vendor, product)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_references (
                id INT AUTO_INCREMENT PRIMARY KEY,
                cve_id VARCHAR(50) NOT NULL,
                intelligence_item_id INT NOT NULL,
                url TEXT NOT NULL,
                source VARCHAR(255) DEFAULT NULL,
                tags TEXT DEFAULT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_cve_id (cve_id),
                INDEX idx_item_id (intelligence_item_id),
                INDEX idx_source (source)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        
        # AI Processing Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_processing_queue (
                id INT AUTO_INCREMENT PRIMARY KEY,
                item_type ENUM('news', 'intelligence') NOT NULL,
                item_id INT NOT NULL,
                priority INT DEFAULT 5,
                status ENUM('queued', 'processing', 'completed', 'failed') DEFAULT 'queued',
                retry_count INT DEFAULT 0,
                error_message TEXT DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP NULL DEFAULT NULL,
                INDEX idx_status_priority (status, priority),
                INDEX idx_item (item_type, item_id),
                UNIQUE KEY unique_item (item_type, item_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
        
        # Add AI columns to existing tables
        try:
            # Add AI columns to news_articles
            cursor.execute("""
                ALTER TABLE news_articles 
                ADD COLUMN IF NOT EXISTS ai_summary LONGTEXT DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_summary_status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
                ADD COLUMN IF NOT EXISTS ai_summary_created_at TIMESTAMP NULL DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_key_points JSON DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_sentiment VARCHAR(20) DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_category_tags JSON DEFAULT NULL
            """)
        except Exception as e:
            # For older MySQL versions that don't support IF NOT EXISTS
            try:
                cursor.execute("ALTER TABLE news_articles ADD COLUMN ai_summary LONGTEXT DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE news_articles ADD COLUMN ai_summary_status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending'")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE news_articles ADD COLUMN ai_summary_created_at TIMESTAMP NULL DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE news_articles ADD COLUMN ai_key_points JSON DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE news_articles ADD COLUMN ai_sentiment VARCHAR(20) DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE news_articles ADD COLUMN ai_category_tags JSON DEFAULT NULL")
            except:
                pass
        
        try:
            # Add AI columns to intelligence_items
            cursor.execute("""
                ALTER TABLE intelligence_items 
                ADD COLUMN IF NOT EXISTS ai_summary LONGTEXT DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_summary_status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending',
                ADD COLUMN IF NOT EXISTS ai_summary_created_at TIMESTAMP NULL DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_key_points JSON DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_sentiment VARCHAR(20) DEFAULT NULL,
                ADD COLUMN IF NOT EXISTS ai_category_tags JSON DEFAULT NULL
            """)
        except Exception as e:
            # For older MySQL versions that don't support IF NOT EXISTS
            try:
                cursor.execute("ALTER TABLE intelligence_items ADD COLUMN ai_summary LONGTEXT DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE intelligence_items ADD COLUMN ai_summary_status ENUM('pending', 'processing', 'completed', 'failed') DEFAULT 'pending'")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE intelligence_items ADD COLUMN ai_summary_created_at TIMESTAMP NULL DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE intelligence_items ADD COLUMN ai_key_points JSON DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE intelligence_items ADD COLUMN ai_sentiment VARCHAR(20) DEFAULT NULL")
            except:
                pass
            try:
                cursor.execute("ALTER TABLE intelligence_items ADD COLUMN ai_category_tags JSON DEFAULT NULL")
            except:
                pass
        
        # Populate default data sources if table is empty
        self._populate_default_sources(cursor)

    def _populate_default_sources(self, cursor):
        """Populate ALL data sources on first run - comprehensive initialization"""
        # Check if data_sources table is empty
        cursor.execute("SELECT COUNT(*) as count FROM data_sources")
        result = cursor.fetchone()
        count = result['count'] if isinstance(result, dict) else result[0]
        
        if count > 0:
            # Sources already exist, skip population
            logger.info(f"Data sources already configured ({count} sources)")
            return
        
        logger.info("First run detected - initializing ALL data sources...")
        
        # Import and run comprehensive source initialization
        try:
            from initialize_sources import get_all_sources
            all_sources = get_all_sources()
            
            added = 0
            for source in all_sources:
                try:
                    cursor.execute("""
                        INSERT INTO data_sources 
                        (source_name, feed_url, feed_type, category, enabled)
                        VALUES (%s, %s, %s, %s, TRUE)
                    """, (source['source_name'], source['feed_url'], 
                          source['feed_type'], source['category']))
                    added += 1
                except Exception as e:
                    logger.debug(f"Skipped source {source['source_name']}: {e}")
            
            logger.info(f"✓ Initialized {added} data sources")
            logger.info("  - News sources: RSS feeds + sitemaps")
            logger.info("  - CERT/Advisory sources: Government + Vendor")
            logger.info("  - CERT-In sources: Indian government")
            logger.info("  - Ransomware intelligence sources")
            
        except ImportError:
            # Fallback to minimal sources if initialize_sources.py not available
            logger.warning("initialize_sources.py not found, using minimal sources")
            minimal_sources = [
                ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews', 'rss', 'news'),
                ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/', 'rss', 'news'),
                ('SecurityWeek', 'https://feeds.feedburner.com/Securityweek', 'rss', 'news'),
                ('Qualys Security Alerts', 'https://blog.qualys.com/feed', 'rss', 'cert'),
                ('Microsoft Security Blog', 'https://www.microsoft.com/en-us/security/blog/feed/', 'rss', 'cert'),
            ]
            
            for name, url, feed_type, category in minimal_sources:
                try:
                    cursor.execute("""
                        INSERT INTO data_sources 
                        (source_name, feed_url, feed_type, category, enabled)
                        VALUES (%s, %s, %s, %s, TRUE)
                    """, (name, url, feed_type, category))
                    logger.info(f"✓ Added: {name}")
                except Exception as e:
                    logger.debug(f"Skipped {name}: {e}")

    def insert_item(self, item: Dict[str, Any]) -> bool:
        """Insert item - routes news items to news_articles table, others to intelligence_items"""
        category = item.get('category', '').lower()
        if category == 'news':
            return self.insert_news_article(item)
        else:
            return self.insert_intelligence_item(item)

    def batch_insert_items(self, items: List[Dict[str, Any]]) -> tuple:
        """Batch insert items for better performance. Returns (inserted_count, updated_count, error_count)"""
        if not items:
            return (0, 0, 0)
        
        news_items = []
        intelligence_items = []
        
        for item in items:
            category = item.get('category', '').lower()
            if category == 'news':
                news_items.append(item)
            else:
                intelligence_items.append(item)
        
        news_inserted = 0
        news_updated = 0
        news_errors = 0
        intel_inserted = 0
        intel_updated = 0
        intel_errors = 0
        
        if news_items:
            try:
                ni, nu, ne = self._batch_insert_news_articles(news_items)
                news_inserted, news_updated, news_errors = ni, nu, ne
            except Exception as e:
                logger.error(f"Error in batch insert news articles: {e}", exc_info=True)
                news_errors = len(news_items)
        
        if intelligence_items:
            try:
                ii, iu, ie = self._batch_insert_intelligence_items(intelligence_items)
                intel_inserted, intel_updated, intel_errors = ii, iu, ie
            except Exception as e:
                logger.error(f"Error in batch insert intelligence items: {e}", exc_info=True)
                intel_errors = len(intelligence_items)
        
        # Add items to AI processing queue after successful insertion
        if hasattr(config, 'AI_SUMMARIZATION_ENABLED') and config.AI_SUMMARIZATION_ENABLED:
            try:
                # Queue news articles for AI processing
                if news_items and (news_inserted > 0 or news_updated > 0):
                    for item in news_items:
                        # Get the article ID - we need to fetch it since batch insert doesn't return IDs
                        if item.get('title') and item.get('source'):
                            try:
                                # Create hash to find the article
                                import hashlib
                                hash_data = f"news|{item['source']}|{item.get('source_url', '')}|{item['title']}"
                                hash_id = hashlib.sha256(hash_data.encode()).hexdigest()
                                
                                # Find the article ID
                                conn = self.get_connection()
                                cursor = self.get_cursor(conn)
                                cursor.execute("SELECT id FROM news_articles WHERE hash_id = %s", (hash_id,))
                                result = cursor.fetchone()
                                if result:
                                    article_id = result['id'] if isinstance(result, dict) else result[0]
                                    self.queue_for_ai_processing('news', article_id, priority=5)
                                cursor.close()
                                conn.close()
                            except Exception as e:
                                logger.debug(f"Could not queue news article for AI processing: {e}")
                
                # Queue intelligence items for AI processing (only news-like categories)
                if intelligence_items and (intel_inserted > 0 or intel_updated > 0):
                    for item in intelligence_items:
                        # Only queue certain categories that benefit from AI summarization
                        category = item.get('category', '').lower()
                        if category in ['cert', 'cert-in', 'ransomware'] and item.get('title') and item.get('source'):
                            try:
                                # Create hash to find the item
                                import hashlib
                                hash_data = f"{item['category']}|{item['source']}|{item.get('source_url', '')}|{item['title']}"
                                hash_id = hashlib.sha256(hash_data.encode()).hexdigest()
                                
                                # Find the item ID
                                conn = self.get_connection()
                                cursor = self.get_cursor(conn)
                                cursor.execute("SELECT id FROM intelligence_items WHERE hash_id = %s", (hash_id,))
                                result = cursor.fetchone()
                                if result:
                                    item_id = result['id'] if isinstance(result, dict) else result[0]
                                    self.queue_for_ai_processing('intelligence', item_id, priority=5)
                                cursor.close()
                                conn.close()
                            except Exception as e:
                                logger.debug(f"Could not queue intelligence item for AI processing: {e}")
                                
            except Exception as e:
                logger.warning(f"Error queuing items for AI processing: {e}")

        return (news_inserted + intel_inserted, news_updated + intel_updated, news_errors + intel_errors)

    def _batch_insert_news_articles(self, items: List[Dict[str, Any]]) -> tuple:
        """Batch insert news articles using INSERT ... ON DUPLICATE KEY UPDATE"""
        if not items:
            return (0, 0, 0)
        
        conn = None
        cursor = None
        inserted = 0
        updated = 0
        errors = 0
        
        try:
            conn = self.get_connection()
            cursor = self.get_cursor(conn)
            param = self._get_param_placeholder()
            placeholders = ', '.join([param] * 10)
            values_list = []
            
            for item in items:
                if not item.get('source') or not item.get('title'):
                    logger.warning(f"Skipping news article with missing fields - source: {item.get('source')}, title: {item.get('title', '')[:50]}")
                    errors += 1
                    continue
                
                hash_data = f"news|{item['source']}|{item.get('source_url', '')}|{item['title']}"
                hash_id = hashlib.sha256(hash_data.encode()).hexdigest()
                
                MAX_DESCRIPTION_LENGTH = 1000000
                MAX_RAW_DATA_LENGTH = 2000000
                MAX_TITLE_LENGTH = 10000
                
                title = str(item.get('title', ''))[:MAX_TITLE_LENGTH]
                description = str(item.get('description', '') or '')[:MAX_DESCRIPTION_LENGTH]
                meta_description = str(item.get('meta_description', '') or '')[:5000]
                image_url = str(item.get('image_url', '') or '')[:2000]
                raw_data = item.get('raw_data', {})
                raw_data_json = json.dumps(raw_data) if raw_data else '{}'
                
                if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                    if isinstance(raw_data, dict):
                        essential_keys = ['url', 'source', 'published', 'title']
                        truncated_data = {k: raw_data.get(k) for k in essential_keys if k in raw_data}
                        raw_data_json = json.dumps(truncated_data)
                        if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                            raw_data_json = '{}'
                    else:
                        raw_data_json = '{}'
                
                tags_json = json.dumps(item.get('tags', [])) if item.get('tags') else '[]'
                
                values_list.append((
                    hash_id,
                    title,
                    description,
                    meta_description,
                    image_url,
                    item['source'],
                    item.get('source_url', '') or '',
                    item.get('published_date', '') or '',
                    tags_json,
                    raw_data_json
                ))
            
            if not values_list:
                return (0, 0, errors)
            
            batch_size = 100
            for i in range(0, len(values_list), batch_size):
                batch = values_list[i:i+batch_size]
                placeholders_per_row = ', '.join([param] * 10)
                batch_placeholders_list = []
                batch_values = []
                
                for row_values in batch:
                    batch_placeholders_list.append(f'({placeholders_per_row})')
                    batch_values.extend(row_values)
                
                batch_placeholders = ', '.join(batch_placeholders_list)
                
                update_clause = """
                    ON DUPLICATE KEY UPDATE
                    title = VALUES(title),
                    description = VALUES(description),
                    meta_description = VALUES(meta_description),
                    image_url = VALUES(image_url),
                    source_url = VALUES(source_url),
                    published_date = VALUES(published_date),
                    tags = VALUES(tags),
                    raw_data = VALUES(raw_data)
                """
                
                query = f"""
                    INSERT INTO news_articles
                    (hash_id, title, description, meta_description, image_url, source, source_url,
                     published_date, tags, raw_data)
                    VALUES {batch_placeholders}
                    {update_clause}
                """
                
                cursor.execute(query, batch_values)
                affected = cursor.rowcount
                # In MySQL, ON DUPLICATE KEY UPDATE returns 2 if a row is updated, 1 if inserted
                # This estimation assumes 1 row affected per item in batch
                updates_in_batch = max(0, affected - len(batch))
                inserts_in_batch = len(batch) - updates_in_batch
                
                inserted += inserts_in_batch
                updated += updates_in_batch
                conn.commit()
            
            cursor.close()
            conn.close()
            return (inserted, updated, errors)
            
        except Exception as e:
            logger.error(f"Error in batch insert news articles: {e}", exc_info=True)
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            # Fall back to individual inserts for failed batch
            logger.info(f"Falling back to individual inserts for {len(items)} news articles...")
            fallback_inserted = 0
            fallback_updated = 0
            fallback_errors = 0
            for item in items:
                try:
                    result = self.insert_news_article(item)
                    if result:
                        fallback_inserted += 1
                    else:
                        fallback_updated += 1
                except Exception as item_error:
                    logger.debug(f"Failed to insert news article: {item.get('title', 'Unknown')[:50]} - {item_error}")
                    fallback_errors += 1
            return (inserted + fallback_inserted, updated + fallback_updated, errors + fallback_errors)

    def _batch_insert_intelligence_items(self, items: List[Dict[str, Any]]) -> tuple:
        """Batch insert intelligence items using INSERT ... ON DUPLICATE KEY UPDATE"""
        if not items:
            return (0, 0, 0)
        
        conn = None
        cursor = None
        inserted = 0
        updated = 0
        errors = 0
        
        try:
            conn = self.get_connection()
            cursor = self.get_cursor(conn)
            
            # Check for columns presence dynamically
            try:
                cursor.execute("""
                    SELECT COLUMN_NAME
                    FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'intelligence_items'
                    AND COLUMN_NAME IN ('meta_description', 'image_url')
                """)
                existing_cols = [row[0] if isinstance(row, (list, tuple)) else row.get('COLUMN_NAME', '') for row in cursor.fetchall()]
                has_meta = 'meta_description' in existing_cols
                has_image = 'image_url' in existing_cols
            except:
                has_meta = False
                has_image = False
            
            param = self._get_param_placeholder()
            values_list = []
            
            for item in items:
                if not item.get('category') or not item.get('source') or not item.get('title'):
                    logger.warning(f"Skipping item with missing fields - category: {item.get('category')}, source: {item.get('source')}, title: {item.get('title', '')[:50]}")
                    errors += 1
                    continue
                
                hash_data = f"{item['category']}|{item['source']}|{item.get('source_url', '')}|{item['title']}"
                hash_id = hashlib.sha256(hash_data.encode()).hexdigest()
                
                MAX_DESCRIPTION_LENGTH = 1000000
                MAX_RAW_DATA_LENGTH = 2000000
                MAX_TITLE_LENGTH = 10000
                
                title = str(item.get('title', ''))[:MAX_TITLE_LENGTH]
                description = str(item.get('description', '') or '')[:MAX_DESCRIPTION_LENGTH]
                meta_description = str(item.get('meta_description', '') or '')[:5000] if has_meta else ''
                image_url = str(item.get('image_url', '') or '')[:2000] if has_image else ''
                raw_data = item.get('raw_data', {})
                raw_data_json = json.dumps(raw_data) if raw_data else '{}'
                
                if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                    if isinstance(raw_data, dict):
                        essential_keys = ['url', 'source', 'published', 'title']
                        truncated_data = {k: raw_data.get(k) for k in essential_keys if k in raw_data}
                        raw_data_json = json.dumps(truncated_data)
                        if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                            raw_data_json = '{}'
                    else:
                        raw_data_json = '{}'
                
                tags_json = json.dumps(item.get('tags', [])) if item.get('tags') else '[]'
                
                # Enhanced NVD fields
                cwe_id = item.get('cwe_id', '') or ''
                cvss_v2_score = item.get('cvss_v2_score')
                cvss_v3_score = item.get('cvss_v3_score')
                cvss_v4_score = item.get('cvss_v4_score')
                cvss_vector = item.get('cvss_vector', '') or ''
                cve_status = item.get('cve_status', '') or ''
                last_modified_date = item.get('last_modified_date', '') or ''
                references_json = item.get('references_json', '') or ''
                affected_products_json = item.get('affected_products_json', '') or ''
                exploitability_score = item.get('exploitability_score')
                impact_score = item.get('impact_score')
                
                if has_meta and has_image:
                    values_list.append((
                        hash_id,
                        item['category'],
                        title,
                        description,
                        meta_description,
                        image_url,
                        item['source'],
                        item.get('source_url', '') or '',
                        item.get('published_date', '') or '',
                        (item.get('severity') or '') if item.get('severity') is not None else '',
                        item.get('cve_id', '') or '',
                        tags_json,
                        raw_data_json,
                        cwe_id,
                        cvss_v2_score,
                        cvss_v3_score,
                        cvss_v4_score,
                        cvss_vector,
                        cve_status,
                        last_modified_date,
                        references_json,
                        affected_products_json,
                        exploitability_score,
                        impact_score
                    ))
                else:
                    values_list.append((
                        hash_id,
                        item['category'],
                        title,
                        description,
                        item['source'],
                        item.get('source_url', '') or '',
                        item.get('published_date', '') or '',
                        (item.get('severity') or '') if item.get('severity') is not None else '',
                        item.get('cve_id', '') or '',
                        tags_json,
                        raw_data_json,
                        cwe_id,
                        cvss_v2_score,
                        cvss_v3_score,
                        cvss_v4_score,
                        cvss_vector,
                        cve_status,
                        last_modified_date,
                        references_json,
                        affected_products_json,
                        exploitability_score,
                        impact_score
                    ))
            
            if not values_list:
                return (0, 0, errors)
            
            batch_size = 100
            for i in range(0, len(values_list), batch_size):
                batch = values_list[i:i+batch_size]
                
                if has_meta and has_image:
                    placeholders_per_row = ', '.join([param] * 24)  # Updated to 24 fields
                    batch_placeholders_list = []
                    batch_values = []
                    for row_values in batch:
                        batch_placeholders_list.append(f'({placeholders_per_row})')
                        batch_values.extend(row_values)
                    
                    batch_placeholders = ', '.join(batch_placeholders_list)
                    update_clause = """
                        ON DUPLICATE KEY UPDATE
                        category = VALUES(category),
                        title = VALUES(title),
                        description = VALUES(description),
                        meta_description = VALUES(meta_description),
                        image_url = VALUES(image_url),
                        source = VALUES(source),
                        source_url = VALUES(source_url),
                        published_date = VALUES(published_date),
                        severity = VALUES(severity),
                        cve_id = VALUES(cve_id),
                        tags = VALUES(tags),
                        raw_data = VALUES(raw_data),
                        cwe_id = VALUES(cwe_id),
                        cvss_v2_score = VALUES(cvss_v2_score),
                        cvss_v3_score = VALUES(cvss_v3_score),
                        cvss_v4_score = VALUES(cvss_v4_score),
                        cvss_vector = VALUES(cvss_vector),
                        cve_status = VALUES(cve_status),
                        last_modified_date = VALUES(last_modified_date),
                        references_json = VALUES(references_json),
                        affected_products_json = VALUES(affected_products_json),
                        exploitability_score = VALUES(exploitability_score),
                        impact_score = VALUES(impact_score)
                    """
                    query = f"""
                        INSERT INTO intelligence_items
                        (hash_id, category, title, description, meta_description, image_url, source, source_url,
                         published_date, severity, cve_id, tags, raw_data,
                         cwe_id, cvss_v2_score, cvss_v3_score, cvss_v4_score, cvss_vector,
                         cve_status, last_modified_date, references_json, affected_products_json,
                         exploitability_score, impact_score)
                        VALUES {batch_placeholders}
                        {update_clause}
                    """
                else:
                    placeholders_per_row = ', '.join([param] * 22)  # Updated to 22 fields
                    batch_placeholders_list = []
                    batch_values = []
                    for row_values in batch:
                        batch_placeholders_list.append(f'({placeholders_per_row})')
                        batch_values.extend(row_values)
                    
                    batch_placeholders = ', '.join(batch_placeholders_list)
                    update_clause = """
                        ON DUPLICATE KEY UPDATE
                        category = VALUES(category),
                        title = VALUES(title),
                        description = VALUES(description),
                        source = VALUES(source),
                        source_url = VALUES(source_url),
                        published_date = VALUES(published_date),
                        severity = VALUES(severity),
                        cve_id = VALUES(cve_id),
                        tags = VALUES(tags),
                        raw_data = VALUES(raw_data),
                        cwe_id = VALUES(cwe_id),
                        cvss_v2_score = VALUES(cvss_v2_score),
                        cvss_v3_score = VALUES(cvss_v3_score),
                        cvss_v4_score = VALUES(cvss_v4_score),
                        cvss_vector = VALUES(cvss_vector),
                        cve_status = VALUES(cve_status),
                        last_modified_date = VALUES(last_modified_date),
                        references_json = VALUES(references_json),
                        affected_products_json = VALUES(affected_products_json),
                        exploitability_score = VALUES(exploitability_score),
                        impact_score = VALUES(impact_score)
                    """
                    query = f"""
                        INSERT INTO intelligence_items
                        (hash_id, category, title, description, source, source_url,
                         published_date, severity, cve_id, tags, raw_data,
                         cwe_id, cvss_v2_score, cvss_v3_score, cvss_v4_score, cvss_vector,
                         cve_status, last_modified_date, references_json, affected_products_json,
                         exploitability_score, impact_score)
                        VALUES {batch_placeholders}
                        {update_clause}
                    """
                
                cursor.execute(query, batch_values)
                affected = cursor.rowcount
                updates_in_batch = max(0, affected - len(batch))
                inserts_in_batch = len(batch) - updates_in_batch
                
                inserted += inserts_in_batch
                updated += updates_in_batch
                conn.commit()
            
            cursor.close()
            conn.close()
            return (inserted, updated, errors)
            
        except Exception as e:
            logger.error(f"Error in batch insert intelligence items: {e}", exc_info=True)
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            # Fall back to individual inserts for failed batch
            logger.info(f"Falling back to individual inserts for {len(items)} items...")
            fallback_inserted = 0
            fallback_updated = 0
            fallback_errors = 0
            for item in items:
                try:
                    result = self.insert_intelligence_item(item)
                    if result:
                        fallback_inserted += 1
                    else:
                        fallback_updated += 1
                except Exception as item_error:
                    logger.debug(f"Failed to insert item: {item.get('title', 'Unknown')[:50]} - {item_error}")
                    fallback_errors += 1
            return (inserted + fallback_inserted, updated + fallback_updated, errors + fallback_errors)

    def insert_news_article(self, item: Dict[str, Any]) -> bool:
        """Insert news article into news_articles table"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = self.get_cursor(conn)
            
            if not item.get('source') or not item.get('title'):
                logger.warning(f"Skipping news article with missing required fields: {item.get('title', 'Unknown')}")
                return False
            
            hash_data = f"news|{item['source']}|{item.get('source_url', '')}|{item['title']}"
            hash_id = hashlib.sha256(hash_data.encode()).hexdigest()
            param = self._get_param_placeholder()
            
            cursor.execute(f"SELECT id FROM news_articles WHERE hash_id = {param}", (hash_id,))
            existing = cursor.fetchone()
            
            MAX_DESCRIPTION_LENGTH = 1000000
            MAX_RAW_DATA_LENGTH = 2000000
            MAX_TITLE_LENGTH = 10000
            
            title = str(item.get('title', ''))[:MAX_TITLE_LENGTH]
            description = str(item.get('description', '') or '')[:MAX_DESCRIPTION_LENGTH]
            meta_description = str(item.get('meta_description', '') or '')[:5000]
            image_url = str(item.get('image_url', '') or '')[:2000]
            raw_data = item.get('raw_data', {})
            raw_data_json = json.dumps(raw_data) if raw_data else '{}'
            
            if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                logger.warning(f"Raw data too large ({len(raw_data_json)} bytes), truncating for news article: {title[:50]}")
                if isinstance(raw_data, dict):
                    essential_keys = ['url', 'source', 'published', 'title']
                    truncated_data = {k: raw_data.get(k) for k in essential_keys if k in raw_data}
                    raw_data_json = json.dumps(truncated_data)
                    if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                        raw_data_json = '{}'
                else:
                    raw_data_json = '{}'
            
            tags_json = json.dumps(item.get('tags', [])) if item.get('tags') else '[]'
            
            if existing:
                params = self._get_param_placeholder()
                cursor.execute(f"""
                    UPDATE news_articles
                    SET title = {params}, description = {params}, meta_description = {params}, image_url = {params},
                        source_url = {params}, published_date = {params}, tags = {params}, raw_data = {params}
                    WHERE hash_id = {params}
                """, (
                    title,
                    description,
                    meta_description,
                    image_url,
                    item.get('source_url', '') or '',
                    item.get('published_date', '') or '',
                    tags_json,
                    raw_data_json,
                    hash_id
                ))
                conn.commit()
                cursor.close()
                conn.close()
                return False
            else:
                params = self._get_param_placeholder()
                placeholders = ', '.join([params] * 10)
                cursor.execute(f"""
                    INSERT INTO news_articles
                    (hash_id, title, description, meta_description, image_url, source, source_url,
                     published_date, tags, raw_data)
                    VALUES ({placeholders})
                """, (
                    hash_id,
                    title,
                    description,
                    meta_description,
                    image_url,
                    item['source'],
                    item.get('source_url', '') or '',
                    item.get('published_date', '') or '',
                    tags_json,
                    raw_data_json
                ))
                conn.commit()
                cursor.close()
                conn.close()
                return True
                
        except Exception as e:
            logger.error(f"Error inserting news article '{item.get('title', 'Unknown') if 'title' in locals() else 'Unknown'}': {e}", exc_info=True)
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            return False

    def insert_intelligence_item(self, item: Dict[str, Any]) -> bool:
        """Insert non-news item into intelligence_items table"""
        conn = None
        cursor = None
        try:
            conn = self.get_connection()
            cursor = self.get_cursor(conn)
            
            if not item.get('category') or not item.get('source') or not item.get('title'):
                logger.warning(f"Skipping item with missing required fields: {item.get('title', 'Unknown')}")
                return False
            
            hash_data = f"{item['category']}|{item['source']}|{item.get('source_url', '')}|{item['title']}"
            hash_id = hashlib.sha256(hash_data.encode()).hexdigest()
            param = self._get_param_placeholder()
            
            cursor.execute(f"SELECT id FROM intelligence_items WHERE hash_id = {param}", (hash_id,))
            existing = cursor.fetchone()
            
            MAX_DESCRIPTION_LENGTH = 1000000
            MAX_RAW_DATA_LENGTH = 2000000
            MAX_TITLE_LENGTH = 10000
            
            title = str(item.get('title', ''))[:MAX_TITLE_LENGTH]
            description = str(item.get('description', '') or '')[:MAX_DESCRIPTION_LENGTH]
            raw_data = item.get('raw_data', {})
            raw_data_json = json.dumps(raw_data) if raw_data else '{}'
            
            if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                logger.warning(f"Raw data too large ({len(raw_data_json)} bytes), truncating for item: {title[:50]}")
                if isinstance(raw_data, dict):
                    essential_keys = ['url', 'source', 'published', 'title']
                    truncated_data = {k: raw_data.get(k) for k in essential_keys if k in raw_data}
                    raw_data_json = json.dumps(truncated_data)
                    if len(raw_data_json) > MAX_RAW_DATA_LENGTH:
                        raw_data_json = '{}'
                else:
                    raw_data_json = '{}'
            
            tags_json = json.dumps(item.get('tags', [])) if item.get('tags') else '[]'
            
            # Dynamically check/add columns
            try:
                cursor.execute("""
                    SELECT COLUMN_NAME
                    FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'intelligence_items'
                    AND COLUMN_NAME IN ('meta_description', 'image_url')
                """)
                existing_columns = [row[0] if isinstance(row, (list, tuple)) else row.get('COLUMN_NAME', '') for row in cursor.fetchall()]
                
                if 'meta_description' not in existing_columns:
                    cursor.execute("ALTER TABLE intelligence_items ADD COLUMN meta_description TEXT NULL")
                    logger.info("Added meta_description column to intelligence_items")
                if 'image_url' not in existing_columns:
                    cursor.execute("ALTER TABLE intelligence_items ADD COLUMN image_url TEXT NULL")
                    logger.info("Added image_url column to intelligence_items")
                conn.commit()
            except Exception as e:
                logger.warning(f"Error checking/adding columns: {e}")
            
            meta_description = str(item.get('meta_description', '') or '')[:5000]
            image_url = str(item.get('image_url', '') or '')[:2000]
            
            # Enhanced NVD fields
            cwe_id = item.get('cwe_id', '') or ''
            cvss_v2_score = item.get('cvss_v2_score')
            cvss_v3_score = item.get('cvss_v3_score')
            cvss_v4_score = item.get('cvss_v4_score')
            cvss_vector = item.get('cvss_vector', '') or ''
            cve_status = item.get('cve_status', '') or ''
            last_modified_date = item.get('last_modified_date', '') or ''
            references_json = item.get('references_json', '') or ''
            affected_products_json = item.get('affected_products_json', '') or ''
            exploitability_score = item.get('exploitability_score')
            impact_score = item.get('impact_score')
            
            # Re-check columns after potential modification
            cursor.execute("""
                SELECT COLUMN_NAME
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'intelligence_items'
                AND COLUMN_NAME IN ('meta_description', 'image_url')
            """)
            existing_cols = [row[0] if isinstance(row, (list, tuple)) else row.get('COLUMN_NAME', '') for row in cursor.fetchall()]
            has_meta = 'meta_description' in existing_cols
            has_image = 'image_url' in existing_cols
            
            params = self._get_param_placeholder()
            
            if existing:
                if has_meta and has_image:
                    cursor.execute(f"""
                        UPDATE intelligence_items
                        SET title = {params}, description = {params}, meta_description = {params}, image_url = {params},
                            source_url = {params}, published_date = {params},
                            severity = {params}, cve_id = {params}, tags = {params}, raw_data = {params},
                            cwe_id = {params}, cvss_v2_score = {params}, cvss_v3_score = {params}, 
                            cvss_v4_score = {params}, cvss_vector = {params}, cve_status = {params},
                            last_modified_date = {params}, references_json = {params}, 
                            affected_products_json = {params}, exploitability_score = {params}, 
                            impact_score = {params}
                        WHERE hash_id = {params}
                    """, (
                        title,
                        description,
                        meta_description,
                        image_url,
                        item.get('source_url', '') or '',
                        item.get('published_date', '') or '',
                        (item.get('severity') or '') if item.get('severity') is not None else '',
                        item.get('cve_id', '') or '',
                        tags_json,
                        raw_data_json,
                        cwe_id,
                        cvss_v2_score,
                        cvss_v3_score,
                        cvss_v4_score,
                        cvss_vector,
                        cve_status,
                        last_modified_date,
                        references_json,
                        affected_products_json,
                        exploitability_score,
                        impact_score,
                        hash_id
                    ))
                else:
                    cursor.execute(f"""
                        UPDATE intelligence_items
                        SET title = {params}, description = {params}, source_url = {params}, published_date = {params},
                            severity = {params}, cve_id = {params}, tags = {params}, raw_data = {params},
                            cwe_id = {params}, cvss_v2_score = {params}, cvss_v3_score = {params}, 
                            cvss_v4_score = {params}, cvss_vector = {params}, cve_status = {params},
                            last_modified_date = {params}, references_json = {params}, 
                            affected_products_json = {params}, exploitability_score = {params}, 
                            impact_score = {params}
                        WHERE hash_id = {params}
                    """, (
                        title,
                        description,
                        item.get('source_url', '') or '',
                        item.get('published_date', '') or '',
                        (item.get('severity') or '') if item.get('severity') is not None else '',
                        item.get('cve_id', '') or '',
                        tags_json,
                        raw_data_json,
                        cwe_id,
                        cvss_v2_score,
                        cvss_v3_score,
                        cvss_v4_score,
                        cvss_vector,
                        cve_status,
                        last_modified_date,
                        references_json,
                        affected_products_json,
                        exploitability_score,
                        impact_score,
                        hash_id
                    ))
                conn.commit()
                return False
            else:
                params = self._get_param_placeholder()
                if has_meta and has_image:
                    placeholders = ', '.join([params] * 24)  # Updated to 24 fields
                    cursor.execute(f"""
                        INSERT INTO intelligence_items
                        (hash_id, category, title, description, meta_description, image_url, source, source_url,
                         published_date, severity, cve_id, tags, raw_data,
                         cwe_id, cvss_v2_score, cvss_v3_score, cvss_v4_score, cvss_vector,
                         cve_status, last_modified_date, references_json, affected_products_json,
                         exploitability_score, impact_score)
                        VALUES ({placeholders})
                    """, (
                        hash_id,
                        item['category'],
                        title,
                        description,
                        meta_description,
                        image_url,
                        item['source'],
                        item.get('source_url', '') or '',
                        item.get('published_date', '') or '',
                        (item.get('severity') or '') if item.get('severity') is not None else '',
                        item.get('cve_id', '') or '',
                        tags_json,
                        raw_data_json,
                        cwe_id,
                        cvss_v2_score,
                        cvss_v3_score,
                        cvss_v4_score,
                        cvss_vector,
                        cve_status,
                        last_modified_date,
                        references_json,
                        affected_products_json,
                        exploitability_score,
                        impact_score
                    ))
                else:
                    placeholders = ', '.join([params] * 22)  # Updated to 22 fields
                    cursor.execute(f"""
                        INSERT INTO intelligence_items
                        (hash_id, category, title, description, source, source_url,
                         published_date, severity, cve_id, tags, raw_data,
                         cwe_id, cvss_v2_score, cvss_v3_score, cvss_v4_score, cvss_vector,
                         cve_status, last_modified_date, references_json, affected_products_json,
                         exploitability_score, impact_score)
                        VALUES ({placeholders})
                    """, (
                        hash_id,
                        item['category'],
                        title,
                        description,
                        item['source'],
                        item.get('source_url', '') or '',
                        item.get('published_date', '') or '',
                        (item.get('severity') or '') if item.get('severity') is not None else '',
                        item.get('cve_id', '') or '',
                        tags_json,
                        raw_data_json,
                        cwe_id,
                        cvss_v2_score,
                        cvss_v3_score,
                        cvss_v4_score,
                        cvss_vector,
                        cve_status,
                        last_modified_date,
                        references_json,
                        affected_products_json,
                        exploitability_score,
                        impact_score
                    ))
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error inserting item '{item.get('title', 'Unknown')}': {e}", exc_info=True)
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            return False
        finally:
            if cursor:
                try:
                    cursor.close()
                except:
                    pass
            if conn:
                try:
                    conn.close()
                except:
                    pass

    def get_items(self, category: Optional[str] = None, search: Optional[str] = None,
                  page: int = 1, per_page: int = 50, sort_by: str = "published_date",
                  sort_order: str = "DESC", date_from: Optional[str] = None,
                  date_to: Optional[str] = None, year: Optional[int] = None,
                  month: Optional[int] = None, severity: Optional[str] = None,
                  source: Optional[str] = None) -> tuple:
        """Get paginated intelligence items with date filtering - routes news to news_articles table"""
        if category and category.lower() == 'news':
            return self.get_news_articles(search, page, per_page, sort_by, sort_order,
                                          date_from, date_to, year, month)
        
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        offset = (page - 1) * per_page
        
        where_clauses = []
        params = []
        param = self._get_param_placeholder()
        
        if category:
            where_clauses.append(f"category = {param}")
            params.append(category)
        
        if source:
            where_clauses.append(f"source = {param}")
            params.append(source)
            
        if search:
            search_pattern = f"%{search}%"
            where_clauses.append(f"(title LIKE {param} OR description LIKE {param} OR tags LIKE {param})")
            params.extend([search_pattern, search_pattern, search_pattern])
            
        if date_from:
            where_clauses.append(f"published_date >= {param}")
            params.append(date_from)
            
        if date_to:
            where_clauses.append(f"published_date <= {param}")
            params.append(date_to)
            
        if year:
            where_clauses.append(f"YEAR(STR_TO_DATE(published_date, '%Y-%m-%d')) = {param}")
            params.append(str(year))
            
        if month:
            where_clauses.append(f"MONTH(STR_TO_DATE(published_date, '%Y-%m-%d')) = {param}")
            params.append(f"{month:02d}")
            
        if severity:
            severity_list = [s.strip() for s in severity.split(',') if s.strip()]
            if severity_list:
                if len(severity_list) == 1:
                    where_clauses.append(f"UPPER(severity) = UPPER({param})")
                    params.append(severity_list[0])
                else:
                    placeholders = ', '.join([param] * len(severity_list))
                    where_clauses.append(f"UPPER(severity) IN ({placeholders})")
                    params.extend([s.upper() for s in severity_list])
        
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        
        valid_sort = ["published_date", "created_at", "title", "severity"]
        if sort_by not in valid_sort:
            sort_by = "published_date"
            
        if sort_order.upper() not in ["ASC", "DESC"]:
            sort_order = "DESC"
            
        count_query = f"SELECT COUNT(*) as total FROM intelligence_items WHERE {where_sql}"
        cursor.execute(count_query, params)
        result = cursor.fetchone()
        
        if isinstance(result, dict):
            total = result.get('total', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            total = result[0] if result else 0
        else:
            total = 0
            
        param = self._get_param_placeholder()
        query = f"""
            SELECT * FROM intelligence_items
            WHERE {where_sql}
            ORDER BY {sort_by} {sort_order}
            LIMIT {param} OFFSET {param}
        """
        cursor.execute(query, params + [per_page, offset])
        rows = cursor.fetchall()
        
        items = []
        for row in rows:
            if isinstance(row, dict):
                item = row
            elif hasattr(row, 'keys'):
                item = dict(row)
            else:
                item = dict(row)
                
            item['tags'] = json.loads(item.get('tags', '[]')) if item.get('tags') else []
            item['raw_data'] = json.loads(item.get('raw_data', '{}')) if item.get('raw_data') else {}
            items.append(item)
            
        cursor.close()
        conn.close()
        return items, total

    def get_news_articles(self, search: Optional[str] = None, page: int = 1, per_page: int = 50,
                          sort_by: str = "published_date", sort_order: str = "DESC",
                          date_from: Optional[str] = None, date_to: Optional[str] = None,
                          year: Optional[int] = None, month: Optional[int] = None) -> tuple:
        """Get paginated news articles from news_articles table"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        offset = (page - 1) * per_page
        
        where_clauses = []
        params = []
        param = self._get_param_placeholder()
        
        if search:
            where_clauses.append(f"(title LIKE {param} OR description LIKE {param} OR meta_description LIKE {param} OR tags LIKE {param})")
            params.append(f"%{search}%")
            params.append(f"%{search}%")
            params.append(f"%{search}%")
            params.append(f"%{search}%")
            
        if date_from:
            where_clauses.append(f"published_date >= {param}")
            params.append(date_from)
            
        if date_to:
            where_clauses.append(f"published_date <= {param}")
            params.append(date_to)
            
        if year:
            where_clauses.append(f"YEAR(STR_TO_DATE(published_date, '%Y-%m-%d')) = {param}")
            params.append(str(year))
            
        if month:
            where_clauses.append(f"MONTH(STR_TO_DATE(published_date, '%Y-%m-%d')) = {param}")
            params.append(f"{month:02d}")
            
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        
        valid_sort = ["published_date", "created_at", "title"]
        if sort_by not in valid_sort:
            sort_by = "published_date"
            
        count_query = f"SELECT COUNT(*) as total FROM news_articles WHERE {where_sql}"
        cursor.execute(count_query, params)
        total_row = cursor.fetchone()
        total = total_row['total'] if isinstance(total_row, dict) else total_row[0]
        
        query = f"""
            SELECT * FROM news_articles
            WHERE {where_sql}
            ORDER BY {sort_by} {sort_order}
            LIMIT {param} OFFSET {param}
        """
        cursor.execute(query, params + [per_page, offset])
        rows = cursor.fetchall()
        
        items = []
        for row in rows:
            if isinstance(row, dict):
                item = row
            elif hasattr(row, 'keys'):
                item = dict(row)
            else:
                item = dict(row)
                
            item['tags'] = json.loads(item.get('tags', '[]')) if item.get('tags') else []
            item['raw_data'] = json.loads(item.get('raw_data', '{}')) if item.get('raw_data') else {}
            item['category'] = 'news'
            items.append(item)
            
        cursor.close()
        conn.close()
        return items, total

    def get_statistics(self, hours: Optional[int] = None, date_from: Optional[str] = None, date_to: Optional[str] = None) -> Dict[str, Any]:
        """Get dashboard statistics - show ALL items by default, or filter by time if specified
        Args:
            hours: Filter by last N hours (based on published_date) - optional
            date_from: Start date (YYYY-MM-DD) - optional
            date_to: End date (YYYY-MM-DD) - optional
        """
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        stats = {}
        date_filter = ""
        params = []
        param = self._get_param_placeholder()
        
        if date_from and date_to:
            date_filter = f"""
                WHERE ((published_date >= {param} AND published_date <= {param})
                    OR (published_date IS NULL AND created_at >= {param} AND created_at <= {param})
                    OR (updated_at >= {param} AND updated_at <= {param}))
            """
            params.extend([date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59'])
        elif hours:
            date_filter = f"""
                WHERE (published_date >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
                    OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
                    OR updated_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
            """
        else:
            # No time filter - show ALL items
            date_filter = ""
        
        if date_from and date_to:
            cursor.execute(f"""
                SELECT category, COUNT(*) as count
                FROM intelligence_items
                WHERE ((published_date >= {param} AND published_date <= {param})
                    OR (published_date IS NULL AND created_at >= {param} AND created_at <= {param})
                    OR (updated_at >= {param} AND updated_at <= {param}))
                AND category != 'ioc'
                GROUP BY category
            """, [date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59'])
        elif hours:
            cursor.execute(f"""
                SELECT category, COUNT(*) as count
                FROM intelligence_items
                WHERE (published_date >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
                    OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
                    OR updated_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
                AND category != 'ioc'
                GROUP BY category
            """)
        else:
            # No time filter - count ALL items
            cursor.execute("""
                SELECT category, COUNT(*) as count
                FROM intelligence_items
                WHERE category != 'ioc'
                GROUP BY category
            """)
            
        rows = cursor.fetchall()
        category_counts = {}
        for row in rows:
            if isinstance(row, dict):
                category_counts[row['category']] = row['count']
            elif hasattr(row, '__getitem__'):
                try:
                    category_counts[row['category']] = row['count']
                except (KeyError, TypeError):
                    category_counts[row[0]] = row[1]
            else:
                category_counts[row[0]] = row[1]
                
        # Get news count
        if date_from and date_to:
            cursor.execute(f"""
                SELECT COUNT(*) as count
                FROM news_articles
                WHERE ((published_date >= {param} AND published_date <= {param})
                    OR (published_date IS NULL AND created_at >= {param} AND created_at <= {param})
                    OR (updated_at >= {param} AND updated_at <= {param}))
            """, [date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59'])
        elif hours:
            cursor.execute(f"""
                SELECT COUNT(*) as count
                FROM news_articles
                WHERE (published_date >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
                    OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
                    OR updated_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
            """)
        else:
            # No time filter - count ALL news
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM news_articles
            """)
            
        news_row = cursor.fetchone()
        news_count = news_row['count'] if isinstance(news_row, dict) else news_row[0]
        category_counts['news'] = news_count
        
        all_categories = ['news', 'cve', 'exploit', 'malware', 'ransomware', 'cert', 'cert-in']
        for cat in all_categories:
            if cat not in category_counts:
                category_counts[cat] = 0
                
        stats['category_counts'] = category_counts
        
        # Get CVE stats
        cursor.execute("""
            SELECT COUNT(*) as count FROM intelligence_items
            WHERE category = 'cve'
        """)
        cve_total_row = cursor.fetchone()
        total_cves = cve_total_row['count'] if isinstance(cve_total_row, dict) else (cve_total_row[0] if cve_total_row else 0)
        stats['total_cves'] = total_cves
        
        cursor.execute("""
            SELECT COUNT(*) as count FROM intelligence_items
            WHERE category = 'cve'
              AND severity IN ('CRITICAL', 'HIGH', 'Critical', 'High')
        """)
        critical_high_total_row = cursor.fetchone()
        total_critical_high = critical_high_total_row['count'] if isinstance(critical_high_total_row, dict) else (critical_high_total_row[0] if critical_high_total_row else 0)
        stats['total_critical_high'] = total_critical_high
        
        # Recent items count based on filter
        if date_from and date_to:
            cursor.execute("""
                SELECT COUNT(*) as count FROM intelligence_items
                WHERE (published_date >= %s AND published_date <= %s)
                   OR (published_date IS NULL AND created_at >= %s AND created_at <= %s)
                   OR (updated_at >= %s AND updated_at <= %s)
            """, (date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59'))
        elif hours:
            cursor.execute(f"""
                SELECT COUNT(*) as count FROM intelligence_items
                WHERE published_date >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
                   OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
                   OR updated_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
            """)
        else:
            cursor.execute("""
                SELECT COUNT(*) as count FROM intelligence_items
                WHERE published_date >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                   OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR))
            """)
            
        result = cursor.fetchone()
        if isinstance(result, dict):
            stats['recent_24h'] = result.get('count', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            stats['recent_24h'] = result[0] if result else 0
        else:
            stats['recent_24h'] = 0
            
        # Critical/High count (ALL or filtered)
        if date_from and date_to:
            cursor.execute("""
                SELECT COUNT(*) as count FROM intelligence_items
                WHERE category = 'cve'
                  AND severity IN ('CRITICAL', 'HIGH', 'Critical', 'High')
                  AND ((published_date >= %s AND published_date <= %s)
                    OR (published_date IS NULL AND created_at >= %s AND created_at <= %s)
                    OR (updated_at >= %s AND updated_at <= %s))
            """, (date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59'))
        elif hours:
            cursor.execute(f"""
                SELECT COUNT(*) as count FROM intelligence_items
                WHERE category = 'cve'
                  AND severity IN ('CRITICAL', 'HIGH', 'Critical', 'High')
                  AND (published_date >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
                    OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
                    OR updated_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
            """)
        else:
            # No time filter - count ALL critical/high CVEs
            cursor.execute("""
                SELECT COUNT(*) as count FROM intelligence_items
                WHERE category = 'cve'
                  AND severity IN ('CRITICAL', 'HIGH', 'Critical', 'High')
            """)
            
        result = cursor.fetchone()
        if isinstance(result, dict):
            stats['critical_high'] = result.get('count', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            stats['critical_high'] = result[0] if result else 0
        else:
            stats['critical_high'] = 0
            
        # Latest items per category
        latest_items = {}
        
        # Latest News - Get 6 articles, one from each different source
        cursor.execute("""
            SELECT n1.*
            FROM news_articles n1
            INNER JOIN (
                SELECT source, MAX(CONCAT(COALESCE(published_date, ''), COALESCE(created_at, ''))) as latest
                FROM news_articles
                GROUP BY source
                ORDER BY latest DESC
                LIMIT 6
            ) n2 ON n1.source = n2.source 
            AND CONCAT(COALESCE(n1.published_date, ''), COALESCE(n1.created_at, '')) = n2.latest
            ORDER BY n1.published_date DESC, n1.created_at DESC
            LIMIT 6
        """)
        rows = cursor.fetchall()
        items = []
        for row in rows:
            if isinstance(row, dict):
                item = row
            elif hasattr(row, 'keys'):
                item = dict(row)
            else:
                item = dict(row)
            item['tags'] = json.loads(item['tags']) if item.get('tags') else []
            item['category'] = 'news'
            items.append(item)
        latest_items['news'] = items
        
        # Latest for other categories
        for category in ['cve', 'exploit', 'malware', 'ransomware', 'cert', 'cert-in']:
            cursor.execute(f"""
                SELECT * FROM intelligence_items
                WHERE category = {self._get_param_placeholder()}
                ORDER BY published_date DESC, created_at DESC
                LIMIT 6
            """, (category,))
            rows = cursor.fetchall()
            items = []
            for row in rows:
                if isinstance(row, dict):
                    item = row
                elif hasattr(row, 'keys'):
                    item = dict(row)
                else:
                    item = dict(row)
                item['tags'] = json.loads(item['tags']) if item.get('tags') else []
                items.append(item)
            latest_items[category] = items
            
        stats['latest_items'] = latest_items
        
        cursor.close()
        conn.close()
        return stats

    def get_total_count(self) -> int:
        """Get total count of items in database (includes both intelligence_items and news_articles)"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        cursor.execute("""
            SELECT
                (SELECT COUNT(*) FROM intelligence_items) +
                (SELECT COUNT(*) FROM news_articles) as total
        """)
        result = cursor.fetchone()
        
        if isinstance(result, dict):
            count = result.get('total', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            count = result[0] if result else 0
        else:
            count = 0
            
        cursor.close()
        conn.close()
        return count

    def get_last_fetch_date(self, source_name: str, fetch_type: str = 'incremental') -> Optional[str]:
        """Get last fetch date for a source"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            SELECT last_fetch_date, last_item_date
            FROM fetch_history
            WHERE source_name = {param} AND fetch_type = {param}
        """, (source_name, fetch_type))
        
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            if isinstance(result, dict):
                return result.get('last_fetch_date'), result.get('last_item_date')
            return result[0], result[1]
        return None, None

    def update_fetch_history(self, source_name: str, fetch_type: str = 'incremental',
                             last_item_date: Optional[str] = None,
                             items_fetched: int = 0,
                             items_inserted: int = 0,
                             items_updated: int = 0):
        """Update fetch history for a source with item counts"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        now = datetime.utcnow().isoformat()
        
        # Check available columns
        cursor.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'fetch_history'
            AND COLUMN_NAME IN ('items_fetched', 'items_inserted', 'items_updated')
        """)
        existing_columns = [row[0] if isinstance(row, (list, tuple)) else row.get('COLUMN_NAME', '') for row in cursor.fetchall()]
        has_stats_columns = 'items_fetched' in existing_columns
        
        cursor.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'fetch_history'
            AND COLUMN_NAME = 'source_name'
        """)
        has_source_name = len(cursor.fetchall()) > 0
        
        if not has_source_name:
            logger.warning(f"fetch_history table missing source_name column. Skipping update for {source_name}")
            cursor.close()
            conn.close()
            return
            
        if has_stats_columns:
            cursor.execute(f"""
                INSERT INTO fetch_history
                (source_name, last_fetch_date, fetch_type, last_item_date, items_fetched, items_inserted, items_updated)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param})
                ON DUPLICATE KEY UPDATE
                last_fetch_date = VALUES(last_fetch_date),
                last_item_date = VALUES(last_item_date),
                items_fetched = items_fetched + VALUES(items_fetched),
                items_inserted = items_inserted + VALUES(items_inserted),
                items_updated = items_updated + VALUES(items_updated)
            """, (source_name, now, fetch_type, last_item_date, items_fetched, items_inserted, items_updated))
        else:
            cursor.execute(f"""
                INSERT INTO fetch_history
                (source_name, last_fetch_date, fetch_type, last_item_date)
                VALUES ({param}, {param}, {param}, {param})
                ON DUPLICATE KEY UPDATE
                last_fetch_date = VALUES(last_fetch_date),
                last_item_date = VALUES(last_item_date)
            """, (source_name, now, fetch_type, last_item_date))
            
        conn.commit()
        cursor.close()
        conn.close()

    def should_fetch_historical(self, source_name: str) -> bool:
        """Check if we should fetch historical data (only once)"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            SELECT COUNT(*) as count FROM fetch_history
            WHERE source_name = {param} AND fetch_type = 'historical'
        """, (source_name,))
        result = cursor.fetchone()
        
        if isinstance(result, dict):
            count = result.get('count', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            count = result[0] if result else 0
        else:
            count = 0
            
        cursor.close()
        conn.close()
        return count == 0

    def get_last_fetch_time(self) -> Optional[str]:
        """Get the most recent fetch time across all sources"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        cursor.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'fetch_history'
            AND COLUMN_NAME = 'last_fetch_date'
        """)
        has_column = cursor.fetchone() is not None
        
        if not has_column:
            cursor.close()
            conn.close()
            return None
            
        cursor.execute("""
            SELECT MAX(last_fetch_date) as last_fetch
            FROM fetch_history
            WHERE fetch_type = 'incremental'
        """)
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            if isinstance(result, dict):
                last_fetch = result.get('last_fetch', result.get('MAX(last_fetch_date)'))
            elif hasattr(result, '__getitem__'):
                last_fetch = result[0] if len(result) > 0 else None
            else:
                last_fetch = None
            return last_fetch if last_fetch else None
        return None

    def add_advisory(self, name: str, topic: str, sent_date: str, sent_by: str) -> int:
        """Add a new advisory"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        now = datetime.utcnow().isoformat()
        
        cursor.execute(f"""
            INSERT INTO advisories (name, topic, sent_date, sent_by, created_at, updated_at)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param})
        """, (name, topic, sent_date, sent_by, now, now))
        
        advisory_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        return advisory_id

    def get_advisories(self, sent_only: bool = False) -> List[Dict[str, Any]]:
        """Get all advisories, optionally filter to sent only"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        if sent_only:
            cursor.execute("""
                SELECT DISTINCT a.*, COUNT(ac.id) as client_count
                FROM advisories a
                LEFT JOIN advisory_clients ac ON a.id = ac.advisory_id
                WHERE EXISTS (SELECT 1 FROM advisory_clients WHERE advisory_id = a.id)
                GROUP BY a.id
                ORDER BY a.sent_date DESC
            """)
        else:
            cursor.execute("""
                SELECT a.*, COUNT(ac.id) as client_count
                FROM advisories a
                LEFT JOIN advisory_clients ac ON a.id = ac.advisory_id
                GROUP BY a.id
                ORDER BY a.created_at DESC
            """)
            
        rows = cursor.fetchall()
        result = []
        for row in rows:
            if isinstance(row, dict):
                result.append(row)
            elif hasattr(row, 'keys'):
                try:
                    result.append(dict(row))
                except (TypeError, ValueError):
                    result.append({key: row[key] for key in row.keys()})
            elif hasattr(row, '__iter__') and not isinstance(row, (str, bytes)):
                try:
                    if hasattr(cursor, 'description') and cursor.description:
                        columns = [desc[0] for desc in cursor.description]
                        result.append(dict(zip(columns, row)))
                except Exception:
                    continue
        
        cursor.close()
        conn.close()
        return result

    def get_advisory_clients(self, advisory_id: int) -> List[Dict[str, Any]]:
        """Get clients for a specific advisory"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            SELECT c.id, c.name, ac.sent_date
            FROM advisory_clients ac
            JOIN clients c ON ac.client_id = c.id
            WHERE ac.advisory_id = {param}
        """, (advisory_id,))
        
        rows = cursor.fetchall()
        result = []
        for row in rows:
            row_dict = None
            if isinstance(row, dict):
                row_dict = row
            elif hasattr(row, 'keys'):
                try:
                    row_dict = dict(row)
                except (TypeError, ValueError):
                    try:
                        row_dict = {key: row[key] for key in row.keys()}
                    except:
                        logger.warning(f"Could not convert row to dict: {type(row)}")
                        continue
            elif hasattr(row, '__iter__') and not isinstance(row, (str, bytes)):
                try:
                    if hasattr(cursor, 'description') and cursor.description:
                        columns = [desc[0] for desc in cursor.description]
                        row_dict = dict(zip(columns, row))
                    else:
                        row_dict = {
                            'id': row[0] if len(row) > 0 else None,
                            'name': row[1] if len(row) > 1 else '',
                            'sent_date': row[2] if len(row) > 2 else ''
                        }
                except Exception as e:
                    logger.warning(f"Error converting row to dict: {e}")
                    continue
            
            if row_dict:
                if row_dict.get('name'):
                    row_dict['name'] = str(row_dict['name']).strip()
                else:
                    row_dict['name'] = ''
                result.append(row_dict)
                
        cursor.close()
        conn.close()
        return result

    def add_advisory_client(self, advisory_id: int, client_id: int, sent_date: str):
        """Mark advisory as sent to a client"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            INSERT INTO advisory_clients (advisory_id, client_id, sent_date)
            VALUES ({param}, {param}, {param})
            ON DUPLICATE KEY UPDATE sent_date = VALUES(sent_date)
        """, (advisory_id, client_id, sent_date))
        
        conn.commit()
        cursor.close()
        conn.close()

    def remove_advisory_client(self, advisory_id: int, client_id: int):
        """Remove client from advisory"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            DELETE FROM advisory_clients
            WHERE advisory_id = {param} AND client_id = {param}
        """, (advisory_id, client_id))
        
        conn.commit()
        cursor.close()
        conn.close()

    def update_advisory(self, advisory_id: int, name: str, topic: str, sent_date: str, sent_by: str):
        """Update an advisory"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            UPDATE advisories
            SET name = {param}, topic = {param}, sent_date = {param}, sent_by = {param}
            WHERE id = {param}
        """, (name, topic, sent_date, sent_by, advisory_id))
        
        conn.commit()
        cursor.close()
        conn.close()

    def delete_advisory(self, advisory_id: int):
        """Delete an advisory"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"DELETE FROM advisories WHERE id = {param}", (advisory_id,))
        
        conn.commit()
        cursor.close()
        conn.close()

    def get_clients(self) -> List[Dict[str, Any]]:
        """Get all clients"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        cursor.execute("SELECT id, name, created_at FROM clients ORDER BY id")
        rows = cursor.fetchall()
        result = []
        
        for row in rows:
            row_dict = None
            if isinstance(row, dict):
                row_dict = row
            elif hasattr(row, 'keys'):
                try:
                    row_dict = dict(row)
                except (TypeError, ValueError):
                    try:
                        row_dict = {key: row[key] for key in row.keys()}
                    except:
                        logger.warning(f"Could not convert row to dict: {type(row)}")
                        continue
            elif hasattr(row, '__iter__') and not isinstance(row, (str, bytes)):
                try:
                    if hasattr(cursor, 'description') and cursor.description:
                        columns = [desc[0] for desc in cursor.description]
                        row_dict = dict(zip(columns, row))
                    else:
                        row_dict = {
                            'id': row[0] if len(row) > 0 else None,
                            'name': row[1] if len(row) > 1 else '',
                            'created_at': row[2] if len(row) > 2 else ''
                        }
                except Exception as e:
                    logger.warning(f"Error converting row to dict: {e}, row type: {type(row)}")
                    continue
            else:
                logger.warning(f"Unexpected row type in get_clients: {type(row)}")
                continue
                
            if row_dict:
                if row_dict.get('name'):
                    row_dict['name'] = str(row_dict['name']).strip()
                else:
                    row_dict['name'] = ''
                result.append(row_dict)
        
        cursor.close()
        conn.close()
        return result

    def add_client(self, name: str) -> int:
        """Add a new client - prevents duplicates by name"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        now = datetime.utcnow().isoformat()
        
        cursor.execute(f"SELECT id FROM clients WHERE name = {param}", (name,))
        existing = cursor.fetchone()
        
        if existing:
            if isinstance(existing, dict):
                client_id = existing.get('id')
            else:
                client_id = existing[0] if len(existing) > 0 else None
            cursor.close()
            conn.close()
            return client_id if client_id else 0
            
        cursor.execute(f"""
            INSERT INTO clients (name, created_at)
            VALUES ({param}, {param})
        """, (name, now))
        
        client_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        return client_id

    def update_client(self, client_id: int, name: str):
        """Update client name"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"""
            UPDATE clients SET name = {param} WHERE id = {param}
        """, (name, client_id))
        
        conn.commit()
        cursor.close()
        conn.close()

    def delete_client(self, client_id: int):
        """Delete a client"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        param = self._get_param_placeholder()
        
        cursor.execute(f"DELETE FROM clients WHERE id = {param}", (client_id,))
        
        conn.commit()
        cursor.close()
        conn.close()

    def init_default_clients(self):
        """Initialize 12 default clients"""
        default_clients = [
            "Client 1", "Client 2", "Client 3", "Client 4", "Client 5", "Client 6",
            "Client 7", "Client 8", "Client 9", "Client 10", "Client 11", "Client 12"
        ]
        for client_name in default_clients:
            self.add_client(client_name)

    def queue_for_ai_processing(self, item_type: str, item_id: int, priority: int = 5):
        """Add item to AI processing queue"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        try:
            cursor.execute("""
                INSERT INTO ai_processing_queue (item_type, item_id, priority)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE priority = VALUES(priority)
            """, (item_type, item_id, priority))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error queuing AI processing: {e}")
        finally:
            cursor.close()
            conn.close()

    def update_ai_summary(self, item_type: str, item_id: int, ai_data: Dict):
        """Update article with AI-generated summary"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        try:
            table = 'news_articles' if item_type == 'news' else 'intelligence_items'
            
            cursor.execute(f"""
                UPDATE {table}
                SET ai_summary = %s,
                    ai_summary_status = 'completed',
                    ai_summary_created_at = NOW(),
                    ai_key_points = %s,
                    ai_sentiment = %s,
                    ai_category_tags = %s
                WHERE id = %s
            """, (
                ai_data.get('summary'),
                json.dumps(ai_data.get('key_points', [])),
                ai_data.get('sentiment'),
                json.dumps(ai_data.get('category_tags', [])),
                item_id
            ))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error updating AI summary: {e}")
        finally:
            cursor.close()
            conn.close()

    def get_pending_ai_items(self, limit: int = 10) -> List[Dict]:
        """Get items pending AI processing"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        try:
            cursor.execute("""
                SELECT q.*, 
                    CASE 
                        WHEN q.item_type = 'news' THEN n.title
                        ELSE i.title
                    END as title,
                    CASE 
                        WHEN q.item_type = 'news' THEN n.description
                        ELSE i.description
                    END as description,
                    CASE 
                        WHEN q.item_type = 'news' THEN n.source
                        ELSE i.source
                    END as source
                FROM ai_processing_queue q
                LEFT JOIN news_articles n ON q.item_type = 'news' AND q.item_id = n.id
                LEFT JOIN intelligence_items i ON q.item_type = 'intelligence' AND q.item_id = i.id
                WHERE q.status = 'queued' AND q.retry_count < 3
                ORDER BY q.priority DESC, q.created_at ASC
                LIMIT %s
            """, (limit,))
            
            return cursor.fetchall()
            
        except Exception as e:
            logger.error(f"Error getting pending AI items: {e}")
            return []
        finally:
            cursor.close()
            conn.close()
    def update_queue_status(self, queue_id: int, status: str, error_message: str = None):
        """Update AI processing queue status"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        try:
            if error_message:
                cursor.execute("""
                    UPDATE ai_processing_queue
                    SET status = %s, error_message = %s, processed_at = NOW()
                    WHERE id = %s
                """, (status, error_message, queue_id))
            else:
                cursor.execute("""
                    UPDATE ai_processing_queue
                    SET status = %s, processed_at = NOW()
                    WHERE id = %s
                """, (status, queue_id))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error updating queue status: {e}")
        finally:
            cursor.close()
            conn.close()

    def get_article_with_ai(self, article_id: int, include_ai: bool = True) -> Optional[Dict]:
        """Get article with AI summary data"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        try:
            if include_ai:
                cursor.execute("""
                    SELECT *, ai_summary, ai_key_points, ai_sentiment, ai_category_tags, ai_summary_status
                    FROM news_articles
                    WHERE id = %s
                """, (article_id,))
            else:
                cursor.execute("""
                    SELECT *
                    FROM news_articles
                    WHERE id = %s
                """, (article_id,))
            
            result = cursor.fetchone()
            if result:
                if isinstance(result, dict):
                    return result
                else:
                    # Convert tuple to dict if needed
                    columns = [desc[0] for desc in cursor.description]
                    return dict(zip(columns, result))
            return None
            
        except Exception as e:
            logger.error(f"Error getting article with AI: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    def get_ai_processing_stats(self) -> Dict:
        """Get AI processing statistics"""
        conn = self.get_connection()
        cursor = self.get_cursor(conn)
        
        try:
            cursor.execute("""
                SELECT 
                    status,
                    COUNT(*) as count
                FROM ai_processing_queue
                GROUP BY status
            """)
            
            status_counts = {}
            for row in cursor.fetchall():
                if isinstance(row, dict):
                    status_counts[row['status']] = row['count']
                else:
                    status_counts[row[0]] = row[1]
            
            # Get total articles with AI summaries
            cursor.execute("""
                SELECT COUNT(*) as count FROM news_articles WHERE ai_summary IS NOT NULL
            """)
            result = cursor.fetchone()
            news_with_ai = result['count'] if isinstance(result, dict) else result[0]
            
            cursor.execute("""
                SELECT COUNT(*) as count FROM intelligence_items WHERE ai_summary IS NOT NULL
            """)
            result = cursor.fetchone()
            intel_with_ai = result['count'] if isinstance(result, dict) else result[0]
            
            return {
                'queue_stats': status_counts,
                'articles_with_ai': news_with_ai,
                'intelligence_with_ai': intel_with_ai,
                'total_with_ai': news_with_ai + intel_with_ai
            }
            
        except Exception as e:
            logger.error(f"Error getting AI processing stats: {e}")
            return {}
        finally:
            cursor.close()
            conn.close()