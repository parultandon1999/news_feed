import sys
import logging
from typing import List, Tuple
import config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try importing mysql.connector, fall back to pymysql
try:
    import mysql.connector
    from mysql.connector import Error
    MYSQL_LIBRARY = 'mysql.connector'
    mysql_connector_module = mysql.connector
except ImportError:
    try:
        import pymysql
        MYSQL_LIBRARY = 'pymysql'
        mysql_connector_module = pymysql
        Error = Exception
    except ImportError:
        logger.error("=" * 80)
        logger.error("CRITICAL: MySQL connector not found!")
        logger.error("=" * 80)
        logger.error("Please install one of:")
        logger.error("  pip install mysql-connector-python")
        logger.error("  OR")
        logger.error("  pip install pymysql")
        logger.error("=" * 80)
        sys.exit(1)


class DatabaseCleaner:
    """Database cleaner that removes all data while preserving structure"""
    
    def __init__(self):
        self.mysql_config = config.MYSQL_CONFIG.copy()
        self.connection = None
        self.cursor = None
        
        # All tables in the database (order matters for foreign key constraints)
        self.tables = [
            'advisory_clients',      # Has foreign keys to advisories and clients
            'cve_change_history',    # Has foreign key to intelligence_items
            'cve_cpe_mapping',       # Has foreign key to intelligence_items
            'cve_references',        # Has foreign key to intelligence_items
            'advisories',            # Referenced by advisory_clients
            'clients',               # Referenced by advisory_clients
            'intelligence_items',    # Main data table
            'news_articles',         # News data table
            'fetch_history',         # Fetch tracking
            'settings',              # Application settings
            'source_settings',       # Source configurations
            'custom_feeds',          # Custom feed configurations
            'data_sources'           # Data source configurations
        ]
    
    def connect(self) -> bool:
        """Connect to MySQL database"""
        try:
            if MYSQL_LIBRARY == 'mysql.connector':
                self.connection = mysql_connector_module.connect(**self.mysql_config)
                self.cursor = self.connection.cursor(dictionary=True, buffered=True)
            else:
                self.connection = mysql_connector_module.connect(
                    host=self.mysql_config['host'],
                    port=self.mysql_config['port'],
                    user=self.mysql_config['user'],
                    password=self.mysql_config['password'],
                    database=self.mysql_config['database'],
                    charset=self.mysql_config.get('charset', 'utf8mb4')
                )
                self.cursor = self.connection.cursor(pymysql.cursors.DictCursor)
            
            logger.info(f"✓ Connected to MySQL database using {MYSQL_LIBRARY}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.cursor:
            try:
                self.cursor.close()
            except:
                pass
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
        logger.info("✓ Database connection closed")
    
    def get_existing_tables(self) -> List[str]:
        """Get list of existing tables in the database"""
        try:
            self.cursor.execute("SHOW TABLES")
            results = self.cursor.fetchall()
            
            if MYSQL_LIBRARY == 'mysql.connector':
                table_key = f"Tables_in_{self.mysql_config['database']}"
                existing_tables = [row[table_key] for row in results]
            else:
                # For pymysql, results are tuples
                existing_tables = [list(row.values())[0] for row in results]
            
            return existing_tables
            
        except Exception as e:
            logger.error(f"Error getting table list: {e}")
            return []
    
    def get_table_row_count(self, table_name: str) -> int:
        """Get row count for a table"""
        try:
            self.cursor.execute(f"SELECT COUNT(*) as count FROM `{table_name}`")
            result = self.cursor.fetchone()
            return result['count'] if result else 0
        except Exception as e:
            logger.warning(f"Could not get row count for {table_name}: {e}")
            return 0
    
    def clear_table(self, table_name: str) -> Tuple[bool, int]:
        """Clear all data from a specific table"""
        try:
            # Get row count before clearing
            row_count = self.get_table_row_count(table_name)
            
            if row_count == 0:
                logger.info(f"  {table_name}: Already empty")
                return True, 0
            
            # Clear the table
            self.cursor.execute(f"DELETE FROM `{table_name}`")
            
            # Reset auto-increment counter if table has an auto-increment column
            try:
                self.cursor.execute(f"ALTER TABLE `{table_name}` AUTO_INCREMENT = 1")
            except Exception:
                # Not all tables have auto-increment, ignore error
                pass
            
            logger.info(f"  {table_name}: Cleared {row_count:,} rows")
            return True, row_count
            
        except Exception as e:
            logger.error(f"  {table_name}: Error - {e}")
            return False, 0
    
    def clear_all_data(self) -> bool:
        """Clear all data from all tables"""
        if not self.connect():
            return False
        
        try:
            logger.info("Starting database cleanup...")
            logger.info("=" * 60)
            
            # Get existing tables
            existing_tables = self.get_existing_tables()
            logger.info(f"Found {len(existing_tables)} tables in database")
            
            # Disable foreign key checks
            logger.info("Disabling foreign key checks...")
            self.cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            
            total_rows_cleared = 0
            tables_cleared = 0
            tables_with_errors = 0
            
            # Clear each table
            logger.info("Clearing tables:")
            for table_name in self.tables:
                if table_name in existing_tables:
                    success, row_count = self.clear_table(table_name)
                    if success:
                        total_rows_cleared += row_count
                        tables_cleared += 1
                    else:
                        tables_with_errors += 1
                else:
                    logger.info(f"  {table_name}: Table does not exist, skipping")
            
            # Clear any additional tables not in our list
            for table_name in existing_tables:
                if table_name not in self.tables:
                    logger.info(f"  {table_name}: Additional table found, clearing...")
                    success, row_count = self.clear_table(table_name)
                    if success:
                        total_rows_cleared += row_count
                        tables_cleared += 1
                    else:
                        tables_with_errors += 1
            
            # Re-enable foreign key checks
            logger.info("Re-enabling foreign key checks...")
            self.cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            
            # Commit all changes
            self.connection.commit()
            
            # Summary
            logger.info("=" * 60)
            logger.info("DATABASE CLEANUP COMPLETE")
            logger.info("=" * 60)
            logger.info(f"Tables processed: {len(existing_tables)}")
            logger.info(f"Tables cleared successfully: {tables_cleared}")
            logger.info(f"Tables with errors: {tables_with_errors}")
            logger.info(f"Total rows deleted: {total_rows_cleared:,}")
            logger.info("=" * 60)
            
            if tables_with_errors == 0:
                logger.info("✓ All data cleared successfully!")
                return True
            else:
                logger.warning(f"⚠ Completed with {tables_with_errors} errors")
                return False
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            try:
                self.connection.rollback()
            except:
                pass
            return False
        finally:
            self.disconnect()
    
    def confirm_action(self) -> bool:
        """Ask user for confirmation before clearing database"""
        print("=" * 80)
        print("WARNING: DATABASE CLEAR OPERATION")
        print("=" * 80)
        print("This will permanently delete ALL data from the following database:")
        print(f"  Host: {self.mysql_config['host']}:{self.mysql_config['port']}")
        print(f"  Database: {self.mysql_config['database']}")
        print(f"  User: {self.mysql_config['user']}")
        print()
        print("ALL DATA WILL BE PERMANENTLY LOST!")
        print("This action cannot be undone.")
        print()
        print("Tables that will be cleared:")
        for table in self.tables:
            print(f"  - {table}")
        print()
        
        while True:
            response = input("Are you sure you want to continue? (type 'YES' to confirm): ").strip()
            if response == 'YES':
                return True
            elif response.lower() in ['no', 'n', 'exit', 'quit', '']:
                return False
            else:
                print("Please type 'YES' to confirm or 'no' to cancel.")


def main():
    """Main function"""
    print("CyberFeed Database Clear Script")
    print("=" * 40)
    
    cleaner = DatabaseCleaner()
    
    # Ask for confirmation
    if not cleaner.confirm_action():
        print("Operation cancelled by user.")
        sys.exit(0)
    
    print("\nStarting database clear operation...")
    
    # Clear the database
    success = cleaner.clear_all_data()
    
    if success:
        print("\n✓ Database cleared successfully!")
        print("The database is now empty but the table structure is preserved.")
        print("You can now run the application to reinitialize with fresh data.")
    else:
        print("\n✗ Database clear completed with errors.")
        print("Please check the log messages above for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()