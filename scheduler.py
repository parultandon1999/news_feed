from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from models import Database
from fetchers import fetch_all_sources
import logging
import time
import atexit

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = Database()
scheduler = BackgroundScheduler()

def fetch_and_store(historical: bool = False, category_filter: str = None, hours: int = None):
    from job_tracker import job_tracker
    logger.info("Starting scheduled data fetch...")
    start_time = time.time()
    
    # Default to 24 hours if not specified
    if hours is None:
        hours = 24
    
    logger.info(f"Fetch parameters: historical={historical}, hours={hours}, category_filter={category_filter}")
    
    try:
        if job_tracker.is_job_running():
            job_tracker.update_job(progress=10, message='Fetching RSS feeds from security websites...')
            
        items = fetch_all_sources(historical=historical, category_filter=category_filter, hours=hours)
        
        if job_tracker.is_job_running():
            job_tracker.update_job(progress=30, message=f'Fetched {len(items)} items from RSS feeds. Storing in database...')
            
        inserted = 0
        updated = 0
        source_stats = {}
        errors = []
        total_items = len(items)
        cancelled = False
        
        if items:
            try:
                if job_tracker.is_job_running():
                    job_tracker.update_job(progress=40, message=f'Batch inserting {len(items)} items...')
                    
                batch_inserted, batch_updated, batch_errors = db.batch_insert_items(items)
                inserted = batch_inserted
                updated = batch_updated
                
                if batch_errors > 0:
                    logger.warning(f"Encountered {batch_errors} errors during batch insert")
                    errors.append(f"{batch_errors} items failed during batch insert")
                :
                # Calculate stats for history
                for item in items:
                    source_name = item.get('source', 'Unknown')
                    category = item.get('category', 'unknown')
                    
                    if category == 'cve' and source_name == 'NVD':
                        source_key = 'CVE'
                    elif category == 'news':
                        source_key = f"NEWS_{source_name}"
                    elif category == 'cert-in':
                        source_key = 'CERT-In'
                    elif category == 'cert':
                        source_key = f"CERT_{source_name}"
                    elif category == 'exploit' and source_name == 'Exploit-DB':
                        source_key = 'Exploit-DB'
                    else:
                        source_key = f"{category.upper()}_{source_name}"
                        
                    if source_key not in source_stats:
                        source_stats[source_key] = {'fetched': 0, 'inserted': 0, 'updated': 0}
                        
                    source_stats[source_key]['fetched'] += 1
                    # Rough attribution of inserts/updates per source since batch doesn't return per-item details
                    source_stats[source_key]['inserted'] += batch_inserted // max(1, len(items))
                    source_stats[source_key]['updated'] += batch_updated // max(1, len(items))
                    
            except Exception as e:
                logger.error(f"Batch insert failed: {e}", exc_info=True)
                errors.append(f"Batch insert failed: {str(e)}")
                logger.warning("Falling back to individual inserts...")
                
                for idx, item in enumerate(items):
                    try:
                        result = db.insert_item(item)
                        if result:
                            inserted += 1
                        else:
                            updated += 1
                    except Exception as e2:
                        logger.error(f"Error inserting item: {e2}")
                        continue

        if cancelled:
            logger.info(f"Job cancelled by user. Successfully saved {inserted} new and {updated} updated items before cancellation.")
            if job_tracker.is_job_running():
                job_tracker.complete_job(success=True, message=f'Cancelled: {inserted} new, {updated} updated items saved')
            return

        if not cancelled:
            fetch_type = 'historical' if historical else 'incremental'
            for source_key, stats in source_stats.items():
                try:
                    db.update_fetch_history(
                        source_key,
                        fetch_type=fetch_type,
                        items_fetched=stats['fetched'],
                        items_inserted=stats['inserted'],
                        items_updated=stats['updated']
                    )
                except Exception as e:
                    logger.warning(f"Error updating fetch history for {source_key}: {e}")

        if errors:
            logger.warning(f"Encountered {len(errors)} errors during insert. First error: {errors[0]}")

        elapsed = time.time() - start_time
        
        if not cancelled:
            if job_tracker.is_job_running():
                job_tracker.update_job(progress=90, message=f'Finalizing: {len(items)} fetched, {inserted} inserted, {updated} updated')
                
            logger.info(f"Data fetch completed: {len(items)} fetched, {inserted} inserted, {updated} updated in {elapsed:.2f}s")
            logger.info(f"Total items in database: {db.get_total_count()}")
            
            if job_tracker.is_job_running():
                job_tracker.update_job(progress=100, message=f'Completed: {inserted} new, {updated} updated')

    except Exception as e:
        logger.error(f"Error in scheduled fetch: {e}", exc_info=True)

def start_scheduler(auto_fetch: bool = False):
    if scheduler.running:
        logger.info("Scheduler is already running")
        return

    scheduler.add_job(
        func=fetch_and_store,
        trigger=IntervalTrigger(minutes=30),
        id='data_fetch',
        name='Fetch cybersecurity intelligence',
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started - data will be fetched every 30 minutes")
    
    if auto_fetch:
        logger.info("Running initial data fetch...")
        # Re-import to avoid circular dependency issues during startup if any
        from models import Database
        db_instance = Database()
        needs_historical = db_instance.should_fetch_historical('CVE')
        
        if needs_historical:
            logger.info("First run detected - fetching historical data (this may take several minutes)...")
            fetch_and_store(historical=True)
        else:
            logger.info("Incremental fetch - getting last 24 hours only...")
            fetch_and_store(historical=False)

    atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    start_scheduler()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down scheduler...")
        scheduler.shutdown()
