import time
import logging
from models import Database
from ai_service import GeminiAIService
import config

logger = logging.getLogger(__name__)

class AIWorker:
    def __init__(self):
        self.db = Database()
        self.ai_service = GeminiAIService()
        self.running = False
        
    def start(self):
        self.running = True
        logger.info("AI Worker started")
        
        while self.running:
            try:
                # Get pending items
                pending_items = self.db.get_pending_ai_items(config.AI_BATCH_SIZE)
                
                if not pending_items:
                    time.sleep(30)  # Wait 30 seconds if no items
                    continue
                
                logger.info(f"Processing {len(pending_items)} items")
                
                # Process each item
                for item in pending_items:
                    self.process_item(item)
                    time.sleep(config.AI_RATE_LIMIT_DELAY)
                    
            except Exception as e:
                logger.error(f"AI Worker error: {e}")
                time.sleep(60)  # Wait 1 minute on error
                
    def process_item(self, item):
        try:
            # Mark as processing
            self.db.update_queue_status(item['id'], 'processing')
            
            # Generate AI summary
            result = self.ai_service.summarize_article(
                item['title'],
                item['description'],
                item['source']
            )
            
            if result['success']:
                # Update database with AI data
                self.db.update_ai_summary(
                    item['item_type'],
                    item['item_id'],
                    result['data']
                )
                
                # Mark as completed
                self.db.update_queue_status(item['id'], 'completed')
                logger.info(f"Processed {item['item_type']} {item['item_id']}")
                
            else:
                # Mark as failed
                self.db.update_queue_status(item['id'], 'failed', result['error'])
                logger.error(f"Failed to process {item['item_type']} {item['item_id']}: {result['error']}")
                
        except Exception as e:
            logger.error(f"Error processing item {item['id']}: {e}")
            self.db.update_queue_status(item['id'], 'failed', str(e))
            
    def stop(self):
        self.running = False
        logger.info("AI Worker stopped")

if __name__ == "__main__":
    worker = AIWorker()
    try:
        worker.start()
    except KeyboardInterrupt:
        worker.stop()
