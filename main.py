import logging
import os

from app import app
import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    logger.info(f"Starting {config.PROJECT_NAME}")
    logger.info(f"Server: {config.HOST}:{config.PORT}")
    
    if config.DEBUG:
        logger.warning("DEBUG mode enabled - not suitable for production")
        app.run(host=config.HOST, port=config.PORT, debug=True, use_reloader=False)
    else:
        from waitress import serve
        logger.info("Starting production server with Waitress")
        serve(app, host=config.HOST, port=config.PORT, threads=4)


if __name__ == '__main__':
    main()