import threading
import time
from datetime import datetime
from typing import Optional, Dict, Any


class JobTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._current_job: Optional[Dict[str, Any]] = None

    def start_job(self, job_type: str, description: str = "") -> bool:
        with self._lock:
            if self._current_job and self._current_job.get('status') == 'running':
                return False
            self._current_job = {
                'type': job_type,
                'description': description,
                'status': 'running',
                'started_at': datetime.utcnow().isoformat(),
                'progress': 0,
                'message': 'Initializing...'
            }
            return True

    def update_job(self, progress: int = None, message: str = None):
        with self._lock:
            if self._current_job and self._current_job.get('status') == 'running':
                if progress is not None:
                    self._current_job['progress'] = progress
                if message is not None:
                    self._current_job['message'] = message

    def complete_job(self, success: bool = True, message: str = None):
        with self._lock:
            if self._current_job:
                self._current_job['status'] = 'completed' if success else 'failed'
                self._current_job['completed_at'] = datetime.utcnow().isoformat()
                self._current_job['progress'] = 100
                if message:
                    self._current_job['message'] = message

    def cancel_job(self):
        with self._lock:
            if self._current_job and self._current_job.get('status') == 'running':
                self._current_job['status'] = 'cancelled'
                self._current_job['completed_at'] = datetime.utcnow().isoformat()
                self._current_job['message'] = 'Cancelled by user'

    def get_current_job(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._current_job.copy() if self._current_job else None

    def is_job_running(self) -> bool:
        with self._lock:
            return self._current_job is not None and self._current_job.get('status') == 'running'

    def clear_completed_job(self):
        with self._lock:
            if self._current_job and self._current_job.get('status') in ['completed', 'failed', 'cancelled']:
                completed_at = self._current_job.get('completed_at')
                if completed_at:
                    completed_time = datetime.fromisoformat(completed_at)
                    if (datetime.utcnow() - completed_time).total_seconds() > 300:
                        self._current_job = None


job_tracker = JobTracker()