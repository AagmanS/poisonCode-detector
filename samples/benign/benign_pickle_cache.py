"""Legitimate pickle usage for local caching - benign code."""

import pickle
import os
from datetime import datetime, timedelta


CACHE_FILE = 'cache.pkl'


def load_cache():
    """Load cache from disk."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                return pickle.load(f)
        except (IOError, pickle.UnpicklingError):
            return {}
    return {}


def save_cache(cache_data):
    """Save cache to disk."""
    with open(CACHE_FILE, 'wb') as f:
        pickle.dump(cache_data, f)


def get_cached_result(key, compute_func):
    """Get result from cache or compute it."""
    cache = load_cache()
    
    if key in cache:
        result, timestamp = cache[key]
        # Check if cached result is still fresh (less than 1 hour old)
        if datetime.now() - timestamp < timedelta(hours=1):
            print(f"Cache hit for {key}")
            return result
    
    # Compute new result
    print(f"Cache miss for {key}, computing...")
    result = compute_func()
    cache[key] = (result, datetime.now())
    save_cache(cache)
    
    return result


def expensive_computation():
    """Simulate expensive computation."""
    total = sum(i * i for i in range(1000000))
    return total


def main():
    """Main function."""
    result = get_cached_result('expensive_sum', expensive_computation)
    print(f"Result: {result}")


if __name__ == '__main__':
    main()
