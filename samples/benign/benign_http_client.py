"""Legitimate HTTP client - benign code using requests and subprocess."""

import requests
import subprocess


def fetch_api_data(api_url):
    """Fetch data from a public API."""
    try:
        response = requests.get(api_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return None


def run_git_status(repo_path):
    """Run git status command in a repository."""
    try:
        result = subprocess.run(
            ['git', 'status'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Git command failed: {e}")
        return None


def main():
    """Main function."""
    # Example legitimate API call
    data = fetch_api_data('https://api.github.com/users/github')
    if data:
        print(f"Fetched data: {data.get('name', 'Unknown')}")
    
    # Example legitimate subprocess use
    status = run_git_status('.')
    if status:
        print(f"Git status:\\n{status}")


if __name__ == '__main__':
    main()
