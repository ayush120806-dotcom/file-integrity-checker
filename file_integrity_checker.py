import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

DEFAULT_HASH_DB = "file_hashes.json"
CHUNK_SIZE = 4096


def calculate_hash(file_path):
    """Return the SHA-256 hash for a file."""
    sha256 = hashlib.sha256()

    with file_path.open("rb") as file_handle:
        while chunk := file_handle.read(CHUNK_SIZE):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_target(target_path, database_path):
    """Build a mapping of file paths to SHA-256 hashes for a file or directory."""
    file_hashes = {}
    excluded_file = database_path.resolve()

    if target_path.is_file():
        if target_path.resolve() != excluded_file:
            file_hashes[target_path.name] = calculate_hash(target_path)
        return file_hashes

    for file_path in target_path.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.resolve() == excluded_file:
            continue

        relative_path = file_path.relative_to(target_path).as_posix()
        file_hashes[relative_path] = calculate_hash(file_path)

    return dict(sorted(file_hashes.items()))


def save_hashes(hashes, database_path):
    """Save hash values to a JSON file."""
    with database_path.open("w", encoding="utf-8") as file_handle:
        json.dump(hashes, file_handle, indent=4)


def load_hashes(database_path):
    """Load saved hash values from the JSON database."""
    if not database_path.exists():
        return {}

    with database_path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def compare_hashes(old_hashes, new_hashes):
    """Return added, modified, and deleted file lists."""
    added_files = sorted(path for path in new_hashes if path not in old_hashes)
    modified_files = sorted(
        path for path, hash_value in new_hashes.items()
        if path in old_hashes and old_hashes[path] != hash_value
    )
    deleted_files = sorted(path for path in old_hashes if path not in new_hashes)

    return added_files, modified_files, deleted_files


def print_report(added_files, modified_files, deleted_files):
    """Print a readable integrity report."""
    print("\nFile Integrity Report")
    print("-" * 30)
    print("Scan Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if not added_files and not modified_files and not deleted_files:
        print("No changes detected.")
        return

    if added_files:
        print("\nNew Files:")
        for file_path in added_files:
            print(f"  + {file_path}")

    if modified_files:
        print("\nModified Files:")
        for file_path in modified_files:
            print(f"  * {file_path}")

    if deleted_files:
        print("\nDeleted Files:")
        for file_path in deleted_files:
            print(f"  - {file_path}")


def initialize_hash_database(target_path, database_path):
    """Create a fresh baseline of file hashes."""
    hashes = scan_target(target_path, database_path)
    save_hashes(hashes, database_path)
    print(f"Baseline created for {len(hashes)} file(s).")
    print(f"Hash database saved to: {database_path}")


def check_integrity(target_path, database_path, update_baseline=False):
    """Compare the current directory state with the stored baseline."""
    old_hashes = load_hashes(database_path)
    if not old_hashes:
        print("No baseline found. Run the script with --init first.")
        return False

    new_hashes = scan_target(target_path, database_path)
    added_files, modified_files, deleted_files = compare_hashes(old_hashes, new_hashes)

    print_report(added_files, modified_files, deleted_files)

    if update_baseline:
        save_hashes(new_hashes, database_path)
        print("\nBaseline updated.")

    return not any((added_files, modified_files, deleted_files))


def watch_target(target_path, database_path, interval):
    """Continuously monitor a file or directory for integrity changes."""
    print(f"Watching {target_path} every {interval} second(s). Press Ctrl+C to stop.")

    try:
        while True:
            check_integrity(target_path, database_path, update_baseline=False)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


def prompt_for_target():
    """Ask the user for the file or folder to monitor."""
    user_input = input("Enter the full path of the file or folder to check: ").strip()
    if not user_input:
        raise ValueError("No path was entered.")
    return Path(user_input).expanduser().resolve()


def build_parser():
    parser = argparse.ArgumentParser(
        description="Monitor file integrity by calculating and comparing SHA-256 hashes."
    )
    parser.add_argument(
        "directory",
        nargs="?",
        help="File or directory to scan. If omitted, the script asks for a path.",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_HASH_DB,
        help=f"Path to the hash database file. Defaults to {DEFAULT_HASH_DB}.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Create or overwrite the baseline hash database.",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update the stored baseline after checking integrity.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuously monitor the directory for changes.",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="Seconds between scans in watch mode. Defaults to 5.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        target_path = Path(args.directory).resolve() if args.directory else prompt_for_target()
    except ValueError as error:
        parser.error(str(error))

    database_path = Path(args.db).resolve()

    if not target_path.exists():
        parser.error("The provided path does not exist.")

    if args.interval < 1:
        parser.error("--interval must be at least 1 second.")

    if args.init:
        initialize_hash_database(target_path, database_path)
        return

    if args.watch:
        watch_target(target_path, database_path, args.interval)
        return

    check_integrity(target_path, database_path, update_baseline=args.update)


if __name__ == "__main__":
    main()
