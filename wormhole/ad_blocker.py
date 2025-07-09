from .logger import logger
from .safeguards import DEFAULT_ALLOWLIST
from pathlib import Path
import aiohttp
import aiosqlite
import asyncio
import re

# A curated list of popular and well-maintained ad-block lists
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
]

# Regex to find domains in various blocklist formats
# Handles formats like: 0.0.0.0 example.com, ||example.com^, and just example.com
DOMAIN_REGEX = re.compile(
    r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+([a-zA-Z0-9.-]+)|"  # For hosts file format
    r"^\|\|([a-zA-Z0-9.-]+)\^"  # For Adblock Plus format
)


async def _fetch_list(session: aiohttp.ClientSession, url: str) -> str:
    """Fetches the content of a single blocklist URL with a retry mechanism."""
    max_retries = 3
    timeout = aiohttp.ClientTimeout(total=15)  # seconds
    for attempt in range(max_retries):
        try:
            logger.info(
                f"Fetching (Attempt {attempt + 1}/{max_retries}): {url}"
            )
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    logger.warning(
                        f"Failed to fetch {url} on attempt {attempt + 1} - Status: {response.status}"
                    )
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching {url} on attempt {attempt + 1}")
        except Exception as e:
            logger.warning(
                f"Error fetching {url} on attempt {attempt + 1}: {e}"
            )

        if attempt < max_retries - 1:
            await asyncio.sleep(2)  # Wait 2 seconds before retrying

    logger.error(f"Failed to fetch {url} after {max_retries} attempts.")
    return ""


def _parse_domains_from_content(content: str) -> set[str]:
    """Parses a block of text and extracts all valid domains."""
    domains: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue

        match = DOMAIN_REGEX.match(line)
        if match:
            # The regex has two capture groups, one will be None
            domain = match.group(1) or match.group(2)
            if domain:
                domains.add(domain.lower())
        # Fallback for simple domain lists
        elif "." in line and " " not in line:
            domains.add(line.lower())
    return domains


def _filter_redundant_domains(domains: set[str]) -> set[str]:
    """
    Optimizes a set of domains by removing redundant subdomains.
    e.g., if 'example.com' is present, 'ad.example.com' is removed.
    """
    # Sort by length descending to ensure we process subdomains before parents
    sorted_domains = sorted(list(domains), key=len, reverse=True)
    optimized_set = set(sorted_domains)

    for domain in sorted_domains:
        parts = domain.split(".")
        # Check for parents of the current domain
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in optimized_set:
                # If a parent domain exists in the set, this subdomain is redundant.
                optimized_set.discard(domain)
                break  # Found a parent, no need to check further.

    return optimized_set


async def update_database(
    db_path_str: str, allowlist_path_str: str | None
) -> None:
    """
    Fetches all public blocklists, filters them against an allowlist,
    and compiles them into a SQLite database.
    """
    db_path = Path(db_path_str)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Start with the hardcoded default allowlist
    allowlist_domains = DEFAULT_ALLOWLIST.copy()
    logger.info(
        f"Loaded {len(allowlist_domains)} domains from the default allowlist."
    )

    # Add domains from the user-provided file, if any
    if allowlist_path_str:
        logger.info(f"Loading custom allowlist from: {allowlist_path_str}")
        try:
            with open(allowlist_path_str, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        allowlist_domains.add(line.strip().lower())
            logger.info(
                f"Total allowlist size is now {len(allowlist_domains)} domains."
            )
        except FileNotFoundError:
            logger.warning(
                "Custom allowlist file not found. Proceeding without it."
            )

    # Fetch and parse all blocklists
    all_blocked_domains: set[str] = set()
    async with aiohttp.ClientSession() as session:
        tasks = [_fetch_list(session, url) for url in BLOCKLIST_URLS]
        results = await asyncio.gather(*tasks)

    logger.info("\nParsing all fetched lists...")
    for content in results:
        all_blocked_domains.update(_parse_domains_from_content(content))

    logger.info(
        f"Found {len(all_blocked_domains)} unique domains before filtering."
    )

    # Remove allowed domains from the blocklist
    if allowlist_domains:
        original_count = len(all_blocked_domains)
        all_blocked_domains -= allowlist_domains
        num_removed = original_count - len(all_blocked_domains)
        logger.info(
            f"Removed {num_removed} domains that were in the allowlist."
        )

    # Optimize the final blocklist
    logger.info("Optimizing list by removing redundant subdomains...")
    optimized_domains = _filter_redundant_domains(all_blocked_domains)
    num_redundant_removed = len(all_blocked_domains) - len(optimized_domains)
    logger.info(
        f"Optimization complete. Removed {num_redundant_removed} redundant domains."
    )

    # Write the final list to the database
    logger.info(f"Writing {len(optimized_domains)} domains to database...")
    async with aiosqlite.connect(db_path) as db:
        await db.execute("DROP TABLE IF EXISTS blocked_domains")
        await db.execute(
            "CREATE TABLE blocked_domains (domain TEXT PRIMARY KEY)"
        )
        await db.executemany(
            "INSERT OR IGNORE INTO blocked_domains (domain) VALUES (?)",
            [(domain,) for domain in optimized_domains],
        )
        await db.commit()

    logger.info(f"\nSuccessfully created ad-block database at: {db_path}")
    logger.info(f"Total domains in database: {len(optimized_domains)}")
