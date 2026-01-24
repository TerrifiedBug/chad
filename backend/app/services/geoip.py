"""
GeoIP enrichment service using MaxMind databases.

Handles database downloads, updates, and IP lookups.
"""
import ipaddress
import logging
import shutil
import tarfile
from datetime import datetime
from pathlib import Path

import geoip2.database
import httpx
from geoip2.errors import AddressNotFoundError

logger = logging.getLogger(__name__)

# Database paths
GEOIP_DATA_DIR = Path("/data/geoip")
CITY_DB_PATH = GEOIP_DATA_DIR / "GeoLite2-City.mmdb"
CITY_DB_URL = "https://download.maxmind.com/app/geoip_download"


class GeoIPService:
    """MaxMind GeoIP lookup service."""

    def __init__(self):
        self._reader: geoip2.database.Reader | None = None
        self._last_check: datetime | None = None

    def is_database_available(self) -> bool:
        """Check if the GeoIP database exists."""
        return CITY_DB_PATH.exists()

    def get_database_info(self) -> dict | None:
        """Get information about the current database."""
        if not self.is_database_available():
            return None

        stat = CITY_DB_PATH.stat()
        return {
            "path": str(CITY_DB_PATH),
            "size_mb": stat.st_size / (1024 * 1024),
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }

    async def download_database(self, license_key: str) -> dict:
        """
        Download the GeoLite2-City database from MaxMind.

        Args:
            license_key: MaxMind license key

        Returns:
            dict with success status and message
        """
        GEOIP_DATA_DIR.mkdir(parents=True, exist_ok=True)

        params = {
            "edition_id": "GeoLite2-City",
            "license_key": license_key,
            "suffix": "tar.gz",
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    CITY_DB_URL,
                    params=params,
                    timeout=120.0,
                    follow_redirects=True,
                )

                if response.status_code == 401:
                    return {"success": False, "error": "Invalid license key"}

                if not response.is_success:
                    return {"success": False, "error": f"HTTP {response.status_code}"}

                # Save and extract
                tar_path = GEOIP_DATA_DIR / "download.tar.gz"
                tar_path.write_bytes(response.content)

                # Extract .mmdb file
                with tarfile.open(tar_path, "r:gz") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith(".mmdb"):
                            # Extract to temp, then move
                            tar.extract(member, GEOIP_DATA_DIR)
                            extracted = GEOIP_DATA_DIR / member.name
                            shutil.move(str(extracted), str(CITY_DB_PATH))
                            break

                # Cleanup
                tar_path.unlink()
                # Remove extracted directory
                for item in GEOIP_DATA_DIR.iterdir():
                    if item.is_dir():
                        shutil.rmtree(item)

                # Reload reader
                self._reload_reader()

                return {
                    "success": True,
                    "message": "Database downloaded successfully",
                    "info": self.get_database_info(),
                }

        except Exception as e:
            logger.error(f"Failed to download GeoIP database: {e}")
            return {"success": False, "error": str(e)}

    def _reload_reader(self):
        """Reload the database reader."""
        if self._reader:
            self._reader.close()
            self._reader = None

        if self.is_database_available():
            try:
                self._reader = geoip2.database.Reader(str(CITY_DB_PATH))
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")

    def _get_reader(self) -> geoip2.database.Reader | None:
        """Get or create the database reader."""
        if not self._reader and self.is_database_available():
            self._reload_reader()
        return self._reader

    def lookup(self, ip: str) -> dict | None:
        """
        Look up geographic information for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            dict with geo info or None if not found/error
        """
        reader = self._get_reader()
        if not reader:
            return None

        try:
            response = reader.city(ip)
            return {
                "country_iso_code": response.country.iso_code,
                "country_name": response.country.name,
                "region_iso_code": response.subdivisions.most_specific.iso_code if response.subdivisions else None,
                "region_name": response.subdivisions.most_specific.name if response.subdivisions else None,
                "city_name": response.city.name,
                "postal_code": response.postal.code,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
            }
        except AddressNotFoundError:
            return None
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            return None

    def is_public_ip(self, ip: str) -> bool:
        """Check if an IP address is public (not private/reserved)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_global
        except ValueError:
            return False


# Singleton instance
geoip_service = GeoIPService()
