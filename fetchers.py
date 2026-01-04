import requests
import feedparser
import json
import csv
import io
import time
import logging
import signal
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from feed_parsers import FeedParser
from models import Database
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BaseFetcher:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        })
        self.timeout = 15
        self.max_retries = 1
        self.max_fetch_time = 60

    def fetch(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def safe_fetch(self, **kwargs) -> List[Dict[str, Any]]:
        start_time = time.time()
        for attempt in range(self.max_retries + 1):
            try:
                if time.time() - start_time > self.max_fetch_time:
                    logger.warning(f"Max fetch time exceeded for {self.__class__.__name__}, skipping...")
                    return []
                
                result = self.fetch(**kwargs)
                elapsed = time.time() - start_time
                
                if elapsed > self.max_fetch_time:
                    logger.warning(f"Fetch took {elapsed:.1f}s for {self.__class__.__name__}, may be incomplete")
                return result
                
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout fetching from {self.__class__.__name__} (attempt {attempt + 1})")
                if attempt < self.max_retries:
                    time.sleep(1)
                    continue
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request error fetching from {self.__class__.__name__}: {e}")
                return []
            except Exception as e:
                logger.warning(f"Error fetching from {self.__class__.__name__}: {e}")
                return []
        return []


class CVEFetcher(BaseFetcher):
    """Enhanced CVE Fetcher with NVD API 2.0 advanced features"""
    def __init__(self):
        super().__init__()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # Temporarily disable API key as it's causing 404 errors
        # The NVD API works fine without a key (just with rate limits: 5 requests per 30 seconds)
        self.api_key = ''  # Disabled until valid key is obtained
        # self.api_key = config.NVD_API_KEY if hasattr(config, 'NVD_API_KEY') and config.NVD_API_KEY else ''
        # if self.api_key:
        #     headers['apiKey'] = self.api_key
        #     logger.info("✓ NVD API key configured")
        # else:
        logger.info("⚠ Using NVD API without key - rate limited to 5 requests per 30 seconds")
        self.session.headers.update(headers)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.last_fetch_time = None
        
        # Rate limiting
        self.rate_limit = 5  # Without API key: 5 requests per 30 seconds
        self.rate_window = 30
        self.request_times = []

    def _rate_limit_wait(self):
        """Implement rate limiting"""
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < self.rate_window]
        
        if len(self.request_times) >= self.rate_limit:
            sleep_time = self.rate_window - (now - self.request_times[0]) + 1
            if sleep_time > 0:
                logger.info(f"Rate limit reached, waiting {sleep_time:.1f}s...")
                time.sleep(sleep_time)
                self.request_times = []
        
        self.request_times.append(now)

    def fetch(self, days_back: int = 30) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API with chunking for large date ranges"""
        # Use 2024 dates if system date is in future (2025+)
        current_date = datetime.utcnow()
        if current_date.year >= 2025:
            end_date_obj = datetime(2024, 12, 23)
        else:
            end_date_obj = current_date
        
        # NVD API limit: Maximum 120 days per request to avoid 404
        MAX_CHUNK_DAYS = 120
        
        # If requesting more than 120 days, fetch in chunks
        if days_back > MAX_CHUNK_DAYS:
            logger.info(f"Fetching {days_back} days of CVEs in chunks of {MAX_CHUNK_DAYS} days...")
            return self._fetch_in_chunks(days_back, end_date_obj)
        else:
            # Single fetch for small date ranges
            start_date_obj = end_date_obj - timedelta(days=days_back)
            logger.info(f"Fetching CVEs from {start_date_obj.strftime('%Y-%m-%d')} to {end_date_obj.strftime('%Y-%m-%d')}")
            return self._fetch_date_range(start_date_obj, end_date_obj)
    
    def _fetch_in_chunks(self, days_back: int, end_date_obj: datetime) -> List[Dict[str, Any]]:
        """Fetch CVEs in chunks to handle large date ranges"""
        MAX_CHUNK_DAYS = 120
        all_items = []
        
        # Calculate number of chunks needed
        num_chunks = (days_back + MAX_CHUNK_DAYS - 1) // MAX_CHUNK_DAYS
        
        logger.info(f"Splitting {days_back} days into {num_chunks} chunks...")
        
        for chunk_num in range(num_chunks):
            # Calculate date range for this chunk
            chunk_end = end_date_obj - timedelta(days=chunk_num * MAX_CHUNK_DAYS)
            chunk_start = chunk_end - timedelta(days=min(MAX_CHUNK_DAYS, days_back - chunk_num * MAX_CHUNK_DAYS))
            
            logger.info(f"Fetching chunk {chunk_num + 1}/{num_chunks}: {chunk_start.strftime('%Y-%m-%d')} to {chunk_end.strftime('%Y-%m-%d')}")
            
            try:
                chunk_items = self._fetch_date_range(chunk_start, chunk_end)
                all_items.extend(chunk_items)
                logger.info(f"✓ Chunk {chunk_num + 1}/{num_chunks}: Fetched {len(chunk_items)} CVEs")
                
                # Add delay between chunks to respect rate limits
                if chunk_num < num_chunks - 1:
                    logger.info("Waiting 6 seconds before next chunk...")
                    time.sleep(6)
                    
            except Exception as e:
                logger.error(f"Error fetching chunk {chunk_num + 1}: {e}")
                # Continue with next chunk even if one fails
                continue
        
        logger.info(f"✓ Total CVEs fetched from all chunks: {len(all_items)}")
        return all_items
    
    def _fetch_date_range(self, start_date_obj: datetime, end_date_obj: datetime) -> List[Dict[str, Any]]:
        """Fetch CVEs for a specific date range"""
        items = []
        start_date = start_date_obj.strftime('%Y-%m-%dT00:00:00.000')
        end_date = end_date_obj.strftime('%Y-%m-%dT23:59:59.999')
        
        start_index = 0
        results_per_page = 100
        max_items = 10000  # Maximum items to fetch per date range
        
        try:
            while start_index < max_items:
                self._rate_limit_wait()  # Rate limiting
                
                params = {
                    'pubStartDate': start_date,
                    'pubEndDate': end_date,
                    'resultsPerPage': results_per_page,
                    'startIndex': start_index
                }
                    
                response = self.session.get(
                    self.base_url,
                    params=params,
                    timeout=30
                )
                
                if response.status_code == 403:
                    logger.warning("NVD API returned 403. Rate limit exceeded. Waiting 60 seconds...")
                    time.sleep(60)
                    continue
                    
                if response.status_code == 404:
                    logger.warning(f"NVD API returned 404 for date range {start_date[:10]} to {end_date[:10]}")
                    break
                    
                response.raise_for_status()
                data = response.json()
                    
                response.raise_for_status()
                data = response.json()
                    
                if 'vulnerabilities' not in data:
                    break
                    
                vulnerabilities = data['vulnerabilities']
                if not vulnerabilities:
                    break
                    
                for vuln in vulnerabilities:
                    try:
                        cve = vuln.get('cve', {})
                        cve_id = cve.get('id', '')
                        if not cve_id:
                            continue
                            
                        descriptions = cve.get('descriptions', [])
                        description = ''
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                        
                        # CVE Status
                        cve_status = cve.get('vulnStatus', 'Unknown')
                        
                        # Published and Modified dates
                        published = cve.get('published', '')
                        last_modified = cve.get('lastModified', '')
                        
                        if published and 'T' in published:
                            published = published.split('T')[0]
                        if last_modified and 'T' in last_modified:
                            last_modified = last_modified.split('T')[0]
                                
                        # CVSS Scores and Severity
                        severity = 'UNKNOWN'
                        cvss_v2_score = None
                        cvss_v3_score = None
                        cvss_v4_score = None
                        cvss_vector = None
                        exploitability_score = None
                        impact_score = None
                        metrics = cve.get('metrics', {})
                        
                        # CVSS v4.0
                        if 'cvssMetricV40' in metrics and len(metrics['cvssMetricV40']) > 0:
                            cvss = metrics['cvssMetricV40'][0]
                            cvss_data = cvss.get('cvssData', {})
                            cvss_v4_score = cvss_data.get('baseScore')
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                            cvss_vector = cvss_data.get('vectorString', '')
                        
                        # CVSS v3.1
                        if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                            cvss = metrics['cvssMetricV31'][0]
                            cvss_data = cvss.get('cvssData', {})
                            cvss_v3_score = cvss_data.get('baseScore')
                            if not cvss_v4_score:
                                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                                cvss_vector = cvss_data.get('vectorString', '')
                            exploitability_score = cvss.get('exploitabilityScore')
                            impact_score = cvss.get('impactScore')
                        
                        # CVSS v2
                        if 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
                            cvss = metrics['cvssMetricV2'][0]
                            cvss_data = cvss.get('cvssData', {})
                            cvss_v2_score = cvss_data.get('baseScore')
                            if not cvss_v3_score and not cvss_v4_score:
                                base_score = cvss_v2_score
                                if base_score >= 9.0:
                                    severity = 'CRITICAL'
                                elif base_score >= 7.0:
                                    severity = 'HIGH'
                                elif base_score >= 4.0:
                                    severity = 'MEDIUM'
                                else:
                                    severity = 'LOW'
                        
                        # CWE (Common Weakness Enumeration)
                        cwe_id = None
                        weaknesses = cve.get('weaknesses', [])
                        for weakness in weaknesses:
                            descriptions_w = weakness.get('description', [])
                            for desc in descriptions_w:
                                if desc.get('lang') == 'en':
                                    cwe_value = desc.get('value', '')
                                    if cwe_value.startswith('CWE-'):
                                        cwe_id = cwe_value
                                        break
                            if cwe_id:
                                break
                        
                        # References
                        references = []
                        for ref in cve.get('references', []):
                            ref_url = ref.get('url', '')
                            ref_source = ref.get('source', '')
                            ref_tags = ref.get('tags', [])
                            if ref_url:
                                references.append({
                                    'url': ref_url,
                                    'source': ref_source,
                                    'tags': ref_tags
                                })
                        
                        # Affected Products (CPE)
                        affected_products = []
                        configurations = cve.get('configurations', [])
                        for config_item in configurations:
                            nodes = config_item.get('nodes', [])
                            for node in nodes:
                                cpe_matches = node.get('cpeMatch', [])
                                for cpe_match in cpe_matches:
                                    cpe_uri = cpe_match.get('criteria', '')
                                    vulnerable = cpe_match.get('vulnerable', True)
                                    version_start = cpe_match.get('versionStartIncluding') or cpe_match.get('versionStartExcluding')
                                    version_end = cpe_match.get('versionEndIncluding') or cpe_match.get('versionEndExcluding')
                                    
                                    if cpe_uri:
                                        cpe_parts = cpe_uri.split(':')
                                        vendor = cpe_parts[3] if len(cpe_parts) > 3 else None
                                        product = cpe_parts[4] if len(cpe_parts) > 4 else None
                                        version = cpe_parts[5] if len(cpe_parts) > 5 else None
                                        
                                        affected_products.append({
                                            'cpe_uri': cpe_uri,
                                            'vendor': vendor,
                                            'product': product,
                                            'version': version,
                                            'version_start': version_start,
                                            'version_end': version_end,
                                            'vulnerable': vulnerable
                                        })
                                
                        items.append({
                            'category': 'cve',
                            'title': cve_id,
                            'description': description,
                            'source': 'NVD',
                            'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            'published_date': published,
                            'severity': severity,
                            'cve_id': cve_id,
                            'tags': ['CVE', 'Vulnerability', severity] if severity != 'UNKNOWN' else ['CVE', 'Vulnerability'],
                            # Enhanced fields
                            'cve_status': cve_status,
                            'last_modified_date': last_modified,
                            'cwe_id': cwe_id,
                            'cvss_v2_score': cvss_v2_score,
                            'cvss_v3_score': cvss_v3_score,
                            'cvss_v4_score': cvss_v4_score,
                            'cvss_vector': cvss_vector,
                            'exploitability_score': exploitability_score,
                            'impact_score': impact_score,
                            'references_json': json.dumps(references) if references else None,
                            'affected_products_json': json.dumps(affected_products) if affected_products else None,
                            'raw_data': vuln
                        })
                    except Exception as e:
                        logger.warning(f"Error processing CVE item: {e}")
                        continue
                        
                total_results = data.get('totalResults', 0)
                start_index += len(vulnerabilities)
                
                if start_index >= total_results or len(vulnerabilities) < results_per_page:
                    break
                    
                time.sleep(0.5)
                
        except Exception as e:
            logger.error(f"Error fetching CVEs for date range: {e}")
            
        return items


class ExploitDBFetcher(BaseFetcher):
    def __init__(self):
        super().__init__()
        self.base_url = "https://www.exploit-db.com"

    def fetch(self) -> List[Dict[str, Any]]:
        return self.fetch_recent()

    def fetch_recent(self, cutoff_time=None) -> List[Dict[str, Any]]:
        items = []
        try:
            rss_url = "https://www.exploit-db.com/rss.xml"
            feed = feedparser.parse(rss_url)
            
            for entry in feed.entries:
                if cutoff_time:
                    published_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        try:
                            published_date = datetime(*entry.published_parsed[:6])
                            if published_date < cutoff_time:
                                continue
                        except:
                            pass
                            
                published_date_str = ''
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    try:
                        published_date_str = datetime(*entry.published_parsed[:6]).isoformat()
                    except:
                        pass
                        
                cve_id = ''
                title = entry.title
                if 'CVE-' in title:
                    parts = title.split('CVE-')
                    if len(parts) > 1:
                        cve_part = 'CVE-' + parts[1].split()[0]
                        cve_id = cve_part
                        
                description = getattr(entry, 'summary', '') or ''
                if not description and hasattr(entry, 'description'):
                    description = entry.description
                    
                author = ''
                if hasattr(entry, 'author'):
                    author = entry.author
                    
                platform = ''
                exploit_type = ''
                
                if hasattr(entry, 'tags'):
                    tags_list = [tag.term for tag in entry.tags] if hasattr(entry.tags[0], 'term') else entry.tags
                    for tag in tags_list:
                        if any(x in tag.lower() for x in ['windows', 'linux', 'unix', 'macos', 'android', 'ios']):
                            platform = tag
                        elif any(x in tag.lower() for x in ['remote', 'local', 'web', 'dos', 'code execution']):
                            exploit_type = tag
                            
                items.append({
                    'category': 'exploit',
                    'title': title,
                    'description': description[:500] if description else 'Exploit details available on Exploit-DB',
                    'source': 'Exploit-DB',
                    'source_url': entry.link,
                    'published_date': published_date_str,
                    'severity': '',
                    'cve_id': cve_id if cve_id else '',
                    'tags': ['Exploit', 'Exploit-DB'] + ([platform] if platform else []) + ([exploit_type] if exploit_type else []),
                    'raw_data': {
                        'link': entry.link,
                        'author': author,
                        'platform': platform,
                        'exploit_type': exploit_type,
                        'cve_id': cve_id
                    }
                })
            logger.info(f"Fetched {len(items)} exploits from Exploit-DB")
        except Exception as e:
            logger.error(f"Error fetching Exploit-DB: {e}")
        return items

    def fetch_full_database(self) -> List[Dict[str, Any]]:
        items = []
        try:
            logger.info("Starting full Exploit-DB database download from CSV...")
            csv_url = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
            
            try:
                response = self.session.get(csv_url, timeout=60)
                if response.status_code == 200:
                    csv_content = io.StringIO(response.text)
                    csv_reader = csv.DictReader(csv_content)
                    
                    for row in csv_reader:
                        try:
                            exploit_id = row.get('id', '').strip()
                            file_path = row.get('file', '').strip()
                            description = row.get('description', '').strip()
                            date_published = row.get('date_published', '').strip()
                            author = row.get('author', '').strip()
                            platform = row.get('platform', '').strip()
                            exploit_type = row.get('type', '').strip()
                            port = row.get('port', '').strip()
                            
                            title = description[:200] if description else f"Exploit {exploit_id}"
                            source_url = f"https://www.exploit-db.com/exploits/{exploit_id}"
                            
                            cve_id = ''
                            if 'CVE-' in description:
                                import re
                                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', description.upper())
                                if cve_match:
                                    cve_id = cve_match.group(0)
                                    
                            published_date_str = ''
                            if date_published:
                                try:
                                    dt = datetime.strptime(date_published[:10], '%Y-%m-%d')
                                    published_date_str = dt.isoformat()
                                except:
                                    pass
                                    
                            items.append({
                                'category': 'exploit',
                                'title': title,
                                'description': description[:500] if description else f'Exploit details available on Exploit-DB (ID: {exploit_id})',
                                'source': 'Exploit-DB',
                                'source_url': source_url,
                                'published_date': published_date_str,
                                'severity': '',
                                'cve_id': cve_id,
                                'tags': ['Exploit', 'Exploit-DB'] + ([platform] if platform else []) + ([exploit_type] if exploit_type else []),
                                'raw_data': {
                                    'exploit_id': exploit_id,
                                    'file': file_path,
                                    'author': author,
                                    'platform': platform,
                                    'type': exploit_type,
                                    'port': port,
                                    'cve_id': cve_id
                                }
                            })
                        except Exception:
                            continue
                    logger.info(f"Downloaded {len(items)} exploits from Exploit-DB CSV database")
                else:
                    logger.warning(f"Could not download CSV, falling back to RSS feed. Status: {response.status_code}")
                    return self._fetch_from_rss()
            except Exception as e:
                logger.warning(f"Error downloading CSV, falling back to RSS feed: {e}")
                return self._fetch_from_rss()
        except Exception as e:
            logger.error(f"Error downloading full Exploit-DB database: {e}")
        return items

    def _fetch_from_rss(self) -> List[Dict[str, Any]]:
        items = []
        try:
            rss_url = "https://www.exploit-db.com/rss.xml"
            feed = feedparser.parse(rss_url)
            
            for entry in feed.entries:
                published_date_str = ''
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    try:
                        published_date_str = datetime(*entry.published_parsed[:6]).isoformat()
                    except:
                        pass
                        
                cve_id = ''
                title = entry.title
                if 'CVE-' in title:
                    parts = title.split('CVE-')
                    if len(parts) > 1:
                        cve_part = 'CVE-' + parts[1].split()[0]
                        cve_id = cve_part
                        
                description = getattr(entry, 'summary', '') or ''
                author = getattr(entry, 'author', '') or ''
                platform = ''
                exploit_type = ''
                
                if hasattr(entry, 'tags'):
                    tags_list = [tag.term for tag in entry.tags] if hasattr(entry.tags[0], 'term') else entry.tags
                    for tag in tags_list:
                        if any(x in tag.lower() for x in ['windows', 'linux', 'unix', 'macos', 'android', 'ios']):
                            platform = tag
                        elif any(x in tag.lower() for x in ['remote', 'local', 'web', 'dos', 'code execution']):
                            exploit_type = tag
                            
                items.append({
                    'category': 'exploit',
                    'title': title,
                    'description': description[:500] if description else 'Exploit details available on Exploit-DB',
                    'source': 'Exploit-DB',
                    'source_url': entry.link,
                    'published_date': published_date_str,
                    'severity': '',
                    'cve_id': cve_id if cve_id else '',
                    'tags': ['Exploit', 'Exploit-DB'] + ([platform] if platform else []) + ([exploit_type] if exploit_type else []),
                    'raw_data': {
                        'link': entry.link,
                        'author': author,
                        'platform': platform,
                        'exploit_type': exploit_type,
                        'cve_id': cve_id
                    }
                })
        except Exception as e:
            logger.error(f"Error fetching from RSS: {e}")
        return items


class MalwareBazaarFetcher(BaseFetcher):
    def __init__(self):
        super().__init__()
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.api_key = config.MALWARE_BAZAAR_API_KEY
        if self.api_key:
            logger.info(f"MalwareBazaar API key loaded: {self.api_key[:10]}...")
        else:
            logger.warning("MalwareBazaar API key not set in config.py")

    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch recent malware samples"""
        items = []
        try:
            data = {
                'query': 'get_recent',
                'selector': 'time'
            }
            headers = {}
            if not self.api_key:
                logger.warning("No API key provided - MalwareBazaar requires authentication")
                return items
                
            headers['Auth-Key'] = self.api_key.strip()
            logger.info(f"Making authenticated POST request to {self.api_url} with Auth-Key header")
            
            if 'Content-Type' in headers:
                del headers['Content-Type']
                
            response = self.session.post(
                self.api_url,
                data=data,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 401:
                logger.error(f"MalwareBazaar API returned 401 Unauthorized. Auth-Key may be invalid or expired.")
                logger.error(f"API Key (first 10 chars): {self.api_key[:10]}...")
                return items
            elif response.status_code == 403:
                logger.error(f"MalwareBazaar API returned 403 Forbidden.")
                return items
            elif response.status_code == 405:
                logger.error(f"MalwareBazaar API returned 405 Method Not Allowed.")
                return items
                
            response.raise_for_status()
            result = response.json()
            query_status = result.get('query_status', '')
            
            if query_status == 'unknown_auth_key':
                logger.error(f"MalwareBazaar API key is invalid or unknown. Response: {result}")
                return items
                
            if query_status == 'ok':
                for sample in result.get('data', [])[:50]:
                    sha256 = sample.get('sha256_hash', '')
                    file_type = sample.get('file_type', '')
                    signature = sample.get('signature', '')
                    
                    items.append({
                        'category': 'malware',
                        'title': f"{signature} - {file_type}" if signature else f"Malware Sample - {file_type}",
                        'description': f"SHA256: {sha256}\nFile Type: {file_type}\nSignature: {signature}" if signature else f"SHA256: {sha256}\nFile Type: {file_type}",
                        'source': 'MalwareBazaar',
                        'source_url': f"https://bazaar.abuse.ch/sample/{sha256}/",
                        'published_date': sample.get('first_seen', ''),
                        'severity': 'HIGH',
                        'tags': ['Malware', file_type, signature] if signature else ['Malware', file_type],
                        'raw_data': sample
                    })
        except Exception as e:
            logger.warning(f"Error fetching MalwareBazaar (may require auth): {e}")
        return items


class RansomwareLiveFetcher(BaseFetcher):
    def __init__(self):
        super().__init__()
        from config import RANSOMWARE_LIVE_API, RANSOMWARE_LIVE_API_KEY
        self.api_base = RANSOMWARE_LIVE_API
        self.api_key = RANSOMWARE_LIVE_API_KEY
        self.timeout = 30
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}'
            })

    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch comprehensive ransomware groups and victims from ransomware.live"""
        items = []
        try:
            groups = self._fetch_groups()
            items.extend(groups)
            victims = self._fetch_victims(groups)
            items.extend(victims)
            logger.info(f"Fetched {len(groups)} groups and {len(victims)} victims from ransomware.live")
            if len(items) == 0:
                logger.warning("Ransomware.live API returned 0 items. Check API endpoint and response format.")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error fetching ransomware.live: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response text: {e.response.text[:300]}")
        except Exception as e:
            logger.error(f"Error fetching ransomware.live: {e}", exc_info=True)
        return items

    def _fetch_groups(self) -> List[Dict[str, Any]]:
        """Fetch all ransomware groups with comprehensive details from ransomware.live API"""
        items = []
        try:
            url = f"{self.api_base}/groups"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            max_retries = 3
            retry_count = 0
            response = None
            
            while retry_count < max_retries:
                try:
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    logger.info(f"Ransomware.live /groups: Status {response.status_code}")
                    break
                except requests.exceptions.ReadTimeout:
                    retry_count += 1
                    if retry_count < max_retries:
                        logger.warning(f"Ransomware.live /groups timeout (attempt {retry_count}/{max_retries}), retrying...")
                        time.sleep(2)
                    else:
                        logger.error("Ransomware.live /groups timeout after all retries")
                        raise
                        
            if not response:
                return items
            if response.status_code == 429:
                logger.warning("Ransomware.live rate limit exceeded.")
                return items
            response.raise_for_status()
            data = response.json()
            
            if isinstance(data, dict):
                if 'data' in data:
                    data = data['data']
                elif 'groups' in data:
                    data = data['groups']
                elif 'results' in data:
                    data = data['results']
                    
            if isinstance(data, list):
                logger.info(f"Received {len(data)} groups from ransomware.live API")
                processed_count = 0
                error_count = 0
                if len(data) > 0:
                    sample = data[0] if len(data) > 0 else None
                    logger.info(f"Sample group data type: {type(sample)}, sample keys: {list(sample.keys())[:10] if isinstance(sample, dict) else 'N/A'}")
                    
                for idx, group in enumerate(data):
                    if idx > 0 and idx % 50 == 0:
                        logger.info(f"Processing groups: {idx}/{len(data)} processed so far...")
                        
                    try:
                        if not isinstance(group, dict):
                            logger.warning(f"Skipping group with unexpected type: {type(group)}")
                            error_count += 1
                            continue
                            
                        group_name = group.get('name') or group.get('group_name') or group.get('title') or ''
                        if not group_name:
                            group_name = group.get('slug') or group.get('id') or 'Unknown'
                        if group_name == 'Unknown' or not group_name:
                            error_count += 1
                            continue
                            
                        description = group.get('description', '') or group.get('content', '') or ''
                        locations = group.get('locations', []) or []
                        if not isinstance(locations, list):
                            locations = []
                            
                        current_onion_urls = []
                        available_locations = []
                        location_details = []
                        
                        for loc in locations:
                            if isinstance(loc, dict):
                                fqdn = loc.get('fqdn') or loc.get('slug', '').replace('http://', '').replace('https://', '')
                                available = loc.get('available', False)
                                enabled = loc.get('enabled', False)
                                loc_type = loc.get('type', '')
                                title = loc.get('title', '')
                                last_scrape = loc.get('lastscrape', '') or loc.get('last_scrape', '')
                                updated = loc.get('updated', '')
                                
                                if title and ('LEAK' in title.upper() or 'LEAKS' in title.upper()):
                                    continue
                                    
                                if fqdn and '.onion' in fqdn:
                                    onion_url = f"http://{fqdn}" if not fqdn.startswith('http') else fqdn
                                    current_onion_urls.append(onion_url)
                                    location_info = {
                                        'fqdn': fqdn,
                                        'onion_url': onion_url,
                                        'available': available,
                                        'enabled': enabled,
                                        'type': loc_type,
                                        'title': title,
                                        'last_scrape': last_scrape,
                                        'updated': updated,
                                        'status': 200 if available else 404
                                    }
                                    if loc.get('http'):
                                        http_data = loc.get('http', {})
                                        location_info['http_status'] = http_data.get('status', '')
                                        location_info['final_url'] = http_data.get('final_url', '')
                                        location_info['fetched_at'] = http_data.get('fetched_at', '')
                                        
                                    location_details.append(location_info)
                                    if available:
                                        available_locations.append(location_info)
                                        
                            elif isinstance(loc, str) and '.onion' in loc:
                                onion_url = loc if loc.startswith('http') else f"http://{loc}"
                                current_onion_urls.append(onion_url)
                                location_details.append({
                                    'onion_url': onion_url,
                                    'fqdn': loc.replace('http://', '').replace('https://', ''),
                                    'available': True,
                                    'enabled': True
                                })
                                
                        primary_onion_url = None
                        if available_locations:
                            primary_onion_url = available_locations[0].get('onion_url')
                        elif current_onion_urls:
                            primary_onion_url = current_onion_urls[0]
                            
                        first_seen = group.get('first_seen', '') or group.get('firstseen', '') or ''
                        last_seen = group.get('last_seen', '') or group.get('lastseen', '') or group.get('updated', '') or ''
                        status = 'Active' if available_locations else 'Inactive'
                        
                        desc_parts = []
                        if description:
                            desc_parts.append(str(description)[:250])
                        if available_locations:
                            desc_parts.append(f"{len(available_locations)} active location(s)")
                        if current_onion_urls:
                            desc_parts.append(f"{len(current_onion_urls)} known onion URL(s)")
                            
                        raw_data = {
                            **group,
                            'group_name': group_name,
                            'name': group_name,
                            'description': description,
                            'locations': location_details,
                            'current_onion_urls': current_onion_urls,
                            'available_locations': available_locations,
                            'primary_onion_url': primary_onion_url,
                            'location_count': len(location_details),
                            'available_count': len(available_locations),
                            'first_seen': first_seen,
                            'last_seen': last_seen,
                            'status': status
                        }
                        
                        source_url = primary_onion_url if primary_onion_url else f"{self.api_base}/group/{group_name}"
                        items.append({
                            'category': 'ransomware',
                            'title': f"Ransomware Group: {group_name}",
                            'description': ' | '.join(desc_parts) if desc_parts else f"Ransomware group {group_name}",
                            'source': 'Ransomware.live',
                            'source_url': source_url,
                            'published_date': first_seen if first_seen else datetime.utcnow().isoformat(),
                            'severity': 'High' if available_locations else 'Medium',
                            'tags': ['Ransomware', 'Group', 'Threat Group', group_name],
                            'raw_data': raw_data
                        })
                        processed_count += 1
                        
                    except Exception as e:
                        error_count += 1
                        group_identifier = group.get('name') or group.get('group_name') or group.get('id') or str(group)[:50]
                        if error_count <= 5:
                            logger.warning(f"Error processing group '{group_identifier}': {e}", exc_info=True)
                        elif error_count == 6:
                            logger.warning(f"Suppressing further group processing errors (total errors: {error_count} and counting...)")
                        continue
                        
                logger.info(f"Processed {processed_count} groups successfully, {error_count} errors")
                if processed_count == 0 and error_count > 0:
                    logger.error(f"All {error_count} groups failed to process. Check sample data logged above.")
            else:
                logger.warning(f"Unexpected data format from ransomware.live /groups: {type(data)}")
                if isinstance(data, dict):
                    logger.warning(f"Available keys: {list(data.keys())[:10]}")
                    
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error fetching ransomware groups: {e}")
            if hasattr(e.response, 'text'):
                logger.error(f"Response: {e.response.text[:200]}")
        except Exception as e:
            logger.error(f"Error fetching ransomware groups: {e}", exc_info=True)
        return items

    def _fetch_victims(self, groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fetch victims for ransomware groups"""
        items = []
        group_names = set()
        for group_item in groups:
            raw_data = group_item.get('raw_data', {})
            group_name = raw_data.get('group_name') or raw_data.get('name') or ''
            if group_name:
                group_names.add(group_name)
                
        if not group_names:
            logger.info("No group names found, skipping victims fetch")
            return items
            
        logger.info(f"Fetching victims for {len(group_names)} groups...")
        processed_count = 0
        error_count = 0
        
        for group_name in list(group_names)[:50]:
            try:
                url = f"{self.api_base}/groupvictims/{group_name}"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json'
                }
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                if response.status_code == 404:
                    continue
                if response.status_code == 429:
                    logger.warning(f"Rate limit hit while fetching victims for {group_name}, stopping...")
                    break
                response.raise_for_status()
                data = response.json()
                
                if isinstance(data, dict):
                    if 'data' in data:
                        data = data['data']
                    elif 'victims' in data:
                        data = data['victims']
                    elif 'results' in data:
                        data = data['results']
                        
                if isinstance(data, list):
                    for victim in data[:100]:
                        try:
                            if not isinstance(victim, dict):
                                continue
                            victim_name = victim.get('name') or victim.get('victim') or victim.get('company') or 'Unknown'
                            if victim_name == 'Unknown':
                                continue
                                
                            country = victim.get('country', '') or ''
                            sector = victim.get('sector', '') or victim.get('industry', '') or ''
                            published_date = victim.get('published_date', '') or victim.get('date', '') or victim.get('created_at', '') or ''
                            description = victim.get('description', '') or ''
                            
                            desc_parts = []
                            if description:
                                clean_desc = str(description).strip()
                                import re
                                clean_desc = re.sub(r'\bCountry:\s*\w+\b', '', clean_desc, flags=re.IGNORECASE)
                                clean_desc = re.sub(r'\bSector:\s*\w+\b', '', clean_desc, flags=re.IGNORECASE)
                                clean_desc = re.sub(r'\|\s*\|\s*', '|', clean_desc)
                                clean_desc = clean_desc.strip(' |')
                                if clean_desc and clean_desc.lower() not in [victim_name.lower(), group_name.lower()]:
                                    desc_parts.append(clean_desc[:200])
                                    
                            if not desc_parts and published_date:
                                try:
                                    date_obj = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                                    desc_parts.append(f"Attack date: {date_obj.strftime('%Y-%m-%d %H:%M:%S')}")
                                except:
                                    pass
                                    
                            items.append({
                                'category': 'ransomware',
                                'title': f"{victim_name} - Victim of {group_name}",
                                'description': ' | '.join(desc_parts) if desc_parts else '',
                                'source': 'Ransomware.live',
                                'source_url': f"{self.api_base}/groupvictims/{group_name}",
                                'published_date': published_date if published_date else datetime.utcnow().isoformat(),
                                'severity': 'High',
                                'tags': ['Ransomware', 'Victim', group_name] + ([country, sector] if country or sector else []),
                                'raw_data': {
                                    **victim,
                                    'victim_name': victim_name,
                                    'group_name': group_name,
                                    'country': country,
                                    'sector': sector
                                }
                            })
                            processed_count += 1
                        except Exception:
                            error_count += 1
                            continue
                            
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    continue
            except Exception:
                error_count += 1
                continue
                
        logger.info(f"Processed {processed_count} victims successfully, {error_count} errors")
        return items


class RansomLookFetcher(BaseFetcher):
    """Fetch ransomware data from ransomlook.io"""
    def __init__(self):
        super().__init__()
        self.api_base = "https://www.ransomlook.io/api"
        self.timeout = 30

    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch ransomware groups and recent posts from ransomlook.io"""
        items = []
        try:
            # Fetch recent posts (victims)
            posts = self._fetch_recent_posts()
            items.extend(posts)
            
            # Fetch groups
            groups = self._fetch_groups()
            items.extend(groups)
            
            logger.info(f"Fetched {len(posts)} posts and {len(groups)} groups from ransomlook.io")
        except Exception as e:
            logger.error(f"Error fetching ransomlook.io: {e}", exc_info=True)
        return items

    def _fetch_recent_posts(self) -> List[Dict[str, Any]]:
        """Fetch recent ransomware posts (victims)"""
        items = []
        try:
            url = f"{self.api_base}/recent"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            logger.info(f"RansomLook /recent: Status {response.status_code}")
            
            if response.status_code != 200:
                logger.warning(f"RansomLook API returned {response.status_code}")
                return items
            
            data = response.json()
            
            # Handle different response formats
            posts = data if isinstance(data, list) else data.get('posts', [])
            
            for post in posts[:100]:  # Limit to 100 recent posts
                try:
                    group_name = post.get('group_name', '') or post.get('group', '') or 'Unknown'
                    victim_name = post.get('post_title', '') or post.get('victim', '') or post.get('title', '')
                    
                    if not victim_name or victim_name == 'Unknown':
                        continue
                    
                    discovered = post.get('discovered', '') or post.get('published', '') or ''
                    post_url = post.get('post_url', '') or ''
                    
                    # Build description
                    desc_parts = []
                    if group_name and group_name != 'Unknown':
                        desc_parts.append(f"Ransomware Group: {group_name}")
                    if discovered:
                        desc_parts.append(f"Discovered: {discovered}")
                    
                    items.append({
                        'category': 'ransomware',
                        'title': f"{victim_name} - Ransomware Attack",
                        'description': ' | '.join(desc_parts) if desc_parts else f"Ransomware attack on {victim_name}",
                        'source': 'RansomLook',
                        'source_url': post_url if post_url else 'https://www.ransomlook.io',
                        'published_date': discovered if discovered else datetime.utcnow().isoformat(),
                        'severity': 'High',
                        'tags': ['Ransomware', 'Victim', group_name] if group_name != 'Unknown' else ['Ransomware', 'Victim'],
                        'raw_data': post
                    })
                except Exception as e:
                    logger.warning(f"Error processing RansomLook post: {e}")
                    continue
            
            logger.info(f"Processed {len(items)} posts from RansomLook")
        except Exception as e:
            logger.error(f"Error fetching RansomLook posts: {e}")
        
        return items

    def _fetch_groups(self) -> List[Dict[str, Any]]:
        """Fetch ransomware groups"""
        items = []
        try:
            url = f"{self.api_base}/groups"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            logger.info(f"RansomLook /groups: Status {response.status_code}")
            
            if response.status_code != 200:
                logger.warning(f"RansomLook groups API returned {response.status_code}")
                return items
            
            data = response.json()
            
            # Handle different response formats
            groups = data if isinstance(data, list) else data.get('groups', [])
            
            for group in groups[:50]:  # Limit to 50 groups
                try:
                    # Handle both string and dict formats (API format changed)
                    if isinstance(group, str):
                        # New API format: just a string (group name)
                        group_name = group
                        group_description = ''
                        group_locations = []
                        group_profile = ''
                    elif isinstance(group, dict):
                        # Old API format: dictionary with details
                        group_name = group.get('name', '') or group.get('group_name', '')
                        group_description = group.get('description', '')
                        group_locations = group.get('locations', [])
                        group_profile = group.get('profile', '')
                    else:
                        # Unknown format, skip
                        logger.debug(f"Unknown group format: {type(group)}")
                        continue
                    
                    if not group_name:
                        continue
                    
                    # Build description
                    desc_parts = []
                    
                    if group_description:
                        desc_parts.append(group_description)
                    
                    if group_locations:
                        if isinstance(group_locations, list) and group_locations:
                            desc_parts.append(f"Active sites: {len(group_locations)}")
                    
                    items.append({
                        'category': 'ransomware',
                        'title': f"Ransomware Group: {group_name}",
                        'description': ' | '.join(desc_parts) if desc_parts else f"Active ransomware group: {group_name}",
                        'source': 'RansomLook',
                        'source_url': group_profile if group_profile else 'https://www.ransomlook.io',
                        'published_date': datetime.utcnow().isoformat(),
                        'severity': 'High',
                        'tags': ['Ransomware', 'Group', group_name],
                        'raw_data': group if isinstance(group, dict) else {'name': group}
                    })
                except Exception as e:
                    logger.warning(f"Error processing RansomLook group: {e}")
                    continue
            
            logger.info(f"Processed {len(items)} groups from RansomLook")
        except Exception as e:
            logger.error(f"Error fetching RansomLook groups: {e}")
        
        return items


class CERTInFetcher(BaseFetcher):
    """Fetch CERT-In (India) advisories - Fetch all advisories for all years (2003-2025)"""
    def __init__(self):
        super().__init__()
        self.base_url = "https://www.cert-in.org.in"
        self.max_fetch_time = 300
        self.timeout = 30

    def fetch(self, historical: bool = False, current_year_only: bool = False) -> List[Dict[str, Any]]:
        """Fetch CERT-In advisories
        Args:
            historical: If True, fetch all years (2003-current). If False, only fetch current year.
            current_year_only: If True, only fetch current year (for refresh to avoid duplicates).
        """
        items = []
        seen_urls = set()
        current_year = datetime.utcnow().year
        
        if current_year_only or not historical:
            logger.info(f"Fetching CERT-In advisories for current year ({current_year}) only...")
            years_to_fetch = [current_year]
        else:
            logger.info(f"Fetching CERT-In advisories for all years (2003-{current_year})...")
            years_to_fetch = list(range(2003, current_year + 1))
            
        for year in years_to_fetch:
            try:
                year_items = self._fetch_year_advisories(year, seen_urls)
                items.extend(year_items)
                logger.info(f"Fetched {len(year_items)} advisories for year {year}")
                time.sleep(0.5)
            except Exception as e:
                logger.warning(f"Error fetching CERT-In advisories for year {year}: {e}")
                continue
                
        logger.info(f"Total fetched {len(items)} CERT-In advisories from {len(years_to_fetch)} year(s)")
        return items

    def _fetch_year_advisories(self, year: int, seen_urls: set) -> List[Dict[str, Any]]:
        items = []
        year_url = f"{self.base_url}/s2cMainServlet?pageid=PUBADVLIST02&year={year}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': f'{self.base_url}/s2cMainServlet?pageid=PUBADVLIST02'
            }
            response = self.session.get(year_url, timeout=self.timeout, headers=headers)
            logger.info(f"Fetching CERT-In ({year}) [{response.status_code}]")
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            advisory_links = []
            seen_hrefs = set()
            
            all_links = soup.find_all('a', href=True)
            for link in all_links:
                href = link.get('href', '').strip()
                text = link.get_text(strip=True).strip()
                if not href:
                    continue
                    
                if '?' in href:
                    query_part = href.split('?', 1)[1]
                    if 'VLCODE=' in query_part:
                        vlcode_match = re.search(r'VLCODE=([^&]+)', query_part)
                        if vlcode_match:
                            vlcode = vlcode_match.group(1)
                            if vlcode not in seen_hrefs:
                                seen_hrefs.add(vlcode)
                                advisory_links.append(link)
                                continue
                                
                if 's2cMainServlet' in href and 'VLCODE=' in href:
                    vlcode_match = re.search(r'VLCODE=([^&]+)', href)
                    if vlcode_match:
                        vlcode = vlcode_match.group(1)
                        if vlcode not in seen_hrefs:
                            seen_hrefs.add(vlcode)
                            advisory_links.append(link)
                            continue
                            
                if text and re.search(r'CIAD-\d{4}-\d{3,4}', text, re.I):
                    if 's2cMainServlet' in href or 'PUBVLNOTES' in href or 'PUBADVLIST' in href:
                        norm_href = href.split('?')[0] if '?' in href else href
                        if norm_href not in seen_hrefs:
                            seen_hrefs.add(norm_href)
                            advisory_links.append(link)
                            
            if len(advisory_links) < 5:
                table_cells = soup.find_all(['td', 'th'])
                for cell in table_cells:
                    links = cell.find_all('a', href=True)
                    for link in links:
                        href = link.get('href', '').strip()
                        if not href:
                            continue
                        if 'VLCODE=' in href:
                            vlcode_match = re.search(r'VLCODE=([^&]+)', href)
                            if vlcode_match:
                                vlcode = vlcode_match.group(1)
                                if vlcode not in seen_hrefs:
                                    seen_hrefs.add(vlcode)
                                    advisory_links.append(link)
                                    
            logger.info(f"Found {len(advisory_links)} advisory links for year {year}")
            
            for link in advisory_links:
                try:
                    href = link.get('href', '')
                    text = link.get_text(strip=True)
                    if not text or len(text.strip()) < 5:
                        continue
                        
                    if href.startswith('http'):
                        full_url = href
                    elif href.startswith('/'):
                        full_url = f"{self.base_url}{href}"
                    elif 'VLCODE=' in href:
                        if 's2cMainServlet' in href:
                            if href.startswith('s2cMainServlet'):
                                full_url = f"{self.base_url}/{href}"
                            else:
                                full_url = f"{self.base_url}/{href}" if not href.startswith('/') else f"{self.base_url}{href}"
                        else:
                            vlcode_match = re.search(r'VLCODE=([^&]+)', href)
                            if vlcode_match:
                                vlcode = vlcode_match.group(1)
                                full_url = f"{self.base_url}/s2cMainServlet?VLCODE={vlcode}&pageid=PUBVLNOTES02"
                            elif href.startswith('?'):
                                full_url = f"{self.base_url}/s2cMainServlet{href}"
                            else:
                                full_url = f"{self.base_url}/s2cMainServlet?VLCODE={href}&pageid=PUBVLNOTES02"
                    elif href.startswith('s2cMainServlet'):
                        full_url = f"{self.base_url}/{href}"
                    else:
                        full_url = f"{self.base_url}/{href}"
                        
                    advisory_code = None
                    vlcode_from_text = None
                    
                    if 'VLCODE=' in href:
                        vlcode_match = re.search(r'VLCODE=([^&]+)', href)
                        if vlcode_match:
                            vlcode_from_text = vlcode_match.group(1)
                            advisory_code = vlcode_from_text
                            
                    if not advisory_code and 'CIAD-' in text:
                        match = re.search(r'CIAD-(\d{4})-(\d{3,4})', text, re.I)
                        if match:
                            year_part = match.group(1)
                            num_part = match.group(2).zfill(4)
                            advisory_code = f"CIAD-{year_part}-{num_part}"
                            vlcode_from_text = advisory_code
                            
                    if not advisory_code and link.parent:
                        parent_text = link.parent.get_text(strip=True)
                        match = re.search(r'CIAD-(\d{4})-(\d{4})', parent_text)
                        if match:
                            year_part = match.group(1)
                            num_part = match.group(2)
                            advisory_code = f"CIAD-{year_part}-{num_part}"
                        else:
                            match = re.search(r'CIAD-(\d{4})-(\d{3,4})', parent_text)
                            if match:
                                year_part = match.group(1)
                                num_part = match.group(2).zfill(4)
                                advisory_code = f"CIAD-{year_part}-{num_part}"
                                
                    if not advisory_code and 'VLCODE=' in href:
                        match = re.search(r'VLCODE=([^&]+)', href)
                        if match:
                            vlcode = match.group(1)
                            ciad_match = re.search(r'CIAD-(\d{4})-(\d{4})', vlcode)
                            if ciad_match:
                                advisory_code = f"CIAD-{ciad_match.group(1)}-{ciad_match.group(2)}"
                            else:
                                ciad_match = re.search(r'CIAD-(\d{4})-(\d{3,4})', vlcode)
                                if ciad_match:
                                    num_part = ciad_match.group(2).zfill(4)
                                    advisory_code = f"CIAD-{ciad_match.group(1)}-{num_part}"
                                elif re.match(r'CIAD-\d{4}-\d{3,4}', vlcode):
                                    match = re.search(r'CIAD-(\d{4})-(\d{3,4})', vlcode)
                                    if match:
                                        num_part = match.group(2).zfill(4)
                                        advisory_code = f"CIAD-{match.group(1)}-{num_part}"
                                    else:
                                        advisory_code = vlcode
                                        
                    if vlcode_from_text and 'VLCODE=' not in full_url:
                        full_url = f"{self.base_url}/s2cMainServlet?VLCODE={vlcode_from_text}&pageid=PUBVLNOTES02"
                        
                    dedup_key = full_url
                    if advisory_code:
                        dedup_key = f"{advisory_code}-{year}"
                        
                    if dedup_key in seen_urls:
                        continue
                        
                    seen_urls.add(dedup_key)
                    advisory_data = self._fetch_full_advisory(full_url, link, text, year)
                    
                    title = advisory_data.get('title', text.strip())
                    description = advisory_data.get('description', text)
                    published_date = advisory_data.get('published_date', self._extract_date_from_advisory(link, text, year))
                    severity = advisory_data.get('severity', '')
                    cve_ids = advisory_data.get('cve_ids', [])
                    
                    if len(title) > 200:
                        title = title[:200] + '...'
                        
                    tags = ['CERT-In', 'India', 'Government Advisory', str(year)]
                    if severity:
                        tags.append(f'Severity: {severity}')
                    if cve_ids:
                        tags.extend([f'CVE: {cve}' for cve in cve_ids[:5]])
                        
                    items.append({
                        'category': 'cert-in',
                        'title': title,
                        'description': description[:1000] if description else f'CERT-In Advisory for {year}',
                        'source': 'CERT-In',
                        'source_url': full_url,
                        'published_date': published_date,
                        'severity': severity if severity else None,
                        'cve_id': advisory_code if advisory_code else '',
                        'tags': tags,
                        'raw_data': {
                            'url': full_url,
                            'year': year,
                            'advisory_code': advisory_code,
                            'method': 'year_page',
                            'cve_ids': cve_ids
                        }
                    })
                except Exception:
                    continue
                    
        except Exception as e:
            logger.warning(f"Error fetching CERT-In advisories for year {year}: {e}")
            
        return items

    def _fetch_full_advisory(self, advisory_url: str, link_element, text: str, year: int) -> Dict[str, Any]:
        """Fetch the actual advisory page to extract structured data (title, description, date, severity, CVEs)"""
        result = {
            'title': text.strip(),
            'description': text,
            'published_date': None,
            'severity': '',
            'cve_ids': []
        }
        try:
            response = self.session.get(advisory_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                title_span = None
                print_content = soup.find(id='print_content')
                
                if print_content:
                    tables = print_content.find_all('table')
                    if len(tables) >= 2:
                        table2 = tables[1]
                        tbody = table2.find('tbody')
                        if tbody:
                            trs = tbody.find_all('tr')
                            if len(trs) >= 1:
                                tr1 = trs[0]
                                td = tr1.find('td')
                                if td:
                                    li = td.find('li')
                                    if li:
                                        a = li.find('a')
                                        if a:
                                            span = a.find('span')
                                            if span:
                                                b = span.find('b')
                                                if b:
                                                    title_span = b.find('span', class_='verblue2')
                                                    
                if title_span:
                    title_text = title_span.get_text(strip=True)
                    if title_text:
                        result['title'] = title_text
                        
                if result['title'] == text.strip():
                    verblue2_spans = soup.find_all('span', class_='verblue2')
                    for span in verblue2_spans:
                        span_text = span.get_text(strip=True)
                        if 'CIAD-' in span_text and len(span_text) > 10:
                            result['title'] = span_text
                            break
                            
                date_span = None
                if print_content:
                    tables = print_content.find_all('table')
                    if len(tables) >= 2:
                        table2 = tables[1]
                        tbody = table2.find('tbody')
                        if tbody:
                            trs = tbody.find_all('tr')
                            if len(trs) >= 2:
                                tr2 = trs[1]
                                td = tr2.find('td')
                                if td:
                                    date_span = td.find('span', class_=lambda x: x and ('DateContent' in x or ('contentTD' in x and 'Date' in str(x))))
                                    
                if date_span:
                    date_text = date_span.get_text(strip=True)
                    date_match = re.search(r'\(?\s*(\w+\s+\d{1,2},\s+\d{4})\s*\)?', date_text)
                    if date_match:
                        date_str = date_match.group(1).strip()
                        date_str = re.sub(r'\s+', ' ', date_str)
                        try:
                            dt = datetime.strptime(date_str, '%B %d, %Y')
                            result['published_date'] = dt.strftime('%Y-%m-%d')
                        except Exception:
                            pass
                            
                if not result['published_date']:
                    page_text = soup.get_text()
                    date_patterns = [
                        r'\(?\s*(\w+\s+\d{1,2},\s+\d{4})\s*\)?',
                        r'Date[:\s]+(\w+\s+\d{1,2},\s+\d{4})',
                        r'Published[:\s]+(\w+\s+\d{1,2},\s+\d{4})',
                        r'(\d{1,2}[/-]\d{1,2}[/-]\d{4})',
                    ]
                    for pattern in date_patterns:
                        matches = re.finditer(pattern, page_text, re.IGNORECASE)
                        for match in matches:
                            date_str = match.group(1).strip()
                            try:
                                if ',' in date_str:
                                    dt = datetime.strptime(date_str, '%B %d, %Y')
                                    result['published_date'] = dt.strftime('%Y-%m-%d')
                                    break
                                elif '/' in date_str:
                                    parts = date_str.split('/')
                                    if len(parts) == 3:
                                        if len(parts[2]) == 4:
                                            result['published_date'] = f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
                                        else:
                                            result['published_date'] = f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
                                        break
                            except Exception:
                                continue
                        if result['published_date']:
                            break
                            
                description_text = None
                if print_content:
                    tables = print_content.find_all('table')
                    if len(tables) >= 2:
                        table2 = tables[1]
                        tbody = table2.find('tbody')
                        if tbody:
                            trs = tbody.find_all('tr')
                            if len(trs) >= 3:
                                tr3 = trs[2]
                                td = tr3.find('td')
                                if td:
                                    div = td.find('div')
                                    if div:
                                        span = div.find('span')
                                        if span:
                                            description_text = span.get_text(strip=True)
                                            if description_text and len(description_text) > 20:
                                                result['description'] = description_text
                                                
                if not result['description'] or result['description'] == text:
                    content_elements = soup.find_all(['div', 'p', 'span'], class_=re.compile(r'content|description|summary', re.I))
                    descriptions = []
                    for elem in content_elements:
                        desc_text = elem.get_text(strip=True)
                        if desc_text and len(desc_text) > 50:
                            descriptions.append(desc_text)
                    if descriptions:
                        result['description'] = ' '.join(descriptions[:3])
                    else:
                        paragraphs = soup.find_all('p')
                        para_texts = [p.get_text(strip=True) for p in paragraphs if len(p.get_text(strip=True)) > 50]
                        if para_texts:
                            result['description'] = ' '.join(para_texts[:3])
                            
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                page_text = soup.get_text()
                cve_matches = re.findall(cve_pattern, page_text, re.IGNORECASE)
                if cve_matches:
                    result['cve_ids'] = list(set(cve_matches))
                    
                severity_patterns = [
                    r'(Critical|High|Medium|Low)\s+Severity',
                    r'Severity[:\s]+(Critical|High|Medium|Low)',
                    r'Risk[:\s]+(Critical|High|Medium|Low)'
                ]
                for pattern in severity_patterns:
                    match = re.search(pattern, page_text, re.IGNORECASE)
                    if match:
                        result['severity'] = match.group(1).capitalize()
                        break
        except Exception:
            pass
            
        if not result['published_date']:
            result['published_date'] = self._extract_date_from_advisory(link_element, text, year)
        return result

    def _extract_date_from_advisory(self, link_element, text: str, year: int) -> str:
        """Extract date from advisory link, parent element, and nearby text"""
        search_texts = [text]
        if link_element.parent:
            parent_text = link_element.parent.get_text(strip=True)
            if parent_text and parent_text != text:
                search_texts.append(parent_text)
                
        if link_element.parent:
            for sibling in link_element.parent.find_all(['span', 'td', 'div', 'li'], recursive=False):
                sibling_text = sibling.get_text(strip=True)
                if sibling_text and sibling_text != text:
                    search_texts.append(sibling_text)
                    
        if link_element.previous_sibling:
            prev_text = str(link_element.previous_sibling).strip()
            if prev_text and len(prev_text) < 200:
                search_texts.append(prev_text)
                
        if link_element.next_sibling:
            next_text = str(link_element.next_sibling).strip()
            if next_text and len(next_text) < 200:
                search_texts.append(next_text)
                
        date_patterns = [
            r'\((\w+ \d{1,2}, \d{4})\)',
            r'(\w+ \d{1,2}, \d{4})',
            r'(\d{1,2}[/-]\d{1,2}[/-]\d{4})',
            r'(\d{4}[/-]\d{1,2}[/-]\d{1,2})',
        ]
        
        for search_text in search_texts:
            for pattern in date_patterns:
                match = re.search(pattern, search_text)
                if match:
                    date_str = match.group(1)
                    try:
                        if ',' in date_str:
                            dt = datetime.strptime(date_str.strip(), '%B %d, %Y')
                            return dt.strftime('%Y-%m-%d')
                        elif '/' in date_str:
                            parts = date_str.split('/')
                            if len(parts) == 3:
                                if len(parts[2]) == 4:
                                    return f"{parts[0]}-{parts[1].zfill(2)}-{parts[2].zfill(2)}"
                                else:
                                    return f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
                        elif '-' in date_str:
                            parts = date_str.split('-')
                            if len(parts) == 3:
                                if len(parts[0]) == 4:
                                    return date_str
                                else:
                                    return f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
                    except Exception:
                        continue
        return f"{year}-01-01"


class IRDAIFetcher(BaseFetcher):
    """Fetch IRDAI (Insurance Regulatory and Development Authority of India) advisories"""
    def __init__(self):
        super().__init__()
        self.base_url = "https://irdai.gov.in"
        self.timeout = 30
        self.urls_to_check = [
            "https://irdai.gov.in/department/it",
            "https://irdai.gov.in/circulars",
            "https://irdai.gov.in/orders",
            "https://irdai.gov.in/advisories",
            "https://irdai.gov.in/notifications",
        ]

    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch IRDAI advisories from all relevant pages"""
        all_items = []
        seen_urls = set()
        
        try:
            items = self._fetch_from_url("https://irdai.gov.in/department/it", seen_urls)
            all_items.extend(items)
            
            response = self.session.get(self.base_url, timeout=self.timeout)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                advisory_links = soup.find_all('a', href=True, string=lambda x: x and any(
                    keyword in x.lower() for keyword in ['advisory', 'circular', 'order', 'notification', 'it', 'cyber', 'security']
                ))
                
                for link in advisory_links[:20]:
                    href = link.get('href', '').strip()
                    if not href or href.startswith('#') or href.startswith('javascript:'):
                        continue
                        
                    if href.startswith('http'):
                        url = href
                    elif href.startswith('/'):
                        url = f"{self.base_url}{href}"
                    else:
                        continue
                        
                    if url in seen_urls:
                        continue
                        
                    items = self._fetch_from_url(url, seen_urls)
                    all_items.extend(items)
        except Exception as e:
            logger.warning(f"Error exploring IRDAI pages: {e}")
            
        for url in self.urls_to_check:
            try:
                items = self._fetch_from_url(url, seen_urls)
                all_items.extend(items)
            except Exception:
                pass
                
        logger.info(f"Fetched {len(all_items)} IRDAI advisories total")
        return all_items

    def _fetch_from_url(self, url: str, seen_urls: set) -> List[Dict[str, Any]]:
        """Fetch advisories from a specific URL"""
        items = []
        try:
            response = self.session.get(url, timeout=self.timeout)
            logger.debug(f"Fetching IRDAI from {url} [{response.status_code}]")
            
            if response.status_code != 200:
                return items
                
            soup = BeautifulSoup(response.content, 'html.parser')
            all_links = soup.find_all('a', href=True)
            
            for link in all_links:
                href = link.get('href', '').strip()
                text = link.get_text(strip=True)
                
                if not text or len(text) < 10:
                    continue
                    
                parent_classes = []
                parent = link.parent
                for _ in range(3):
                    if parent and hasattr(parent, 'get'):
                        class_attr = parent.get('class', [])
                        if class_attr:
                            parent_classes.extend([str(c).lower() for c in class_attr])
                        parent = parent.parent if hasattr(parent, 'parent') else None
                        
                skip_keywords = ['nav', 'header', 'footer', 'menu', 'sidebar', 'breadcrumb']
                if any(keyword in ' '.join(parent_classes) for keyword in skip_keywords):
                    continue
                    
                if any(skip in text.lower() for skip in ['home', 'contact', 'login', 'search', 'sitemap', 'privacy', 'terms']):
                    continue
                    
                if href.startswith('http://') or href.startswith('https://'):
                    full_url = href
                elif href.startswith('//'):
                    full_url = f"https:{href}"
                elif href.startswith('/'):
                    full_url = f"{self.base_url}{href}"
                elif href.startswith('javascript:') or href.startswith('#'):
                    continue
                else:
                    if '/' in url:
                        base_path = '/'.join(url.split('/')[:-1])
                        full_url = f"{base_path}/{href}" if not base_path.endswith('/') else f"{base_path}{href}"
                    else:
                        full_url = f"{self.base_url}/{href}"
                        
                if '#' in full_url:
                    full_url = full_url.split('#')[0]
                    
                if full_url in seen_urls:
                    continue
                    
                seen_urls.add(full_url)
                published_date = self._extract_date_from_context(link)
                description = self._extract_description(link)
                
                exclude_keywords = ['vacancy', 'vacancies', 'recruitment', 'job', 'jobs', 'career', 'careers',
                                   'application', 'apply', 'tender', 'tenders', 'bidding', 'auction']
                text_lower = text.lower()
                desc_lower = description.lower() if description else ''
                full_url_lower = full_url.lower()
                
                if any(exclude_word in text_lower or exclude_word in desc_lower or exclude_word in full_url_lower
                       for exclude_word in exclude_keywords):
                    continue
                    
                if text.strip().lower() in ['(click here)', 'click here', 'here', 'view', 'read more', 'more']:
                    continue
                    
                advisory_keywords = ['advisory', 'circular', 'order', 'guideline', 'directive',
                                   'instruction', 'cyber', 'security', 'it', 'data', 'privacy',
                                   'breach', 'incident', 'alert', 'warning', 'threat']
                                   
                if not any(keyword in text_lower or keyword in desc_lower for keyword in advisory_keywords):
                    continue
                    
                items.append({
                    'category': 'cert-in',
                    'title': text[:200],
                    'description': description[:500] if description else f'IRDAI Advisory: {text[:200]}',
                    'source': 'IRDAI',
                    'source_url': full_url,
                    'published_date': published_date,
                    'tags': ['IRDAI', 'India', 'Government Advisory'],
                    'raw_data': {'url': full_url, 'text': text, 'source_page': url}
                })
        except Exception as e:
            logger.warning(f"Error fetching IRDAI from {url}: {e}")
        return items

    def _extract_date_from_context(self, link) -> str:
        """Extract published date from link's context"""
        published_date = datetime.utcnow().isoformat()
        
        for level in range(5):
            parent = link.parent if level == 0 else (parent.parent if hasattr(parent, 'parent') and parent else None)
            if not parent:
                break
                
            parent_text = parent.get_text()
            date_patterns = [
                r'(\d{1,2}[/-]\d{1,2}[/-]\d{4})',
                r'(\d{4}[/-]\d{1,2}[/-]\d{1,2})',
                r'(\w{3,9}\s+\d{1,2},?\s+\d{4})',
                r'(\d{1,2}\s+\w{3,9}\s+\d{4})',
            ]
            
            for pattern in date_patterns:
                date_match = re.search(pattern, parent_text)
                if date_match:
                    try:
                        date_str = date_match.group(1)
                        if '/' in date_str and len(date_str.split('/')) == 3:
                            parts = date_str.split('/')
                            if len(parts) == 3:
                                if len(parts[2]) == 4:
                                    return f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
                                elif len(parts[0]) == 4:
                                    return f"{parts[0]}-{parts[1].zfill(2)}-{parts[2].zfill(2)}"
                        elif '-' in date_str and len(date_str.split('-')) == 3:
                            parts = date_str.split('-')
                            if len(parts) == 3:
                                if len(parts[2]) == 4:
                                    return f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
                                elif len(parts[0]) == 4:
                                    return date_str
                                    
                        from datetime import datetime as dt
                        for fmt in ['%b %d, %Y', '%B %d, %Y', '%d %b %Y', '%d %B %Y']:
                            try:
                                parsed = dt.strptime(date_str, fmt)
                                return parsed.isoformat()
                            except:
                                continue
                    except Exception:
                        continue
                    break
        return published_date

    def _extract_description(self, link) -> str:
        """Extract description from link's context"""
        description = ''
        parent = link.parent
        if parent:
            parent_text = parent.get_text(strip=True)
            if len(parent_text) > len(link.get_text(strip=True)):
                description = parent_text[:500]
                
        if not description or len(description) < 50:
            next_sibling = link.next_sibling
            if next_sibling:
                if hasattr(next_sibling, 'get_text'):
                    description = next_sibling.get_text(strip=True)[:500]
                elif isinstance(next_sibling, str):
                    description = next_sibling.strip()[:500]
        return description


class RBIFetcher(BaseFetcher):
    """Fetch RBI (Reserve Bank of India) Advisories from Press Releases page"""
    def __init__(self):
        super().__init__()
        self.base_url = "https://www.rbi.org.in"
        self.press_releases_url = "https://www.rbi.org.in/commonman/English/scripts/PressReleases.aspx"
        self.timeout = 30

    def fetch(self) -> List[Dict[str, Any]]:
        """Fetch RBI Advisories from Press Releases page"""
        items = []
        seen_urls = set()
        
        try:
            logger.info(f"Fetching RBI Press Releases from: {self.press_releases_url}")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            }
            response = self.session.get(self.press_releases_url, timeout=self.timeout, headers=headers)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            press_links = []
            
            for link in soup.find_all('a', href=True):
                href = link.get('href', '').strip()
                if not href:
                    continue
                    
                if 'PressRelease' in href or 'pressrelease' in href.lower() or 'PressReleases' in href:
                    if href.startswith('/'):
                        full_url = f"{self.base_url}{href}"
                    elif href.startswith('http'):
                        full_url = href
                    else:
                        full_url = f"{self.base_url}/{href}"
                        
                    if full_url not in seen_urls:
                        seen_urls.add(full_url)
                        title = link.get_text(strip=True)
                        if title and len(title) > 5:
                            press_links.append({
                                'url': full_url,
                                'title': title,
                                'element': link
                            })
                            
            if not press_links:
                for td in soup.find_all('td'):
                    link = td.find('a', href=True)
                    if link:
                        href = link.get('href', '').strip()
                        if href and ('PressRelease' in href or 'pressrelease' in href.lower()):
                            if href.startswith('/'):
                                full_url = f"{self.base_url}{href}"
                            elif href.startswith('http'):
                                full_url = href
                            else:
                                full_url = f"{self.base_url}/{href}"
                                
                            if full_url not in seen_urls:
                                seen_urls.add(full_url)
                                title = link.get_text(strip=True) or td.get_text(strip=True)
                                if title and len(title) > 5:
                                    press_links.append({
                                        'url': full_url,
                                        'title': title,
                                        'element': link
                                    })
                                    
            for press_item in press_links[:100]:
                try:
                    url = press_item['url']
                    title = press_item['title']
                    published_date = datetime.utcnow().isoformat()
                    
                    parent = press_item['element'].parent
                    if parent:
                        date_text = parent.get_text()
                        date_patterns = [
                            r'(\d{1,2})[/-](\d{1,2})[/-](\d{4})',
                            r'(\d{4})[/-](\d{1,2})[/-](\d{1,2})',
                        ]
                        for pattern in date_patterns:
                            match = re.search(pattern, date_text)
                            if match:
                                try:
                                    if len(match.group(3)) == 4:
                                        day, month, year = match.groups()
                                    else:
                                        year, month, day = match.groups()
                                    published_date = datetime(int(year), int(month), int(day)).isoformat()
                                    break
                                except:
                                    pass
                                    
                    items.append({
                        'category': 'cert-in',
                        'title': title[:200] if title else 'RBI Press Release',
                        'description': f'RBI Press Release: {title[:200] if title else "Advisory"}',
                        'source': 'RBI',
                        'source_url': url,
                        'published_date': published_date,
                        'tags': ['RBI', 'India', 'Government Advisory', 'Press Release'],
                        'raw_data': {
                            'url': url,
                            'feed_type': 'Press Release',
                            'source_url': self.press_releases_url
                        }
                    })
                except Exception:
                    continue
            logger.info(f"Total fetched {len(items)} RBI Advisories from Press Releases page")
        except Exception as e:
            logger.error(f"Error fetching RBI Advisories: {e}", exc_info=True)
        return items


def fetch_all_sources(historical: bool = False, category_filter: Optional[str] = None, hours: int = 24) -> List[Dict[str, Any]]:
    from models import Database
    try:
        from sitemap_parser import fetch_historical_from_sitemap
    except ImportError:
        fetch_historical_from_sitemap = None
        logger.warning("sitemap_parser.fetch_historical_from_sitemap not available, sitemap fetching disabled")
    
    # Convert hours to days for CVE fetcher
    days_back = max(1, hours // 24)
    logger.info(f"Fetching sources with time range: {hours} hours ({days_back} days)")
        
    db = Database()
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    cursor.execute("SELECT source_name, enabled FROM source_settings")
    source_settings_rows = cursor.fetchall()
    
    enabled_sources = {}
    for row in source_settings_rows:
        if isinstance(row, dict):
            enabled_sources[row['source_name']] = row['enabled']
        else:
            enabled_sources[row[0]] = row[1]
            
    cursor.close()
    conn.close()
    
    def is_source_enabled(source_name: str) -> bool:
        return enabled_sources.get(source_name, True)
        
    all_items = []
    
    if category_filter is None or category_filter == 'cve':
        logger.info(f"Fetching CVEs for last {days_back} days...")
        cve_fetcher = CVEFetcher()
        if historical and db.should_fetch_historical('CVE'):
            logger.info("First-time CVE fetch: Getting ALL available historical data (this may take a while)...")
            for years in [10, 15, 20, 30]:
                days = years * 365
                logger.info(f"Trying to fetch {years} years of CVEs...")
                items = cve_fetcher.safe_fetch(days_back=days)
                if items:
                    all_items.extend(items)
                    oldest_date = min([item.get('published_date', '') for item in items if item.get('published_date')], default=None)
                    try:
                        db.update_fetch_history('CVE', fetch_type='historical', last_item_date=oldest_date, items_fetched=len(items))
                    except Exception as e:
                        logger.warning(f"Could not update fetch history for CVE: {e}")
                    logger.info(f"Successfully fetched {len(items)} CVEs from {years} years")
                    break
                else:
                    logger.warning(f"No CVEs found for {years} years, trying less...")
        else:
            logger.info(f"Incremental CVE fetch: Getting last {days_back} days...")
            items = cve_fetcher.safe_fetch(days_back=days_back)
            all_items.extend(items)
            if items:
                newest_date = max([item.get('published_date', '') for item in items if item.get('published_date')], default=None)
                try:
                    db.update_fetch_history('CVE', fetch_type='incremental', last_item_date=newest_date, items_fetched=len(items))
                except Exception as e:
                    logger.warning(f"Could not update fetch history for CVE: {e}")
                    
    feed_parser = FeedParser()
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    param = db._get_param_placeholder()
    
    try:
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = 'data_sources'
        """)
        table_exists = cursor.fetchone()
        if isinstance(table_exists, dict):
            table_exists = table_exists.get('COUNT(*)', 0) > 0
        else:
            table_exists = (table_exists[0] if table_exists else 0) > 0
            
        if not table_exists:
            logger.warning("data_sources table does not exist. Please run create_mysql_tables.sql")
            cursor.close()
            conn.close()
            return all_items
    except Exception as e:
        logger.warning(f"Error checking for data_sources table: {e}")
        cursor.close()
        conn.close()
        return all_items
        
    where_clause = "enabled = TRUE"
    params = []
    if category_filter:
        where_clause += f" AND category = {param}"
        params.append(category_filter)
        
    try:
        cursor.execute(f"""
            SELECT source_name, feed_url, feed_type, category
            FROM data_sources
            WHERE {where_clause}
            ORDER BY category, source_name
        """, params)
    except Exception as e:
        logger.warning(f"Error querying data_sources table: {e}. Table may not exist or have wrong schema.")
        cursor.close()
        conn.close()
        return all_items
        
    db_sources = []
    for row in cursor.fetchall():
        if isinstance(row, dict):
            db_sources.append({
                'name': row.get('source_name', ''),
                'url': row.get('feed_url', ''),
                'type': row.get('feed_type', 'rss'),
                'category': row.get('category', '')
            })
        else:
            db_sources.append({
                'name': row[0] if len(row) > 0 else '',
                'url': row[1] if len(row) > 1 else '',
                'type': row[2] if len(row) > 2 else 'rss',
                'category': row[3] if len(row) > 3 else ''
            })
            
    cursor.close()
    conn.close()
    
    # Prioritize RSS feeds for 24-hour fetches (they're better for recent content)
    if not historical:
        # Separate RSS feeds from sitemaps
        rss_sources = [s for s in db_sources if s.get('type', '').lower() in ['rss', 'xml', 'atom']]
        sitemap_sources = [s for s in db_sources if s.get('type', '').lower() == 'sitemap']
        other_sources = [s for s in db_sources if s.get('type', '').lower() not in ['rss', 'xml', 'atom', 'sitemap']]
        
        # Process RSS first, then sitemaps, then others
        db_sources = rss_sources + sitemap_sources + other_sources
        if rss_sources:
            logger.info(f"Prioritizing {len(rss_sources)} RSS feed(s) for 24-hour fetch")
            
    for source in db_sources:
        if not source.get('url') or not source.get('name'):
            continue
            
        source_category = source.get('category', '')
        if source_category == 'ioc':
            continue
        if category_filter and source_category != category_filter:
            continue
            
        # For 24-hour fetches, process RSS feeds and recent sitemaps
        # Skip only old numbered sitemaps (they contain historical data)
        if not historical and source.get('type', '').lower() == 'sitemap':
            url = source.get('url', '').lower()
            source_name = source.get('name', '').lower()
            
            # Check if this is a numbered sitemap (e.g., sitemap2.xml, post-sitemap10.xml)
            # Pattern matches: sitemap2, sitemap-2, sitemap_2, post-sitemap10, etc.
            # But NOT "Sitemap 1" in the name (that's just a label, not the actual number)
            
            # Look for numbers in the URL (more reliable than name)
            url_num_match = re.search(r'sitemap[_-]?(\d+)|page=(\d+)', url)
            if url_num_match:
                sitemap_num = int(url_num_match.group(1) or url_num_match.group(2))
                # For non-historical fetches, process more sitemaps based on time range
                # 24h: process 1-5, 7d: process 1-20, 30d+: process all
                if hours <= 24:
                    max_sitemap = 5
                elif hours <= 168:  # 7 days
                    max_sitemap = 20  # Increased from 10 to 20
                elif hours <= 720:  # 30 days
                    max_sitemap = 50  # Process up to 50 sitemaps for 30 days
                else:
                    max_sitemap = 999  # Process all for longer periods
                
                if sitemap_num > max_sitemap:
                    logger.debug(f"Skipping old sitemap {source.get('name')} (number {sitemap_num}) for {hours}h fetch (max: {max_sitemap})")
                    continue
            # If no number in URL, check the name (but be more careful)
            elif 'sitemap' in source_name:
                # Look for patterns like "sitemap 10", "sitemap10", "sitemap-10"
                name_num_match = re.search(r'sitemap\s*[_-]?\s*(\d+)', source_name)
                if name_num_match:
                    sitemap_num = int(name_num_match.group(1))
                    if hours <= 24:
                        max_sitemap = 5
                    elif hours <= 168:  # 7 days
                        max_sitemap = 20  # Increased from 10 to 20
                    elif hours <= 720:  # 30 days
                        max_sitemap = 50  # Process up to 50 sitemaps for 30 days
                    else:
                        max_sitemap = 999  # Process all for longer periods
                    
                    if sitemap_num > max_sitemap:
                        logger.debug(f"Skipping old sitemap {source.get('name')} (number {sitemap_num}) for {hours}h fetch (max: {max_sitemap})")
                        continue
            
            # If we get here, process this sitemap
            logger.debug(f"Processing sitemap: {source.get('name')}")
                    
        try:
            link_archive = False
            result = feed_parser.parse(source['url'], source['type'], source['name'], source_category, historical=historical, link_archive=link_archive, hours=hours)
            
            if isinstance(result, tuple):
                items, status_code, feed_type = result
                from job_tracker import job_tracker
                if job_tracker.is_job_running():
                    time_str = datetime.now().strftime('%I:%M:%S %p')
                    job_tracker.update_job(message=f'[{time_str}] [{feed_type}] [{source["name"]}] [{status_code}]')
            else:
                items = result
                status_code = 200
                feed_type = source['type'].upper()
                
            all_items.extend(items)
        except Exception as e:
            logger.warning(f"Error fetching {source['name']}: {e}, continuing...")
            
    if category_filter is None or category_filter == 'exploit':
        logger.info("Fetching Exploits...")
        try:
            exploit_fetcher = ExploitDBFetcher()
            all_items.extend(exploit_fetcher.safe_fetch())
        except Exception as e:
            logger.warning(f"Error fetching Exploits: {e}, continuing...")
            
    if category_filter is None or category_filter == 'malware':
        logger.info("Fetching Malware...")
        try:
            malware_fetcher = MalwareBazaarFetcher()
            all_items.extend(malware_fetcher.safe_fetch())
        except Exception as e:
            logger.warning(f"Error fetching Malware: {e}, continuing...")
            
    if category_filter is None or category_filter == 'ransomware':
        logger.info("Fetching Ransomware...")
        
        # Fetch from ransomware.live
        try:
            ransomware_fetcher = RansomwareLiveFetcher()
            all_items.extend(ransomware_fetcher.safe_fetch())
        except Exception as e:
            logger.warning(f"Error fetching ransomware.live: {e}, continuing...")
        
        # Fetch from ransomlook.io
        try:
            ransomlook_fetcher = RansomLookFetcher()
            all_items.extend(ransomlook_fetcher.safe_fetch())
        except Exception as e:
            logger.warning(f"Error fetching ransomlook.io: {e}, continuing...")
            
    if category_filter is None or category_filter == 'cert-in':
        cert_fetcher = CERTInFetcher()
        if historical and db.should_fetch_historical('CERT-In'):
            logger.info("First-time CERT-In fetch: Getting ALL advisories for all years (2003-current)...")
            try:
                items = cert_fetcher.safe_fetch(historical=True, current_year_only=False)
                for item in items:
                    item['category'] = 'cert-in'
                    item['severity'] = ''
                all_items.extend(items)
                db.update_fetch_history('CERT-In', 'historical', None)
                logger.info(f"Fetched {len(items)} CERT-In advisories from all years")
            except Exception as e:
                logger.warning(f"Error fetching CERT-In (historical): {e}, continuing...")
        else:
            logger.info("Auto-refresh CERT-In: Fetching current year only to avoid duplicates...")
            try:
                items = cert_fetcher.safe_fetch(historical=False, current_year_only=True)
                for item in items:
                    item['category'] = 'cert-in'
                    item['severity'] = ''
                all_items.extend(items)
                db.update_fetch_history('CERT-In', 'incremental', None)
                logger.info(f"Fetched {len(items)} CERT-In advisories for current year only")
            except Exception as e:
                logger.warning(f"Error fetching CERT-In (refresh): {e}, continuing...")
                
        if (category_filter is None or category_filter == 'cert-in') and is_source_enabled('IRDAI'):
            logger.info("Fetching IRDAI advisories...")
            try:
                irdai_fetcher = IRDAIFetcher()
                items = irdai_fetcher.safe_fetch()
                all_items.extend(items)
                logger.info(f"Fetched {len(items)} IRDAI advisories")
            except Exception as e:
                logger.warning(f"Error fetching IRDAI: {e}, continuing...")
                
        if (category_filter is None or category_filter == 'cert-in') and is_source_enabled('RBI Directions'):
            logger.info("Fetching RBI Master Directions...")
            try:
                rbi_fetcher = RBIFetcher()
                items = rbi_fetcher.safe_fetch()
                all_items.extend(items)
                logger.info(f"Fetched {len(items)} RBI Master Directions")
            except Exception as e:
                logger.warning(f"Error fetching RBI: {e}, continuing...")
                
    logger.info("Fetching custom feeds...")
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        cursor.execute("SELECT name, url, category, feed_type FROM custom_feeds WHERE enabled = TRUE")
        custom_feeds_rows = cursor.fetchall()
        
        for feed_row in custom_feeds_rows:
            if isinstance(feed_row, dict):
                feed_name = feed_row['name']
                feed_url = feed_row['url']
                feed_category = feed_row['category']
                feed_type = feed_row['feed_type']
            else:
                feed_name, feed_url, feed_category, feed_type = feed_row
                
            try:
                result = feed_parser.parse(feed_url, feed_type, feed_name, feed_category)
                if isinstance(result, tuple):
                    items, status_code, feed_type_parsed = result
                    from job_tracker import job_tracker
                    if job_tracker.is_job_running():
                        time_str = datetime.now().strftime('%I:%M:%S %p')
                        job_tracker.update_job(message=f'[{time_str}] [{feed_type_parsed}] [{feed_name}] [{status_code}]')
                else:
                    items = result
                all_items.extend(items)
            except Exception as e:
                logger.warning(f"Error fetching custom feed {feed_name}: {e}, continuing...")
                
        cursor.close()
        conn.close()
    except Exception as e:
        logger.warning(f"Error fetching custom feeds: {e}")
        
    logger.info(f"Fetched {len(all_items)} total items")
    return all_items