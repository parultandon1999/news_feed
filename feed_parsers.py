import time
import random
import requests
import json
import csv
import io
import gzip
import xml.etree.ElementTree as ET
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, unquote

import feedparser
from bs4 import BeautifulSoup
import urllib3

logger = logging.getLogger(__name__)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
]


class FeedParser:
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def clean_title(self, title: str) -> str:
        """Clean title by removing common suffixes and unwanted patterns"""
        if not title:
            return title
        
        # Remove .html, .htm, .php, .aspx suffixes (case insensitive)
        title = re.sub(r'\.(html?|php|aspx)$', '', title, flags=re.IGNORECASE)
        
        # Remove trailing dashes or underscores that might be left
        title = re.sub(r'[-_]+$', '', title)
        
        # Clean up extra whitespace
        title = ' '.join(title.split())
        
        return title.strip()

    def parse(self, url: str, feed_type: str, source_name: str, category: str = None, 
              historical: bool = False, link_archive: bool = False, limit: int = None, hours: int = 24) -> Any:
        try:
            if feed_type == 'rss' or feed_type == 'xml':
                return self._parse_rss(url, source_name, category, historical, limit=limit, hours=hours)
            elif feed_type == 'sitemap':
                return self._parse_sitemap(url, source_name, category, historical, link_archive, limit=limit, hours=hours)
            elif feed_type == 'json':
                return self._parse_json(url, source_name, category)
            elif feed_type == 'csv':
                return self._parse_csv(url, source_name, category)
            elif feed_type == 'api':
                return self._parse_api(url, source_name, category)
            elif feed_type == 'txt':
                return self._parse_txt(url, source_name, category)
            else:
                logger.warning(f"Unknown feed type: {feed_type} for {url}")
                return [], 0, feed_type.upper()
        except Exception as e:
            logger.error(f"Error parsing {feed_type} feed {url}: {e}")
            return [], 0, feed_type.upper()

    def _parse_rss(self, url: str, source_name: str, category: str, historical: bool = False, limit: int = None, hours: int = 24) -> Tuple[List[Dict[str, Any]], int, str]:

        if 'packetstorm' in url.lower():  # for https://packetstorm.news/feeds/ site not to block me if it works
            time.sleep(5)

        items = []
        status_code = None
        feed_type = 'RSS'
        # Filter by time for incremental fetches - use dynamic hours
        cutoff_time = None
        if not historical:
            cutoff_time = datetime.utcnow().replace(tzinfo=None) - timedelta(hours=hours)
            logger.debug(f"RSS cutoff time set to {hours} hours ago: {cutoff_time}")
            
        try:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=True, stream=True)
                status_code = response.status_code
                response.raise_for_status()
            except requests.exceptions.SSLError:
                logger.warning(f"SSL error for {url}, trying without verification...")
                response = self.session.get(url, timeout=self.timeout, verify=False, stream=True)
                status_code = response.status_code
                response.raise_for_status()

                time.sleep(1)  # Wait 1 second between requests
                
            content = response.content
            if url.endswith('.gz') or url.endswith('.gzip') or 'gzip' in response.headers.get('content-type', '').lower():
                try:
                    content = gzip.decompress(content)
                except Exception:
                    try:
                        content = gzip.GzipFile(fileobj=io.BytesIO(response.content)).read()
                    except Exception:
                        content = response.content
                        
            feed = feedparser.parse(content)
            
            if not hasattr(feed, 'entries') or not feed.entries:
                logger.warning(f"No entries found in RSS feed: {url}")
                return items, status_code, feed_type
            
            if status_code:
                logger.info(f"[{feed_type}] [{source_name}] [{status_code}]")
            
            total_entries = len(feed.entries)
            filtered_count = 0
            
            for entry in feed.entries:
                published_date = ''
                entry_datetime = None
                
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    try:
                        if len(entry.published_parsed) >= 6:
                            entry_datetime = datetime(*entry.published_parsed[:6])
                            published_date = entry_datetime.isoformat()
                        elif hasattr(entry, 'published'):
                            try:
                                entry_datetime = datetime.fromisoformat(entry.published.replace('Z', '+00:00'))
                                published_date = entry_datetime.isoformat()
                            except:
                                pass
                    except Exception:
                        pass
                
                # Try updated_parsed if published_parsed is not available
                if not entry_datetime and hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    try:
                        if len(entry.updated_parsed) >= 6:
                            entry_datetime = datetime(*entry.updated_parsed[:6])
                            published_date = entry_datetime.isoformat()
                    except Exception:
                        pass
                        
                # Filter by cutoff time only if we have a valid date
                # If no date is available, include the item (it might be new)
                if not historical and cutoff_time and entry_datetime:
                    if entry_datetime < cutoff_time:
                        filtered_count += 1
                        continue
                        
                description = ''
                try:
                    if hasattr(entry, 'summary'):
                        description = str(entry.summary) if entry.summary else ''
                    elif hasattr(entry, 'description'):
                        description = str(entry.description) if entry.description else ''
                except Exception:
                    description = ''
                
                try:
                    if description:
                        soup = BeautifulSoup(description, 'html.parser')
                        description = soup.get_text()[:500]
                except Exception:
                    description = description[:500] if description else ''
                
                try:
                    title = entry.title.strip() if hasattr(entry, 'title') and entry.title else ''
                    title = self.clean_title(title)  # Clean the title
                except Exception:
                    title = ''
                    
                if not title or len(title) < 3 or title.lower() in ['csv entry', 'untitled', 'no title', '']:
                    continue
                if title.lower().startswith('csv') and 'entry' in title.lower():
                    continue
                    
                cve_id = ''
                if category == 'cve':
                    cve_pattern = r'CVE-\d{4}-\d{4,}'
                    title_match = re.search(cve_pattern, title)
                    desc_match = re.search(cve_pattern, description)
                    if title_match:
                        cve_id = title_match.group(0)
                    elif desc_match:
                        cve_id = desc_match.group(0)
                        
                image_url = None
                if hasattr(entry, 'media_thumbnail') and entry.media_thumbnail:
                    image_url = entry.media_thumbnail[0].get('url', '') if isinstance(entry.media_thumbnail, list) else getattr(entry.media_thumbnail, 'url', '')
                elif hasattr(entry, 'image') and entry.image:
                    image_url = getattr(entry.image, 'href', '') or getattr(entry.image, 'url', '')
                elif hasattr(entry, 'media_content') and entry.media_content:
                    for media in entry.media_content:
                        if hasattr(media, 'type') and 'image' in str(media.type).lower():
                            image_url = getattr(media, 'url', '')
                            break
                            
                meta_description = description[:500] if description else ''
                
                items.append({
                    'category': category,
                    'title': title[:200],
                    'description': description[:500] if description else '',
                    'meta_description': meta_description,
                    'image_url': image_url,
                    'source': source_name,
                    'source_url': entry.link if hasattr(entry, 'link') and entry.link else '',
                    'published_date': published_date,
                    'cve_id': cve_id,
                    'tags': ['RSS', source_name],
                    'raw_data': {'link': entry.link if hasattr(entry, 'link') else ''}
                })
                
            if limit and limit > 0 and items:
                try:
                    items.sort(key=lambda x: x.get('published_date', ''), reverse=True)
                    items = items[:limit]
                    logger.info(f"Limited RSS results to {len(items)} latest items (requested: {limit})")
                except Exception as e:
                    logger.warning(f"Error sorting/limiting RSS items: {e}")
            
            # Log filtering statistics
            if not historical and cutoff_time:
                time_desc = f"{hours} hours" if hours < 48 else f"{hours // 24} days"
                logger.info(f"[{feed_type}] [{source_name}] Processed {total_entries} entries, filtered {filtered_count} old items, kept {len(items)} recent items (last {time_desc})")
            else:
                logger.info(f"[{feed_type}] [{source_name}] Processed {total_entries} entries, kept {len(items)} items (historical mode)")
                    
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                logger.error(f"[{feed_type}] [{source_name}] [{status_code}] Error: {e}")
            else:
                status_code = 0
                logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
        except Exception as e:
            status_code = 0
            logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
            
        if status_code is None:
            status_code = 0
            
        return items, status_code, feed_type

    def _parse_json(self, url: str, source_name: str, category: str) -> Tuple[List[Dict[str, Any]], int, str]:
        items = []
        status_code = None
        feed_type = 'JSON'
        
        try:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=True)
                status_code = response.status_code
                response.raise_for_status()
            except requests.exceptions.SSLError:
                logger.warning(f"SSL error for {url}, trying without verification...")
                response = self.session.get(url, timeout=self.timeout, verify=False)
                status_code = response.status_code
                response.raise_for_status()
                
            if status_code:
                logger.info(f"[{feed_type}] [{source_name}] [{status_code}]")
                
            data = response.json()
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = data.get('items', data.get('data', data.get('results', [data])))
            else:
                entries = [data]
                
            for entry in entries[:100]:
                if isinstance(entry, dict):
                    title = entry.get('title', entry.get('name', entry.get('id', 'Untitled')))
                    title = self.clean_title(str(title))  # Clean the title
                    description = entry.get('description', entry.get('summary', entry.get('content', '')))
                    link = entry.get('url', entry.get('link', entry.get('href', '')))
                    published = entry.get('published', entry.get('date', entry.get('created', '')))
                    
                    items.append({
                        'category': category,
                        'title': str(title)[:200],
                        'description': str(description)[:500],
                        'source': source_name,
                        'source_url': link if link else '',
                        'published_date': published,
                        'tags': ['JSON', source_name],
                        'raw_data': entry
                    })
                    
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                logger.error(f"[{feed_type}] [{source_name}] [{status_code}] Error: {e}")
            else:
                status_code = 0
                logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
        except Exception as e:
            status_code = 0
            logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
            
        if status_code is None:
            status_code = 200
            
        return items, status_code, feed_type

    def _parse_csv(self, url: str, source_name: str, category: str) -> Tuple[List[Dict[str, Any]], int, str]:
        items = []
        status_code = None
        feed_type = 'CSV'
        
        try:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=True)
                status_code = response.status_code
                response.raise_for_status()
            except requests.exceptions.SSLError:
                logger.warning(f"SSL error for {url}, trying without verification...")
                response = self.session.get(url, timeout=self.timeout, verify=False)
                status_code = response.status_code
                response.raise_for_status()
                
            if status_code:
                logger.info(f"[{feed_type}] [{source_name}] [{status_code}]")
                
            content = response.content
            if url.endswith('.gz') or url.endswith('.gzip') or 'gzip' in response.headers.get('content-type', '').lower():
                try:
                    content = gzip.decompress(content).decode('utf-8', errors='ignore')
                except Exception:
                    try:
                        content = gzip.GzipFile(fileobj=io.BytesIO(response.content)).read().decode('utf-8', errors='ignore')
                    except Exception:
                        content = response.content.decode('utf-8', errors='ignore')
            else:
                try:
                    content = content.decode('utf-8', errors='ignore')
                except Exception:
                    try:
                        content = content.decode('latin-1', errors='ignore')
                    except Exception:
                        content = str(content)
                        
            if not content or not content.strip():
                logger.warning(f"Empty CSV content for {source_name}")
                return items, status_code, feed_type
                
            csv_reader = csv.DictReader(io.StringIO(content))
            fieldnames = csv_reader.fieldnames or []
            
            if not fieldnames:
                logger.warning(f"No column headers found in CSV for {source_name}")
                return items, status_code, feed_type
                
            logger.info(f"CSV columns for {source_name} ({category}): {fieldnames[:10]}")
            
            row_count = 0
            empty_row_count = 0
            
            for row in csv_reader:
                row_count += 1
                if category == 'ioc':
                    title = ''
                    description = ''
                    source_url = ''
                    published_date = ''
                    
                    url_val = None
                    for url_key in ['url', 'source.url', 'urlhaus_url', 'link']:
                        if url_key in row and row.get(url_key):
                            url_val = str(row[url_key]).strip()
                            if url_val and url_val != 'N/A' and not url_val.startswith('#') and len(url_val) > 3:
                                if url_val.startswith('http'):
                                    break
                                    
                    if url_val and url_val != 'N/A' and not url_val.startswith('#') and len(url_val) > 3:
                        if url_val.startswith('http'):
                            title = f"IOC: URL {url_val[:60]}"
                            description = f"Malicious URL: {url_val}"
                            source_url = url_val
                            
                    if not title:
                        ip_val = None
                        for ip_key in ['ip', 'source.ip', 'ip_address']:
                            if ip_key in row and row.get(ip_key):
                                ip_val = str(row[ip_key]).strip()
                                if ip_val and ip_val != 'N/A' and not ip_val.startswith('#') and '.' in ip_val:
                                    parts = ip_val.split('.')
                                    if len(parts) == 4 and all(p.isdigit() for p in parts):
                                        break
                                        
                        if ip_val and ip_val != 'N/A' and not ip_val.startswith('#') and '.' in ip_val:
                            title = f"IOC: IP {ip_val}"
                            description = f"Malicious IP Address: {ip_val}"
                            
                    if not title:
                        for hash_key in ['sha256_hash', 'sha256', 'hash', 'file_hash']:
                            if hash_key in row and row.get(hash_key):
                                hash_val = str(row[hash_key]).strip()
                                if hash_val and hash_val != 'N/A' and not hash_val.startswith('#') and len(hash_val) == 64:
                                    try:
                                        int(hash_val, 16)
                                        title = f"IOC: SHA256 {hash_val[:16]}..."
                                        description = f"SHA256 Hash: {hash_val}"
                                        break
                                    except ValueError:
                                        continue
                                        
                    if not title:
                        if 'domain' in row and row.get('domain'):
                            domain = str(row['domain']).strip()
                            if domain and domain != 'N/A' and not domain.startswith('#') and '.' in domain and not domain.replace('.', '').isdigit():
                                title = f"IOC: Domain {domain}"
                                description = f"Malicious Domain: {domain}"
                                
                    if not title:
                        skip_keys = ['id', 'dateadded', 'date', 'first_seen', 'published', 'index', 'row', 'num', 'count', 'url_status', 'urlhaus_link']
                        for key, value in row.items():
                            if key.lower() in skip_keys:
                                continue
                            if value and str(value).strip():
                                val_str = str(value).strip()
                                if val_str.startswith('#') or val_str == 'N/A':
                                    continue
                                if val_str.replace('-', '').replace('.', '').isdigit() and len(val_str) > 10:
                                    continue
                                if len(set(val_str)) <= 2 and len(val_str) > 10:
                                    continue
                                if len(val_str) > 3:
                                    title = f"IOC: {key} - {val_str[:60]}"
                                    description = f"{key}: {val_str}"
                                    break
                                    
                    if not title:
                        continue
                        
                    if not source_url:
                        source_url = row.get('url', row.get('urlhaus_link', row.get('link', row.get('reference', ''))))
                        
                    published_date = row.get('dateadded', row.get('first_seen', row.get('date', row.get('published', datetime.utcnow().isoformat()))))
                    
                    if not description or len(description) < 10:
                        desc_parts = []
                        for key, value in row.items():
                            if value and str(value).strip():
                                val_str = str(value).strip()
                                if key.lower() in ['id', 'index', 'row', 'num'] or val_str.startswith('#') or val_str == 'N/A':
                                    continue
                                if len(set(val_str)) <= 2 and len(val_str) > 10:
                                    continue
                                if key not in ['url', 'link', 'reference', 'urlhaus_link', 'source_url']:
                                    desc_parts.append(f"{key}: {val_str[:100]}")
                        if desc_parts:
                            description = ' | '.join(desc_parts[:5])
                        else:
                            description = f"IOC from {source_name}"
                            
                    items.append({
                        'category': category,
                        'title': title[:200],
                        'description': description[:1000] if description else f"IOC from {source_name}",
                        'source': source_name,
                        'source_url': source_url if source_url else '',
                        'published_date': published_date,
                        'severity': None,
                        'tags': ['IOC', source_name] + [str(v) for k, v in row.items() if v and k in ['type', 'ioc_type', 'threat_type', 'malware', 'signature']],
                        'raw_data': row
                    })
                else:
                    title = str(row.get('title', row.get('name', row.get('id', '')))).strip()
                    if not title or len(title) < 3 or title.lower() in ['csv entry', 'untitled', 'no title', '']:
                        continue
                    if title.lower().startswith('csv') and 'entry' in title.lower():
                        continue
                        
                    description = str(row.get('description', row.get('summary', '')))[:500]
                    link = str(row.get('url', row.get('link', '')))
                    published = str(row.get('published', row.get('date', '')))
                    
                    items.append({
                        'category': category,
                        'title': title[:200],
                        'description': description,
                        'source': source_name,
                        'source_url': link,
                        'published_date': published,
                        'tags': ['CSV', source_name],
                        'raw_data': row
                    })
                    
            if category == 'ioc':
                if row_count == 0:
                    logger.warning(f"No rows found in IOC CSV for {source_name}. CSV columns: {fieldnames}")
                elif len(items) == 0:
                    logger.warning(f"Parsed {row_count} rows from {source_name} but created 0 items. Empty rows: {empty_row_count}. Columns: {fieldnames[:10]}")
                    if row_count > 0:
                        csv_reader_sample = csv.DictReader(io.StringIO(content))
                        sample_row = next(csv_reader_sample, None)
                        if sample_row:
                            logger.warning(f"Sample row keys: {list(sample_row.keys())}")
                            logger.warning(f"Sample row values: {dict(list(sample_row.items())[:5])}")
                else:
                    logger.info(f"Parsed {len(items)} IOC items from {source_name} (processed {row_count} CSV rows, {empty_row_count} empty rows skipped)")
                    
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                logger.error(f"[{feed_type}] [{source_name}] [{status_code}] Error: {e}")
            else:
                status_code = 0
                logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
        except Exception as e:
            status_code = 0
            logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
            
        if status_code is None:
            status_code = 200
            
        return items, status_code, feed_type

    def _parse_sitemap(self, url: str, source_name: str, category: str, historical: bool = False, link_archive: bool = False, limit: int = None, hours: int = 24) -> Tuple[List[Dict[str, Any]], int, str]:
        items = []
        status_code = None
        feed_type = 'SITEMAP'
        cutoff_time = None
        
        if not historical:
            cutoff_time = datetime.utcnow().replace(tzinfo=None) - timedelta(hours=hours)
            logger.debug(f"Sitemap cutoff time set to {hours} hours ago: {cutoff_time}")
            
        try:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=True, stream=True)
                status_code = response.status_code
                response.raise_for_status()
            except requests.exceptions.SSLError:
                logger.warning(f"SSL error for {url}, trying without verification...")
                response = self.session.get(url, timeout=self.timeout, verify=False, stream=True)
                status_code = response.status_code
                response.raise_for_status()
                
            if status_code:
                logger.info(f"[{feed_type}] [{source_name}] [{status_code}]")
                
            content = response.content
            if url.endswith('.gz') or url.endswith('.gzip') or 'gzip' in response.headers.get('content-type', '').lower():
                try:
                    content = gzip.decompress(content)
                except Exception:
                    try:
                        content = gzip.GzipFile(fileobj=io.BytesIO(response.content)).read()
                    except Exception:
                        logger.warning(f"Failed to decompress gzip sitemap {url}")
                        return items, status_code, feed_type
                        
            if isinstance(content, bytes):
                try:
                    decoded_content = content.decode('utf-8', errors='ignore')
                except Exception:
                    try:
                        decoded_content = content.decode('latin-1', errors='ignore')
                    except Exception:
                        decoded_content = str(content)
            else:
                decoded_content = content
                
            if not decoded_content.strip().startswith('<?xml') and not decoded_content.strip().startswith('<'):
                lines = decoded_content.strip().split('\n')
                for line in lines[:200]:
                    line = line.strip()
                    if line and (line.startswith('http://') or line.startswith('https://')):
                        items.append({
                            'category': category if category else 'news',
                            'title': line.split('/')[-1].replace('-', ' ').replace('_', ' ').title()[:200],
                            'description': '',
                            'meta_description': '',
                            'image_url': None,
                            'source': source_name,
                            'source_url': line,
                            'published_date': '',
                            'tags': [],
                            'raw_data': {'url': line},
                            '_sort_date': datetime.min.replace(tzinfo=None)
                        })
                if limit and limit > 0:
                    items = items[:limit]
                for item in items:
                    item.pop('_sort_date', None)
                logger.info(f"Parsed {len(items)} URLs from text sitemap {source_name}" + (f" (limited to {limit})" if limit else ""))
                return items, status_code, feed_type
                
            if isinstance(content, str):
                content = content.encode('utf-8')
                
            if content.startswith(b'\xef\xbb\xbf'):
                content = content[3:]
            elif content.startswith(b'\xff\xfe') or content.startswith(b'\xfe\xff'):
                try:
                    content = content.decode('utf-16').encode('utf-8')
                except Exception:
                    pass
                    
            try:
                root = ET.fromstring(content)
            except ET.ParseError:
                try:
                    decoded = content.decode('utf-8', errors='ignore')
                    root = ET.fromstring(decoded.encode('utf-8'))
                except Exception:
                    logger.error(f"Failed to parse XML sitemap {url}")
                    return items, status_code, feed_type
            except Exception as e:
                logger.error(f"Unexpected error parsing XML sitemap {url}: {e}")
                return items, status_code, feed_type
                
            namespaces = {}
            root_tag = root.tag
            if root_tag.startswith('{'):
                namespace_uri = root_tag[1:root_tag.index('}')]
                namespaces['sitemap'] = namespace_uri
            else:
                namespaces['sitemap'] = 'http://www.sitemaps.org/schemas/sitemap/0.9'
            namespaces['news'] = 'http://www.google.com/schemas/sitemap-news/0.9'
            namespaces['image'] = 'http://www.google.com/schemas/sitemap-image/1.1'
            
            urls = []
            try:
                urls = root.findall('.//sitemap:url', namespaces)
            except:
                pass
            if not urls:
                try:
                    urls = root.findall(f'.//{{{namespaces["sitemap"]}}}url')
                except:
                    pass
            if not urls:
                for ns_uri in ['http://www.sitemaps.org/schemas/sitemap/0.9', 'http://www.google.com/schemas/sitemap/0.9']:
                    try:
                        urls = root.findall(f'.//{{{ns_uri}}}url')
                        if urls:
                            namespaces['sitemap'] = ns_uri
                            break
                    except:
                        pass
            if not urls:
                urls = root.findall('.//url')
            if not urls:
                for elem in root.iter():
                    tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    if tag_name == 'url':
                        urls.append(elem)
                        
            if not urls:
                sitemap_index_elems = []
                for elem in root.iter():
                    tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    if tag_name == 'sitemap':
                        sitemap_index_elems.append(elem)
                        
                if sitemap_index_elems:
                    logger.info(f"Sitemap {source_name} is a sitemap index with {len(sitemap_index_elems)} sitemap references")
                    if not historical and not link_archive:
                        sitemap_with_dates = []
                        for sitemap_elem in sitemap_index_elems:
                            sitemap_loc = None
                            sitemap_lastmod = None
                            for child in sitemap_elem:
                                tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                                if tag_name == 'loc':
                                    sitemap_loc = child.text.strip() if child.text else None
                                elif tag_name == 'lastmod':
                                    if child.text:
                                        try:
                                            sitemap_lastmod = datetime.fromisoformat(child.text.replace('Z', '+00:00'))
                                            if sitemap_lastmod.tzinfo:
                                                sitemap_lastmod = sitemap_lastmod.replace(tzinfo=None)
                                        except:
                                            pass
                            if sitemap_loc:
                                if sitemap_lastmod is None or sitemap_lastmod >= cutoff_time - timedelta(days=6):
                                    sort_date = sitemap_lastmod if sitemap_lastmod else datetime.min.replace(tzinfo=None)
                                    sitemap_with_dates.append((sitemap_elem, sitemap_loc, sort_date))
                                    
                        if sitemap_with_dates:
                            sitemap_with_dates.sort(key=lambda x: x[2], reverse=True)
                            sitemaps_with_dates_only = [x for x in sitemap_with_dates if x[2] > datetime.min.replace(tzinfo=None)]
                            if sitemaps_with_dates_only:
                                sitemap_index_elems = [x[0] for x in sitemaps_with_dates_only[:3]]
                                logger.info(f"24-hour fetch: Filtered to {len(sitemap_index_elems)} recent sitemap(s) from index (with dates)")
                            else:
                                sitemap_index_elems = [x[0] for x in sitemap_with_dates[-3:]]
                                logger.info(f"24-hour fetch: No dates available, taking last {len(sitemap_index_elems)} sitemap(s) from index")
                        else:
                            sitemap_index_elems = sitemap_index_elems[-1:]
                            logger.info(f"24-hour fetch: No date info available, fetching last sitemap from index")
                            
                    for sitemap_elem in sitemap_index_elems:
                        sitemap_loc_elem = None
                        for child in sitemap_elem:
                            tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                            if tag_name == 'loc':
                                sitemap_loc_elem = child
                                break
                        if sitemap_loc_elem and sitemap_loc_elem.text:
                            sitemap_url = sitemap_loc_elem.text.strip()
                            logger.info(f"Found sitemap reference in index: {sitemap_url}")
                            try:
                                sub_items, sub_status, sub_type = self._parse_sitemap(sitemap_url, source_name, category, historical, link_archive)
                                items.extend(sub_items)
                            except Exception as e:
                                logger.warning(f"Error fetching sub-sitemap {sitemap_url}: {e}")
                                
                    if limit and limit > 0 and items:
                        try:
                            items.sort(key=lambda x: x.get('published_date', ''), reverse=True)
                            items = items[:limit]
                            logger.info(f"Limited sitemap index results to {len(items)} latest items (requested: {limit})")
                        except Exception as e:
                            logger.warning(f"Error sorting/limiting sitemap index items: {e}")
                    return items, status_code, feed_type
                    
            logger.info(f"Found {len(urls)} URL elements in sitemap {source_name} (root tag: {root.tag})")
            
            max_urls_to_process = 200 if not historical else None
            if limit:
                max_urls_to_process = limit
                
            if not historical and cutoff_time and len(urls) > 100:
                sample_urls = urls[:50]
                recent_count = 0
                for sample_url in sample_urls:
                    for child in sample_url:
                        tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if tag_name == 'lastmod' and child.text:
                            try:
                                sample_date = datetime.fromisoformat(child.text.replace('Z', '+00:00'))
                                if sample_date.tzinfo:
                                    sample_date = sample_date.replace(tzinfo=None)
                                if sample_date >= cutoff_time:
                                    recent_count += 1
                            except:
                                pass
                            break
                if recent_count == 0:
                    logger.info(f"Skipping sitemap {source_name} - no recent URLs found in sample")
                    return items, status_code, feed_type
                    
            urls_to_process = urls[:max_urls_to_process] if max_urls_to_process else urls
            
            for url_elem in urls_to_process:
                loc_elem = None
                loc = None
                for child in url_elem:
                    tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    if tag_name == 'loc':
                        loc_elem = child
                        break
                        
                if loc_elem is None:
                    try:
                        loc_elem = url_elem.find('sitemap:loc', namespaces)
                    except:
                        pass
                if loc_elem is None:
                    loc_elem = url_elem.find('loc')
                if loc_elem is None:
                    try:
                        loc_elem = url_elem.find(f'{{{namespaces["sitemap"]}}}loc')
                    except:
                        pass
                if loc_elem is None:
                    for ns_uri in ['http://www.sitemaps.org/schemas/sitemap/0.9', 'http://www.google.com/schemas/sitemap/0.9']:
                        try:
                            loc_elem = url_elem.find(f'{{{ns_uri}}}loc')
                            if loc_elem is not None:
                                break
                        except:
                            pass
                if loc_elem is None:
                    for child in url_elem:
                        tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if tag_name == 'loc':
                            loc_elem = child
                            break
                            
                if loc_elem is None:
                    continue
                    
                if loc_elem.text:
                    loc = loc_elem.text.strip()
                if not loc:
                    try:
                        text_parts = list(loc_elem.itertext())
                        if text_parts:
                            loc = ''.join(text_parts).strip()
                    except:
                        pass
                        
                if not loc or len(loc) < 4:
                    continue
                if not (loc.startswith('http://') or loc.startswith('https://')):
                    continue
                    
                lastmod_elem = None
                try:
                    lastmod_elem = url_elem.find('sitemap:lastmod', namespaces)
                except:
                    pass
                if lastmod_elem is None:
                    lastmod_elem = url_elem.find('lastmod')
                if lastmod_elem is None:
                    try:
                        lastmod_elem = url_elem.find(f'{{{namespaces["sitemap"]}}}lastmod')
                    except:
                        pass
                if lastmod_elem is None:
                    for ns_uri in ['http://www.sitemaps.org/schemas/sitemap/0.9', 'http://www.google.com/schemas/sitemap/0.9']:
                        try:
                            lastmod_elem = url_elem.find(f'{{{ns_uri}}}lastmod')
                            if lastmod_elem is not None:
                                break
                        except:
                            pass
                if lastmod_elem is None:
                    for child in url_elem:
                        tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if tag_name == 'lastmod':
                            lastmod_elem = child
                            break
                            
                published_date = ''
                entry_datetime = None
                if lastmod_elem is not None and lastmod_elem.text:
                    try:
                        entry_datetime = datetime.fromisoformat(lastmod_elem.text.replace('Z', '+00:00'))
                        if entry_datetime.tzinfo is not None:
                            entry_datetime = entry_datetime.replace(tzinfo=None)
                        published_date = entry_datetime.isoformat()
                    except:
                        published_date = lastmod_elem.text
                        entry_datetime = None
                        
                if not historical and cutoff_time and entry_datetime:
                    if entry_datetime < cutoff_time:
                        continue
                        
                title = ''
                try:
                    title_elem = url_elem.find('news:news/news:title', namespaces)
                    if title_elem is None:
                        news_elem = url_elem.find('news')
                        if news_elem is not None:
                            title_elem = news_elem.find('title')
                    if title_elem is not None and title_elem.text:
                        title = title_elem.text.strip()
                except:
                    pass
                    
                try:
                    pub_date_elem = url_elem.find('news:news/news:publication_date', namespaces)
                    if pub_date_elem is None:
                        news_elem = url_elem.find('news')
                        if news_elem is not None:
                            pub_date_elem = news_elem.find('publication_date')
                    if pub_date_elem is not None and pub_date_elem.text:
                        try:
                            entry_datetime = datetime.fromisoformat(pub_date_elem.text.replace('Z', '+00:00'))
                            if entry_datetime.tzinfo is not None:
                                entry_datetime = entry_datetime.replace(tzinfo=None)
                            published_date = entry_datetime.isoformat()
                            if not historical and cutoff_time and entry_datetime < cutoff_time:
                                continue
                        except:
                            pass
                except:
                    pass
                    
                if not title:
                    parsed = urlparse(loc)
                    path_parts = [p for p in parsed.path.split('/') if p]
                    if path_parts:
                        title = unquote(path_parts[-1]).replace('-', ' ').replace('_', ' ').title()
                    else:
                        title = parsed.netloc or loc[:50]
                        
                image_url = None
                try:
                    image_elem = url_elem.find('image:image/image:loc', namespaces)
                    if image_elem is None:
                        image_container = url_elem.find('image')
                        if image_container is not None:
                            image_loc_elem = image_container.find('loc')
                            if image_loc_elem is None:
                                for child in image_container:
                                    tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                                    if tag_name == 'loc' and child.text:
                                        image_url = child.text.strip()
                                        break
                            elif image_loc_elem.text:
                                image_url = image_loc_elem.text.strip()
                    elif image_elem.text:
                        image_url = image_elem.text.strip()
                except:
                    pass
                    
                tags = []
                try:
                    keywords_elem = url_elem.find('news:news/news:keywords', namespaces)
                    if keywords_elem is None:
                        news_elem = url_elem.find('news')
                        if news_elem is not None:
                            keywords_elem = news_elem.find('keywords')
                    if keywords_elem is not None and keywords_elem.text:
                        tags.extend([kw.strip() for kw in keywords_elem.text.split(',')[:5]])
                except:
                    pass
                    
                meta_description = ''
                webpage_image_url = None
                if category == 'news' and len(items) < 20:
                    try:
                        page_response = self.session.get(loc, timeout=3, verify=False, allow_redirects=True, stream=True)
                        content = b''
                        for chunk in page_response.iter_content(chunk_size=8192):
                            content += chunk
                            if len(content) > 50000:
                                break
                        if page_response.status_code == 200 and content:
                            page_soup = BeautifulSoup(content, 'html.parser')
                            meta_desc_tag = page_soup.find('meta', attrs={'name': 'description'}) or \
                                            page_soup.find('meta', attrs={'property': 'og:description'}) or \
                                            page_soup.find('meta', attrs={'name': 'og:description'})
                            if meta_desc_tag and meta_desc_tag.get('content'):
                                meta_description = meta_desc_tag.get('content', '').strip()[:500]
                            og_image_tag = page_soup.find('meta', attrs={'property': 'og:image'}) or \
                                           page_soup.find('meta', attrs={'name': 'og:image'})
                            if og_image_tag and og_image_tag.get('content'):
                                webpage_image_url = og_image_tag.get('content', '').strip()
                                if webpage_image_url and not webpage_image_url.startswith('http'):
                                    from urllib.parse import urljoin
                                    webpage_image_url = urljoin(loc, webpage_image_url)
                    except Exception:
                        pass
                        
                final_image_url = webpage_image_url or image_url
                
                # Clean the title before adding to items
                cleaned_title = self.clean_title(title) if title else loc[:50]
                
                items.append({
                    'category': category if category else 'news',
                    'title': cleaned_title[:200],
                    'description': '',
                    'meta_description': meta_description,
                    'image_url': final_image_url,
                    'source': source_name,
                    'source_url': loc,
                    'published_date': published_date if published_date else '',
                    'tags': tags,
                    'raw_data': {'url': loc, 'lastmod': lastmod_elem.text if lastmod_elem is not None else ''},
                    '_sort_date': entry_datetime if entry_datetime else datetime.min.replace(tzinfo=None)
                })
                
            if len(items) == 0 and len(urls) > 0:
                sample_url_elem = urls[0] if urls else None
                if sample_url_elem is not None:
                    sample_children = [c.tag for c in list(sample_url_elem)[:5]]
                    sample_loc = None
                    for child in sample_url_elem:
                        tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if tag_name == 'loc':
                            sample_loc = child.text if child.text else 'empty'
                            break
                    logger.warning(f"Parsed 0 URLs from sitemap {source_name} despite {len(urls)} URL elements")
                    logger.warning(f"Sample URL element children: {sample_children}, sample loc: {sample_loc}")
            else:
                logger.info(f"Parsed {len(items)} URLs from sitemap {source_name}")
                
            if limit and limit > 0 and items:
                try:
                    items.sort(key=lambda x: x.get('_sort_date', datetime.min.replace(tzinfo=None)), reverse=True)
                    items = items[:limit]
                    for item in items:
                        item.pop('_sort_date', None)
                    logger.info(f"Limited sitemap results to {len(items)} latest items (requested: {limit})")
                except Exception as e:
                    logger.warning(f"Error sorting/limiting sitemap items: {e}")
                    for item in items:
                        item.pop('_sort_date', None)
            else:
                for item in items:
                    item.pop('_sort_date', None)
                    
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                logger.error(f"[{feed_type}] [{source_name}] [{status_code}] Error: {e}")
            else:
                status_code = 0
                logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
        except Exception as e:
            status_code = 0
            logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}", exc_info=True)
            
        for item in items:
            item.pop('_sort_date', None)
            
        if status_code is None:
            status_code = 200
            
        return items, status_code, feed_type

    def _parse_api(self, url: str, source_name: str, category: str) -> List[Dict[str, Any]]:
        return self._parse_json(url, source_name, category)

    def _parse_txt(self, url: str, source_name: str, category: str) -> Tuple[List[Dict[str, Any]], int, str]:
        items = []
        status_code = None
        feed_type = 'TXT'
        
        try:
            try:
                response = self.session.get(url, timeout=self.timeout, verify=True)
                status_code = response.status_code
                response.raise_for_status()
            except requests.exceptions.SSLError:
                logger.warning(f"SSL error for {url}, trying without verification...")
                response = self.session.get(url, timeout=self.timeout, verify=False)
                status_code = response.status_code
                response.raise_for_status()
                
            if status_code:
                logger.info(f"[{feed_type}] [{source_name}] [{status_code}]")
                
            lines = response.text.strip().split('\n')
            valid_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
            
            if valid_lines:
                items.append({
                    'category': category,
                    'title': f'{source_name} Update - {len(valid_lines)} entries',
                    'description': f'Updated {category} feed containing {len(valid_lines)} entries.',
                    'source': source_name,
                    'source_url': url,
                    'published_date': datetime.utcnow().isoformat(),
                    'severity': 'HIGH' if category in ['malware', 'ransomware'] else 'MEDIUM',
                    'tags': [category.title(), source_name, 'Blocklist'],
                    'raw_data': {'entry_count': len(valid_lines), 'sample': valid_lines[:10]}
                })
                
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                status_code = e.response.status_code
                logger.error(f"[{feed_type}] [{source_name}] [{status_code}] Error: {e}")
            else:
                status_code = 0
                logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
        except Exception as e:
            status_code = 0
            logger.error(f"[{feed_type}] [{source_name}] [ERROR] {e}")
            
        if status_code is None:
            status_code = 200
            
        return items, status_code, feed_type