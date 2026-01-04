from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from models import Database
from fetchers import fetch_all_sources
from datetime import datetime, date, timedelta
import logging
import json
import os
import re
import config
from job_tracker import job_tracker
from functools import wraps
from time_utils import format_datetime_ist, format_date_ist, now_ist

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Use Flask secret key from config.py
app.config['SECRET_KEY'] = config.FLASK_SECRET_KEY

# Add cache control headers to prevent browser caching of API responses
@app.after_request
def add_no_cache_headers(response):
    """Add no-cache headers to API responses to prevent stale data"""
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

def settings_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'settings_authenticated' not in session:
            return redirect(url_for('settings_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.template_filter('rjust')
def rjust_filter(s, width, fillchar=' '):
    return str(s).rjust(width, fillchar)

@app.template_filter('safe_dict')
def safe_dict_filter(value):
    if isinstance(value, dict):
        return value
    return {}
@app.template_filter('format_date')
def format_date_filter(date_value):
    if not date_value:
        return ''
    if isinstance(date_value, str):
        return date_value[:10] if len(date_value) >= 10 else date_value
    try:
        if hasattr(date_value, 'strftime'):
            return date_value.strftime('%Y-%m-%d')
        return str(date_value)[:10]
    except:
        return ''
@app.template_filter('clean_source')
def clean_source_filter(source_name):
    if not source_name:
        return ''
    import re
    cleaned = re.sub(r'\s*SITEMAP\s*\d*\s*$', '', source_name, flags=re.IGNORECASE)
    cleaned = re.sub(r'\s*SITEMAP\s*\d*\s*', ' ', cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.strip()
    return cleaned
@app.template_filter('format_datetime')
def format_datetime_filter(date_value):
    if not date_value or date_value == '':
        return ''
    if isinstance(date_value, str):
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return date_value[:19] if len(date_value) >= 19 else date_value
    try:
        if hasattr(date_value, 'strftime'):
            return date_value.strftime('%Y-%m-%d %H:%M:%S')
        return str(date_value)[:19]
    except:
        return 'N/A'

@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string to Python object"""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except:
            return []
    elif isinstance(value, (list, dict)):
        return value
    return []

@app.context_processor
def inject_now_ist():
    return {'now_ist': now_ist}
db = Database()
@app.route('/')
def dashboard():
    hours = request.args.get('hours', type=int)
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    # Don't set default hours - show ALL items by default
    stats = db.get_statistics(hours=hours if hours else None, date_from=date_from if date_from else None, date_to=date_to if date_to else None)
    return render_template('dashboard.html', stats=stats, selected_hours=hours, selected_date_from=date_from, selected_date_to=date_to)
@app.route('/news')
def news():
    tab = request.args.get('tab', 'articles').strip()
    if tab == 'archive':
        return news_archive()
    else:
        return category_page('news')
def news_archive():
    website = request.args.get('website', '').strip()
    page = int(request.args.get('page', 1))
    search = request.args.get('search', '').strip()
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    param = db._get_param_placeholder()
    offset = (page - 1) * 50
    try:
        cursor.execute("""
            SELECT ds.feed_url, ds.source_name
            FROM data_sources ds
            WHERE ds.feed_type = 'sitemap'
            ORDER BY ds.feed_url
        """)
        website_map = {}
        from urllib.parse import urlparse
        for row in cursor.fetchall():
            if isinstance(row, dict):
                feed_url = row.get('feed_url', '')
                source_name = row.get('source_name', '')
            else:
                feed_url = row[0] if row else ''
                source_name = row[1] if len(row) > 1 else ''
            if feed_url:
                try:
                    parsed = urlparse(feed_url)
                    base_domain = parsed.netloc or parsed.path.split('/')[0] if parsed.path else ''
                    base_domain = base_domain.replace('www.', '').split(':')[0]
                    if base_domain:
                        display_name = source_name
                        if ' Sitemap ' in source_name or ' sitemap ' in source_name:
                            parts = source_name.rsplit(' Sitemap ', 1)
                            if len(parts) == 1:
                                parts = source_name.rsplit(' sitemap ', 1)
                            if len(parts) > 0:
                                display_name = parts[0].strip()
                        if base_domain not in website_map:
                            website_map[base_domain] = display_name
                        elif 'Sitemap' not in display_name and 'Sitemap' in website_map[base_domain]:
                            website_map[base_domain] = display_name
                except Exception:
                    continue
        websites = [(domain, name) for domain, name in website_map.items()]
        websites.sort(key=lambda x: x[1].lower())
        domain_variations = {}
        for domain, name in websites:
            variations = [domain]
            if domain.startswith('www.'):
                variations.append(domain.replace('www.', ''))
            else:
                variations.append(f'www.{domain}')
            domain_variations[domain] = variations
        cursor.execute("""
            SELECT ds.id, ds.source_name, ds.feed_url, ds.enabled
            FROM data_sources ds
            WHERE ds.feed_type = 'sitemap' AND ds.category = 'news'
            ORDER BY ds.source_name, ds.feed_url
        """)
        all_sitemaps = []
        for row in cursor.fetchall():
            if isinstance(row, dict):
                all_sitemaps.append({
                    'id': row.get('id'),
                    'name': row.get('source_name', ''),
                    'url': row.get('feed_url', ''),
                    'enabled': row.get('enabled', True)
                })
            else:
                all_sitemaps.append({
                    'id': row[0] if len(row) > 0 else None,
                    'name': row[1] if len(row) > 1 else '',
                    'url': row[2] if len(row) > 2 else '',
                    'enabled': row[3] if len(row) > 3 else True
                })
        sitemaps_by_website = {}
        for sitemap in all_sitemaps:
            try:
                parsed = urlparse(sitemap['url'])
                base_domain = parsed.netloc or parsed.path.split('/')[0] if parsed.path else ''
                base_domain = base_domain.replace('www.', '').split(':')[0]
                if base_domain:
                    if base_domain not in sitemaps_by_website:
                        sitemaps_by_website[base_domain] = []
                    sitemaps_by_website[base_domain].append(sitemap)
            except:
                continue
    except Exception as e:
        logger.warning(f"Error getting sitemap websites: {e}")
        websites = []
        sitemaps_by_website = {}
    where_clauses = []
    params = []
    try:
        where_clauses.append("""
            EXISTS (
                SELECT 1 FROM data_sources ds
                WHERE ds.source_name = news_articles.source
                AND ds.feed_type = 'sitemap'
            )
        """)
    except Exception as e:
        logger.warning(f"Error filtering sitemap sources: {e}")
        where_clauses.append("1=0")
    if website:
        domain_patterns = [f"%{website}%"]
        if not website.startswith('www.'):
            domain_patterns.append(f"%www.{website}%")
        else:
            domain_patterns.append(f"%{website.replace('www.', '')}%")
        pattern_conditions = []
        for pattern in domain_patterns:
            pattern_conditions.append(f"(ds.feed_url LIKE {param} OR news_articles.source_url LIKE {param})")
            params.append(pattern)
            params.append(pattern)
        where_clauses.append(f"""
            EXISTS (
                SELECT 1 FROM data_sources ds
                WHERE ds.source_name = news_articles.source
                AND ds.feed_type = 'sitemap'
                AND ({' OR '.join(pattern_conditions)})
            )
        """)
    if search:
        where_clauses.append(f"(title LIKE {param} OR description LIKE {param})")
        params.extend([f"%{search}%", f"%{search}%"])
    where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
    cursor.execute(f"""
        SELECT * FROM news_articles
        WHERE {where_sql}
        ORDER BY published_date DESC, created_at DESC
        LIMIT 50 OFFSET {offset}
    """, params)
    items = []
    for row in cursor.fetchall():
        if isinstance(row, dict):
            item = row
        else:
            item = dict(row)
        item['tags'] = json.loads(item['tags']) if item.get('tags') else []
        item['category'] = 'news'
        items.append(item)
    cursor.execute(f"""
        SELECT COUNT(*) as total FROM news_articles
        WHERE {where_sql}
    """, params)
    total_row = cursor.fetchone()
    total = total_row['total'] if isinstance(total_row, dict) else total_row[0]
    cursor.close()
    conn.close()
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template('category.html',
                         category='news',
                         tab='archive',
                         items=items,
                         websites=websites,
                         selected_website=website,
                         sitemaps_by_website=sitemaps_by_website,
                         search=search,
                         page=page,
                         total_pages=total_pages,
                         total=total,
                         sort_by='published_date',
                         sort_order='DESC',
                         date_from='',
                         date_to='',
                         year='',
                         month='',
                         current_year=current_year)
@app.route('/cve')
def cve():
    tab = request.args.get('tab', 'database').strip()
    if tab == 'nvd':
        return cve_nvd_search()
    else:
        return cve_database()
def cve_database():
    """Enhanced CVE database view with CWE and CVSS filtering"""
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort', 'published_date')
    sort_order = request.args.get('order', 'DESC')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    severity = request.args.get('severity', '').strip()
    severities = request.args.get('severities', '').strip()
    cwe = request.args.get('cwe', '').strip()  # NEW: CWE filter
    cvss_range = request.args.get('cvss_range', '').strip()  # NEW: CVSS range filter
    
    if severities:
        severity = severities
    if date_from and not re.match(r'^\d{4}-\d{2}-\d{2}', date_from):
        date_from = ''
    if date_to and not re.match(r'^\d{4}-\d{2}-\d{2}', date_to):
        date_to = ''
    year_int = int(year) if year and year.isdigit() else None
    month_int = int(month) if month and month.isdigit() else None
    selected_severities = []
    if severity:
        selected_severities = [s.strip().upper() for s in severity.split(',') if s.strip()]
    
    # Build custom query for enhanced filters
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    
    query = "SELECT * FROM intelligence_items WHERE category = 'cve'"
    params = []
    
    if search:
        query += " AND (title LIKE %s OR description LIKE %s OR cve_id LIKE %s)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
    
    if severity:
        severity_list = [s.strip().upper() for s in severity.split(',') if s.strip()]
        placeholders = ','.join(['%s'] * len(severity_list))
        query += f" AND severity IN ({placeholders})"
        params.extend(severity_list)
    
    # NEW: CWE filter
    if cwe:
        query += " AND cwe_id = %s"
        params.append(cwe)
    
    # NEW: CVSS range filter
    if cvss_range:
        if cvss_range == '9.0-10.0':
            query += " AND cvss_v3_score >= 9.0"
        elif cvss_range == '7.0-8.9':
            query += " AND cvss_v3_score >= 7.0 AND cvss_v3_score < 9.0"
        elif cvss_range == '4.0-6.9':
            query += " AND cvss_v3_score >= 4.0 AND cvss_v3_score < 7.0"
        elif cvss_range == '0.1-3.9':
            query += " AND cvss_v3_score > 0 AND cvss_v3_score < 4.0"
    
    if date_from:
        query += " AND published_date >= %s"
        params.append(date_from)
    
    if date_to:
        query += " AND published_date <= %s"
        params.append(date_to)
    
    # Count total
    count_query = query.replace("SELECT *", "SELECT COUNT(*)")
    cursor.execute(count_query, params)
    total = cursor.fetchone()
    total = total['COUNT(*)'] if isinstance(total, dict) else total[0]
    
    # Add sorting and pagination
    query += f" ORDER BY {sort_by} {sort_order}"
    query += " LIMIT %s OFFSET %s"
    params.extend([50, (page - 1) * 50])
    
    cursor.execute(query, params)
    items = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    total_pages = (total + 49) // 50
    return render_template(
        'cve.html',
        tab='database',
        category='cve',
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by=sort_by,
        sort_order=sort_order,
        selected_severities=selected_severities,
        cwe=cwe,
        cvss_range=cvss_range,
        severity=''
    )
def cve_nvd_search():
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    severity = request.args.get('severity', '').strip()
    items = []
    total = 0
    total_pages = 0
    error_message = None
    
    try:
        import requests
        from datetime import datetime, timedelta
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'resultsPerPage': 50,
            'startIndex': (page - 1) * 50
        }
        if search and search.upper().startswith('CVE-'):
            params['cveId'] = search.upper()
        elif search:
            params['keywordSearch'] = search
        else:
            # Search for CVEs from the last 30 days
            # Note: Using 2024 dates since system date might be incorrect
            date_from = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
            date_to = datetime.utcnow().strftime('%Y-%m-%d')
            # If dates are in future (2025+), use 2024 dates instead
            if date_to.startswith('2025') or date_to.startswith('2026'):
                date_from = '2024-11-23'
                date_to = '2024-12-23'
            params['pubStartDate'] = f"{date_from}T00:00:00.000"
            params['pubEndDate'] = f"{date_to}T23:59:59.999"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        # Temporarily disable API key as it's causing 404 errors
        # The NVD API works fine without a key (just with rate limits: 5 requests per 30 seconds)
        # if config.NVD_API_KEY and config.NVD_API_KEY != "YOUR_API_KEY_HERE":
        #     params['apiKey'] = config.NVD_API_KEY
        #     logger.info("Using NVD API key for higher rate limits")
        # else:
        #     logger.info("No API key configured - using public rate limits (5 req/30sec)")
        
        logger.info(f"Searching NVD without API key - params: {params}")
        response = requests.get(nvd_url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 403:
            error_message = "NVD API access forbidden. API key may be invalid or rate limited."
            logger.warning(f"NVD API returned 403. Response: {response.text[:200]}")
        elif response.status_code != 200:
            error_message = f"NVD API returned status code {response.status_code}"
            logger.warning(f"NVD API error: {response.status_code} - {response.text[:200]}")
        else:
            response.raise_for_status()
            data = response.json()
            if 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    descriptions = cve_data.get('descriptions', [])
                    description = ''
                    if descriptions:
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                        if not description and descriptions:
                            description = descriptions[0].get('value', '')
                    metrics = cve_data.get('metrics', {})
                    item_severity = 'UNKNOWN'
                    cvss_score = None
                    cvss_vector = None
                    affected_products = []
                    references = []
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                        cvss_score = cvss.get('baseScore')
                        cvss_vector = cvss.get('vectorString', '')
                        severity_map = {9.0: 'CRITICAL', 7.0: 'HIGH', 4.0: 'MEDIUM', 0.1: 'LOW'}
                        for threshold, sev in severity_map.items():
                            if cvss_score >= threshold:
                                item_severity = sev
                                break
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss = metrics['cvssMetricV30'][0].get('cvssData', {})
                        cvss_score = cvss.get('baseScore')
                        cvss_vector = cvss.get('vectorString', '')
                        severity_map = {9.0: 'CRITICAL', 7.0: 'HIGH', 4.0: 'MEDIUM', 0.1: 'LOW'}
                        for threshold, sev in severity_map.items():
                            if cvss_score >= threshold:
                                item_severity = sev
                                break
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss = metrics['cvssMetricV2'][0].get('cvssData', {})
                        cvss_score = cvss.get('baseScore')
                        cvss_vector = cvss.get('vectorString', '')
                        severity_map = {7.0: 'HIGH', 4.0: 'MEDIUM', 0.1: 'LOW'}
                        for threshold, sev in severity_map.items():
                            if cvss_score >= threshold:
                                item_severity = sev
                                break
                    if severity and severity != item_severity:
                        continue
                    configurations = cve_data.get('configurations', [])
                    for config_item in configurations:
                        nodes = config_item.get('nodes', [])
                        for node in nodes:
                            cpe_match = node.get('cpeMatch', [])
                            for cpe in cpe_match:
                                criteria = cpe.get('criteria', '')
                                if criteria:
                                    parts = criteria.split(':')
                                    if len(parts) >= 5:
                                        vendor = parts[3] if len(parts) > 3 else ''
                                        product = parts[4] if len(parts) > 4 else ''
                                        if vendor and product:
                                            affected_products.append(f"{vendor}/{product}")
                    references_data = cve_data.get('references', [])
                    for ref in references_data[:5]:
                        ref_url = ref.get('url', '')
                        if ref_url:
                            references.append(ref_url)
                    published_date = cve_data.get('published', '')[:10] if cve_data.get('published') else ''
                    last_modified = cve_data.get('lastModified', '')[:10] if cve_data.get('lastModified') else ''
                    items.append({
                        'cve_id': cve_id,
                        'title': f"{cve_id}: {description[:150] if description else 'No description'}",
                        'description': description,
                        'source': 'NVD',
                        'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        'published_date': published_date,
                        'severity': item_severity,
                        'tags': list(set(affected_products[:5])),
                        'raw_data': {
                            'cvss_score': cvss_score,
                            'cvss_vector': cvss_vector,
                            'affected_products': affected_products[:10],
                            'references': references,
                            'last_modified': last_modified
                        }
                    })
                total = data.get('totalResults', len(items))
                total_pages = (total + 49) // 50
                logger.info(f"NVD search returned {len(items)} items, total: {total}")
            else:
                error_message = "NVD API response missing 'vulnerabilities' key"
                logger.warning(f"NVD API response structure unexpected: {list(data.keys())}")
    except requests.exceptions.Timeout:
        error_message = "NVD API request timed out. Please try again."
        logger.error("NVD API timeout")
    except requests.exceptions.ConnectionError:
        error_message = "Cannot connect to NVD API. Check your internet connection."
        logger.error("NVD API connection error")
    except Exception as e:
        error_message = f"Error searching NVD: {str(e)}"
        logger.error(f"Error searching NVD: {e}", exc_info=True)
    
    return render_template(
        'cve.html',
        tab='nvd',
        category='cve',
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by='published_date',
        sort_order='DESC',
        severity=severity,
        selected_severities=[],
        cwe='',
        cvss_range='',
        error_message=error_message
    )
@app.route('/exploit')
def exploit():
    return category_page('exploit')
@app.route('/ransomware')
def ransomware():
    tab = request.args.get('tab', 'groups').strip()
    search = request.args.get('search', '').strip()
    source = request.args.get('source', '').strip()  # NEW: Source filter
    sort = request.args.get('sort', 'published_date').strip()  # NEW: Sort parameter
    page = int(request.args.get('page', 1))
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    param = db._get_param_placeholder()
    offset = (page - 1) * 50
    where_clauses = ["category = 'ransomware'"]
    params = []
    
    if search:
        where_clauses.append(f"(title LIKE {param} OR description LIKE {param})")
        params.extend([f"%{search}%", f"%{search}%"])
    
    # NEW: Source filter
    if source:
        where_clauses.append(f"source = {param}")
        params.append(source)
    
    if tab == 'groups' or not tab:
        where_clauses.append(f"tags LIKE {param}")
        params.append('%Group%')
    elif tab == 'victims':
        where_clauses.append(f"tags LIKE {param}")
        params.append('%Victim%')
    elif tab == 'news':
        where_clauses.append("""EXISTS (
            SELECT 1 FROM data_sources ds
            WHERE ds.source_name = intelligence_items.source
            AND ds.feed_type = 'sitemap'
            AND ds.feed_url LIKE %s
        )""")
        params.append('%ransomware.live%')
    
    where_sql = " AND ".join(where_clauses)
    
    # NEW: Sort order
    order_by = "published_date DESC, created_at DESC" if sort == 'published_date' else "title ASC"
    
    if tab == 'news':
        cursor.execute("""
            SELECT ii.* FROM intelligence_items ii
            WHERE category = 'ransomware'
            AND EXISTS (
                SELECT 1 FROM data_sources ds
                WHERE ds.source_name = ii.source
                AND ds.feed_type = 'sitemap'
                AND ds.feed_url LIKE %s
            )
            """ + (f" AND (ii.title LIKE {param} OR ii.description LIKE {param})" if search else "") + f"""
            ORDER BY {order_by}
            LIMIT 50 OFFSET %s
        """, (['%ransomware.live%'] + ([f"%{search}%", f"%{search}%"] if search else []) + [offset]))
    else:
        cursor.execute(f"""
            SELECT * FROM intelligence_items
            WHERE {where_sql}
            ORDER BY {order_by}
            LIMIT 50 OFFSET {offset}
        """, params)
    items = []
    for row in cursor.fetchall():
        if isinstance(row, dict):
            item = row
        else:
            item = dict(row)
        item['tags'] = json.loads(item['tags']) if item.get('tags') else []
        try:
            raw_data = item.get('raw_data')
            if raw_data:
                if isinstance(raw_data, str) and raw_data.strip():
                    item['raw_data'] = json.loads(raw_data)
                elif isinstance(raw_data, dict):
                    item['raw_data'] = raw_data
                else:
                    item['raw_data'] = {}
            else:
                item['raw_data'] = {}
        except (json.JSONDecodeError, TypeError, AttributeError, ValueError):
            item['raw_data'] = {}
        items.append(item)
    if tab == 'news':
        count_params = ['%ransomware.live%']
        count_where = """
            SELECT COUNT(*) as total FROM intelligence_items ii
            WHERE category = 'ransomware'
            AND EXISTS (
                SELECT 1 FROM data_sources ds
                WHERE ds.source_name = ii.source
                AND ds.feed_type = 'sitemap'
                AND ds.feed_url LIKE %s
            )
        """
        if search:
            count_where += f" AND (ii.title LIKE {param} OR ii.description LIKE {param})"
            count_params.extend([f"%{search}%", f"%{search}%"])
        cursor.execute(count_where, count_params)
    else:
        cursor.execute(f"""
            SELECT COUNT(*) as total FROM intelligence_items
            WHERE {where_sql}
        """, params)
    total_row = cursor.fetchone()
    total = total_row['total'] if isinstance(total_row, dict) else total_row[0]
    cursor.close()
    conn.close()
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template('ransomware.html',
                         category='ransomware',
                         tab=tab,
                         items=items,
                         search=search,
                         source=source,
                         sort=sort,
                         page=page,
                         total_pages=total_pages,
                         total=total,
                         current_year=current_year)

@app.route('/government')
def government():
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    cert_items, cert_total = db.get_items(
        category='cert',
        page=page,
        per_page=10,
        search=search if search else None
    )
    cert_in_items, cert_in_total = db.get_items(
        category='cert-in',
        page=page,
        per_page=10,
        search=search if search else None
    )
    return render_template('government.html',
                         cert_items=cert_items,
                         cert_in_items=cert_in_items,
                         cert_total=cert_total,
                         cert_in_total=cert_in_total,
                         search=search,
                         page=page)
@app.route('/cert')
def cert():
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort', 'published_date')
    sort_order = request.args.get('order', 'DESC')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    year_int = int(year) if year and year.isdigit() else None
    month_int = int(month) if month and month.isdigit() else None
    items, total = db.get_items(
        category='cert',
        search=search if search else None,
        page=page,
        per_page=50,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from if date_from else None,
        date_to=date_to if date_to else None,
        year=year_int,
        month=month_int
    )
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template(
        'category.html',
        category='cert',
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from,
        date_to=date_to,
        year=year,
        month=month,
        current_year=current_year
    )
@app.route('/cert-in')
def cert_in():
    """CERT-In advisories page - filters by source='CERT-In'"""
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort', 'published_date')
    sort_order = request.args.get('order', 'DESC')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    year_int = int(year) if year and year.isdigit() else None
    month_int = int(month) if month and month.isdigit() else None
    items, total = db.get_items(
        category='cert-in',
        source='CERT-In',
        search=search if search else None,
        page=page,
        per_page=50,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from if date_from else None,
        date_to=date_to if date_to else None,
        year=year_int,
        month=month_int
    )
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template(
        'category.html',
        category='cert-in',
        source='CERT-In',
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from,
        date_to=date_to,
        year=year,
        month=month,
        current_year=current_year
    )
@app.route('/irdai')
def irdai():
    """IRDAI advisories page - filters by source='IRDAI'"""
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort', 'published_date')
    sort_order = request.args.get('order', 'DESC')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    year_int = int(year) if year and year.isdigit() else None
    month_int = int(month) if month and month.isdigit() else None
    items, total = db.get_items(
        category='cert-in',
        source='IRDAI',
        search=search if search else None,
        page=page,
        per_page=50,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from if date_from else None,
        date_to=date_to if date_to else None,
        year=year_int,
        month=month_int
    )
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template(
        'category.html',
        category='cert-in',
        source='IRDAI',
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from,
        date_to=date_to,
        year=year,
        month=month,
        current_year=current_year
    )
@app.route('/rbi')
def rbi():
    """RBI Master Directions page - filters by source='RBI'"""
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort', 'published_date')
    sort_order = request.args.get('order', 'DESC')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    year_int = int(year) if year and year.isdigit() else None
    month_int = int(month) if month and month.isdigit() else None
    items, total = db.get_items(
        category='cert-in',
        source='RBI',
        search=search if search else None,
        page=page,
        per_page=50,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from if date_from else None,
        date_to=date_to if date_to else None,
        year=year_int,
        month=month_int
    )
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template(
        'category.html',
        category='cert-in',
        source='RBI',
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from,
        date_to=date_to,
        year=year,
        month=month,
        current_year=current_year
    )
@app.route('/india-govt')
def india_govt():
    """Indian Government Advisories main page - shows all Indian advisories"""
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    cert_in_items, cert_in_total = db.get_items(
        category='cert-in',
        source='CERT-In',
        page=page,
        per_page=10,
        search=search if search else None
    )
    irdai_items, irdai_total = db.get_items(
        category='cert-in',
        source='IRDAI',
        page=page,
        per_page=10,
        search=search if search else None
    )
    rbi_items, rbi_total = db.get_items(
        category='cert-in',
        source='RBI',
        page=page,
        per_page=10,
        search=search if search else None
    )
    return render_template('india_govt.html',
                         cert_in_items=cert_in_items,
                         irdai_items=irdai_items,
                         rbi_items=rbi_items,
                         cert_in_total=cert_in_total,
                         irdai_total=irdai_total,
                         rbi_total=rbi_total,
                         search=search,
                         page=page)
def category_page(category: str):
    search = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort', 'published_date')
    sort_order = request.args.get('order', 'DESC')
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    year = request.args.get('year', '').strip()
    month = request.args.get('month', '').strip()
    year_int = int(year) if year and year.isdigit() else None
    month_int = int(month) if month and month.isdigit() else None
    items, total = db.get_items(
        category=category,
        search=search if search else None,
        page=page,
        per_page=50,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from if date_from else None,
        date_to=date_to if date_to else None,
        year=year_int,
        month=month_int
    )
    total_pages = (total + 49) // 50
    from datetime import datetime
    current_year = datetime.utcnow().year
    return render_template(
        'category.html',
        category=category,
        items=items,
        search=search,
        page=page,
        total_pages=total_pages,
        total=total,
        sort_by=sort_by,
        sort_order=sort_order,
        date_from=date_from,
        date_to=date_to,
        year=year,
        month=month,
        current_year=current_year
    )

@app.route('/api/timeseries')
def api_timeseries():
    hours = request.args.get('hours')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    category = request.args.get('category', None)
    if date_from and date_to:
        data = db.get_time_series_data(date_from=date_from, date_to=date_to, category=category)
    else:
        hours = int(hours) if hours else 24
        if hours < 1:
            hours = 1
        elif hours > 43800:
            hours = 43800
        data = db.get_time_series_data(hours=hours, category=category)
    return jsonify(data)

@app.route('/api/severity-breakdown')
def api_severity_breakdown():
    """Get severity breakdown for charts"""
    hours = request.args.get('hours', type=int, default=24)
    if hours < 1:
        hours = 1
    elif hours > 43800:
        hours = 43800
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    cursor.execute(f"""
        SELECT
            SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN UPPER(severity) = 'LOW' THEN 1 ELSE 0 END) as low
        FROM intelligence_items
        WHERE category = 'cve'
          AND (published_date >= DATE_SUB(NOW(), INTERVAL {hours} HOUR)
           OR (published_date IS NULL AND created_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
           OR updated_at >= DATE_SUB(NOW(), INTERVAL {hours} HOUR))
    """)
    result = cursor.fetchone()
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    if result:
        if isinstance(result, dict):
            counts['critical'] = result.get('critical', 0) or 0
            counts['high'] = result.get('high', 0) or 0
            counts['medium'] = result.get('medium', 0) or 0
            counts['low'] = result.get('low', 0) or 0
        elif hasattr(result, '__getitem__'):
            try:
                counts['critical'] = result['critical'] if 'critical' in result else (result[0] if len(result) > 0 else 0)
                counts['high'] = result['high'] if 'high' in result else (result[1] if len(result) > 1 else 0)
                counts['medium'] = result['medium'] if 'medium' in result else (result[2] if len(result) > 2 else 0)
                counts['low'] = result['low'] if 'low' in result else (result[3] if len(result) > 3 else 0)
            except:
                pass
    total = counts['critical'] + counts['high'] + counts['medium'] + counts['low']
    if total == 0 and hours == 24:
        cursor.execute("""
            SELECT
                SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN UPPER(severity) = 'LOW' THEN 1 ELSE 0 END) as low
            FROM intelligence_items
            WHERE category = 'cve'
        """)
        result = cursor.fetchone()
        if result:
            if isinstance(result, dict):
                counts['critical'] = result.get('critical', 0) or 0
                counts['high'] = result.get('high', 0) or 0
                counts['medium'] = result.get('medium', 0) or 0
                counts['low'] = result.get('low', 0) or 0
            elif hasattr(result, '__getitem__'):
                try:
                    counts['critical'] = result['critical'] if 'critical' in result else (result[0] if len(result) > 0 else 0)
                    counts['high'] = result['high'] if 'high' in result else (result[1] if len(result) > 1 else 0)
                    counts['medium'] = result['medium'] if 'medium' in result else (result[2] if len(result) > 2 else 0)
                    counts['low'] = result['low'] if 'low' in result else (result[3] if len(result) > 3 else 0)
                except:
                    pass
    cursor.close()
    conn.close()
    return jsonify({'counts': counts})
@app.route('/api/stats')
def api_stats():
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    if date_from and date_to:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM intelligence_items
            WHERE published_date >= %s AND published_date <= %s
               OR (published_date IS NULL AND created_at >= %s AND created_at <= %s)
               OR (updated_at >= %s AND updated_at <= %s)
        """, (date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59', date_from, date_to + ' 23:59:59'))
        result = cursor.fetchone()
        if isinstance(result, dict):
            count = result.get('count', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            count = result[0] if result else 0
        else:
            count = 0
        cursor.close()
        conn.close()
        return jsonify({'count': count})
    else:
        stats = db.get_statistics()
        return jsonify(stats)
@app.route('/api/graph-data')
def api_graph_data():
    """Get daily statistics for the last 7 days for the threat activity graph"""
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    days_data = []
    for i in range(6, -1, -1):
        day_start = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        day_end = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') + ' 23:59:59'
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM intelligence_items
            WHERE (published_date >= %s AND published_date <= %s)
               OR (published_date IS NULL AND DATE(created_at) = %s)
               OR DATE(updated_at) = %s
        """, (day_start, day_end, day_start, day_start))
        result = cursor.fetchone()
        if isinstance(result, dict):
            count = result.get('count', result.get('COUNT(*)', 0))
        elif hasattr(result, '__getitem__'):
            count = result[0] if result else 0
        else:
            count = 0
        days_data.append({
            'date': day_start,
            'count': count,
            'day': (datetime.now() - timedelta(days=i)).strftime('%a')
        })
    cursor.close()
    conn.close()
    return jsonify({
        'labels': [d['day'] for d in days_data],
        'data': [d['count'] for d in days_data],
        'dates': [d['date'] for d in days_data]
    })
@app.route('/settings/login', methods=['GET', 'POST'])
def settings_login():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == config.SETTINGS_PASSWORD:
            session['settings_authenticated'] = True
            return redirect(url_for('settings'))
        else:
            return render_template('settings_login.html', error='Incorrect password')
    return render_template('settings_login.html')
@app.route('/settings/logout', methods=['POST'])
def settings_logout():
    session.pop('settings_authenticated', None)
    return redirect(url_for('settings_login'))
@app.route('/settings')
@settings_login_required
def settings():
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    cursor.execute("SELECT setting_key, setting_value FROM settings")
    rows = cursor.fetchall()
    settings_dict = {}
    for row in rows:
        if isinstance(row, dict):
            settings_dict[row['setting_key']] = row['setting_value']
        elif hasattr(row, '__getitem__'):
            settings_dict[row[0]] = row[1]
    auto_refresh_val = settings_dict.get('auto_refresh', '0')
    auto_refresh_bool = False
    if isinstance(auto_refresh_val, bool):
        auto_refresh_bool = auto_refresh_val
    elif isinstance(auto_refresh_val, str):
        auto_refresh_bool = auto_refresh_val.lower() in ('1', 'true', 'yes', 'on')
    else:
        auto_refresh_bool = bool(auto_refresh_val)
    current_settings = {
        'fetch_interval': int(settings_dict.get('fetch_interval', 30)),
        'historical_from': settings_dict.get('historical_from', ''),
        'historical_to': settings_dict.get('historical_to', ''),
        'auto_refresh': auto_refresh_bool
    }
    cursor.execute("""
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'source_settings'
        AND COLUMN_NAME IN ('custom_name', 'custom_url', 'custom_type')
    """)
    existing_columns = [row[0] if isinstance(row, (list, tuple)) else row.get('COLUMN_NAME', '') for row in cursor.fetchall()]
    has_custom_columns = 'custom_name' in existing_columns
    if has_custom_columns:
        cursor.execute("SELECT source_name, enabled, custom_name, custom_url, custom_type FROM source_settings")
    else:
        cursor.execute("SELECT source_name, enabled FROM source_settings")
    source_settings_rows = cursor.fetchall()
    source_settings = {}
    source_overrides = {}
    for row in source_settings_rows:
        if isinstance(row, dict):
            source_name = row['source_name']
            source_settings[source_name] = row['enabled']
            if has_custom_columns and (row.get('custom_name') or row.get('custom_url') or row.get('custom_type')):
                source_overrides[source_name] = {
                    'name': row.get('custom_name'),
                    'url': row.get('custom_url'),
                    'type': row.get('custom_type')
                }
        else:
            source_name = row[0]
            source_settings[source_name] = row[1]
            if has_custom_columns and len(row) > 2 and (row[2] if len(row) > 2 else None or row[3] if len(row) > 3 else None or row[4] if len(row) > 4 else None):
                source_overrides[source_name] = {
                    'name': row[2] if len(row) > 2 else None,
                    'url': row[3] if len(row) > 3 else None,
                    'type': row[4] if len(row) > 4 else None
                }
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
            db_sources_rows = []
        else:
            cursor.execute("""
                SELECT source_name, feed_url, feed_type, category, enabled, api_key
                FROM data_sources
                ORDER BY category, source_name
            """)
            db_sources_rows = cursor.fetchall()
    except Exception as e:
        logger.warning(f"Error querying data_sources table: {e}")
        db_sources_rows = []
    sources_by_category = {
        'news': [],
        'cve': [],
        'exploit': [],
        'cert': [],
        'cert-in': [],
    }
    
    # Add hardcoded sources (CERT-In, RBI, IRDAI)
    hardcoded_sources = [
        {'name': 'CERT-In', 'url': 'https://www.cert-in.org.in', 'type': 'html', 'category': 'cert-in', 'enabled': True},
        {'name': 'RBI', 'url': 'https://www.rbi.org.in', 'type': 'html', 'category': 'cert-in', 'enabled': True},
        {'name': 'IRDAI', 'url': 'https://irdai.gov.in', 'type': 'html', 'category': 'cert-in', 'enabled': True},
    ]
    
    for hc_source in hardcoded_sources:
        hc_source['enabled'] = source_settings.get(hc_source['name'], hc_source.get('enabled', True))
        sources_by_category['cert-in'].append(hc_source)
    from urllib.parse import urlparse
    import re
    # Group sitemaps by base name for smart display
    sitemap_groups = {}  # key: base_name, value: list of sitemap sources
    regular_sources = []
    
    for row in db_sources_rows:
        if isinstance(row, dict):
            source = {
                'name': row['source_name'],
                'url': row['feed_url'],
                'type': row['feed_type'],
                'category': row['category'],
                'enabled': row.get('enabled', True),
                'api_key': row.get('api_key'),
                'id': row.get('id') if 'id' in row else None
            }
        else:
            source = {
                'name': row[0],
                'url': row[1],
                'type': row[2],
                'category': row[3],
                'enabled': row[4] if len(row) > 4 else True,
                'api_key': row[5] if len(row) > 5 else None,
                'id': row[6] if len(row) > 6 else None
            }
        category = source['category']
        if category in sources_by_category:
            if source['type'] == 'sitemap':
                # Extract base name (remove "Sitemap 1", "Sitemap 2", etc.)
                base_name = source['name']
                sitemap_num_match = re.search(r'\s+sitemap\s+(\d+)$', base_name, re.IGNORECASE)
                if sitemap_num_match:
                    base_name = re.sub(r'\s+sitemap\s+\d+$', '', base_name, flags=re.IGNORECASE).strip()
                elif ' Sitemap ' in base_name:
                    parts = base_name.rsplit(' Sitemap ', 1)
                    if len(parts) > 1 and parts[1].isdigit():
                        base_name = parts[0].strip()
                
                # Group by base name
                if base_name not in sitemap_groups:
                    sitemap_groups[base_name] = []
                source['base_name'] = base_name
                source['original_name'] = source['name']
                source['enabled'] = source_settings.get(source['name'], source.get('enabled', True))
                sitemap_groups[base_name].append(source)
            else:
                # Regular (non-sitemap) sources
                source['enabled'] = source_settings.get(source['name'], source.get('enabled', True))
                if source['name'] in source_overrides:
                    override = source_overrides[source['name']]
                    if override.get('name'):
                        source['name'] = override['name']
                    if override.get('url'):
                        source['url'] = override['url']
                    if override.get('type'):
                        source['type'] = override['type']
                regular_sources.append(source)
    
    # Add grouped sitemaps and regular sources to categories
    for source in regular_sources:
        if source['category'] in sources_by_category:
            sources_by_category[source['category']].append(source)
    
    # Add grouped sitemaps - show as groups if multiple, individual if single
    for base_name, sitemaps in sitemap_groups.items():
        if not sitemaps:
            continue
        category = sitemaps[0]['category']
        if category not in sources_by_category:
            continue
        
        # Sort sitemaps by number if they have numbers
        def get_sitemap_num(s):
            match = re.search(r'sitemap\s+(\d+)', s['original_name'], re.IGNORECASE)
            return int(match.group(1)) if match else 9999
        
        sitemaps_sorted = sorted(sitemaps, key=get_sitemap_num)
        
        if len(sitemaps) == 1:
            # Single sitemap - add as regular source
            source = sitemaps[0].copy()
            source['name'] = source['original_name']
            sources_by_category[category].append(source)
        else:
            # Multiple sitemaps - add as grouped source
            # Generate unique group ID based on category and base_name
            group_id = f"group-{category}-{base_name}".replace(' ', '-').replace('.', '-').lower()
            grouped_source = {
                'name': base_name,
                'url': sitemaps_sorted[0]['url'],  # Use first URL as main
                'type': 'sitemap',
                'category': category,
                'enabled': any(s.get('enabled', True) for s in sitemaps_sorted),
                'is_group': True,
                'sitemap_count': len(sitemaps_sorted),
                'group_id': group_id,
                'sitemaps': sitemaps_sorted  # Store all sitemaps for editing
            }
            sources_by_category[category].append(grouped_source)
    custom_feeds = []
    try:
        cursor.execute("""
            SELECT id, name, url, category, feed_type, enabled, created_at
            FROM custom_feeds
            ORDER BY created_at DESC
        """)
        custom_feeds_rows = cursor.fetchall()
        for row in custom_feeds_rows:
            if isinstance(row, dict):
                custom_feeds.append({
                    'id': row['id'],
                    'name': row['name'],
                    'url': row['url'],
                    'category': row['category'],
                    'feed_type': row['feed_type'],
                    'enabled': row['enabled'],
                    'created_at': row.get('created_at', '')
                })
            else:
                custom_feeds.append({
                    'id': row[0],
                    'name': row[1],
                    'url': row[2],
                    'category': row[3],
                    'feed_type': row[4],
                    'enabled': row[5] if len(row) > 5 else True,
                    'created_at': row[6] if len(row) > 6 else ''
                })
    except Exception as e:
        logger.warning(f"Error fetching custom_feeds: {e}")
        custom_feeds = []
    cursor.close()
    conn.close()
    total_items = db.get_total_count()
    import os
    db_size = "N/A"
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        cursor.execute("""
            SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
        """)
        result = cursor.fetchone()
        if result:
            size_val = result.get('size_mb', 0) if isinstance(result, dict) else result[0]
            db_size = f"{size_val} MB" if size_val else "0 MB"
        cursor.close()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not get database size: {e}")
        pass
    last_fetch = db.get_last_fetch_time()
    if last_fetch:
        try:
            fetch_dt = datetime.fromisoformat(last_fetch)
            last_fetch = format_datetime_ist(fetch_dt)
        except:
            pass
    db_type = "MySQL"
    db_connected = False
    db_info = {}
    try:
        test_conn = db.get_connection()
        test_conn.close()
        db_connected = True
        db_info = {
            'type': 'MySQL',
            'host': config.MYSQL_CONFIG.get('host', 'localhost'),
            'port': config.MYSQL_CONFIG.get('port', 3306),
            'database': config.MYSQL_CONFIG.get('database', 'cybersecurity_feed'),
            'user': config.MYSQL_CONFIG.get('user', 'root'),
            'status': 'Connected'
        }
    except Exception as e:
        db_connected = False
        db_info = {
            'type': db_type,
            'status': 'Disconnected',
            'error': str(e)
        }
    db_stats = {
        'total_items': total_items,
        'db_size': db_size,
        'last_fetch': last_fetch or 'Never',
        'db_type': db_type,
        'db_connected': db_connected,
        'db_info': db_info
    }
    stats_conn = db.get_connection()
    stats_cursor = db.get_cursor(stats_conn)
    stats_cursor.execute("""
        SELECT category, COUNT(*) as count
        FROM intelligence_items
        GROUP BY category
    """)
    category_rows = stats_cursor.fetchall()
    category_stats = {}
    for row in category_rows:
        if isinstance(row, dict):
            category_stats[row['category']] = row['count']
        else:
            category_stats[row[0]] = row[1]
    stats_cursor.execute("""
        SELECT MIN(published_date) as oldest_date, MIN(created_at) as oldest_created
        FROM intelligence_items
        WHERE published_date IS NOT NULL OR created_at IS NOT NULL
    """)
    oldest_result = stats_cursor.fetchone()
    oldest_article = None
    if oldest_result:
        if isinstance(oldest_result, dict):
            oldest_date = oldest_result.get('oldest_date')
            oldest_created = oldest_result.get('oldest_created')
        else:
            oldest_date = oldest_result[0] if len(oldest_result) > 0 else None
            oldest_created = oldest_result[1] if len(oldest_result) > 1 else None
        if oldest_date:
            if isinstance(oldest_date, datetime):
                oldest_article = format_date_ist(oldest_date)
            elif isinstance(oldest_date, date):
                oldest_article = format_date_ist(oldest_date)
            else:
                oldest_article = format_date_ist(datetime.fromisoformat(str(oldest_date))) if oldest_date else None
        elif oldest_created:
            if isinstance(oldest_created, datetime):
                oldest_article = format_date_ist(oldest_created)
            elif isinstance(oldest_created, date):
                oldest_article = format_date_ist(oldest_created)
            else:
                oldest_article = format_date_ist(datetime.fromisoformat(str(oldest_created))) if oldest_created else None
    stats_cursor.close()
    stats_conn.close()
    clients = db.get_clients()
    all_advisories = db.get_advisories(sent_only=False)
    for adv in all_advisories:
        client_list = db.get_advisory_clients(adv['id'])
        adv['clients'] = client_list
        if isinstance(adv.get('sent_date'), date):
            adv['sent_date'] = adv['sent_date'].strftime('%Y-%m-%d')
        elif isinstance(adv.get('sent_date'), datetime):
            adv['sent_date'] = adv['sent_date'].strftime('%Y-%m-%d')
        elif adv.get('sent_date'):
            adv['sent_date'] = str(adv['sent_date'])[:10]
        for client in client_list:
            if isinstance(client.get('sent_date'), datetime):
                client['sent_date'] = client['sent_date'].strftime('%Y-%m-%d %H:%M')
            elif isinstance(client.get('sent_date'), date):
                client['sent_date'] = client['sent_date'].strftime('%Y-%m-%d')
            elif client.get('sent_date'):
                client['sent_date'] = str(client['sent_date'])[:10]
    conn = db.get_connection()
    cursor = db.get_cursor(conn)
    filter_month = request.args.get('calendar_month', '').strip()
    filter_year = request.args.get('calendar_year', '').strip()
    where_clause = "WHERE a.sent_date IS NOT NULL"
    params = []
    param = db._get_param_placeholder()
    if filter_year:
        where_clause += f" AND YEAR(a.sent_date) = {param}"
        params.append(filter_year)
    if filter_month:
        where_clause += f" AND MONTH(a.sent_date) = {param}"
        params.append(filter_month)
    cursor.execute(f"""
        SELECT
            a.id,
            a.name,
            a.topic,
            a.sent_date,
            a.sent_by,
            DATE_FORMAT(a.sent_date, '%Y-%m') as month,
            DATE_FORMAT(a.sent_date, '%Y-%m-%d') as date,
            DATE_FORMAT(a.sent_date, '%H:%i') as time
        FROM advisories a
        {where_clause}
        ORDER BY a.sent_date DESC
        LIMIT 500
    """, params if params else None)
    calendar_rows = cursor.fetchall()
    calendar_data = []
    for row in calendar_rows:
        advisory_id = None
        if isinstance(row, dict):
            advisory_id = row.get('id')
            sent_date = row.get('sent_date')
            if isinstance(sent_date, (datetime, date)):
                sent_date = sent_date.strftime('%Y-%m-%d')
            else:
                sent_date = str(sent_date)[:10] if sent_date else ''
            advisory_clients_list = db.get_advisory_clients(advisory_id) if advisory_id else []
            client_names = [c.get('name', '') for c in advisory_clients_list if c.get('name')]
            calendar_data.append({
                'id': advisory_id,
                'name': row.get('name', ''),
                'topic': row.get('topic', ''),
                'sent_date': sent_date,
                'sent_by': row.get('sent_by', ''),
                'month': row.get('month', ''),
                'date': row.get('date', ''),
                'time': row.get('time', ''),
                'client_count': len(advisory_clients_list),
                'clients': client_names
            })
        else:
            advisory_id = row[0] if len(row) > 0 else None
            sent_date = row[3] if len(row) > 3 else None
            if isinstance(sent_date, (datetime, date)):
                sent_date = sent_date.strftime('%Y-%m-%d')
            else:
                sent_date = str(sent_date)[:10] if sent_date else ''
            advisory_clients_list = db.get_advisory_clients(advisory_id) if advisory_id else []
            client_names = [c.get('name', '') for c in advisory_clients_list if c.get('name')]
            calendar_data.append({
                'id': advisory_id,
                'name': row[1] if len(row) > 1 else '',
                'topic': row[2] if len(row) > 2 else '',
                'sent_date': sent_date,
                'sent_by': row[4] if len(row) > 4 else '',
                'month': row[5] if len(row) > 5 else '',
                'date': row[6] if len(row) > 6 else '',
                'time': row[7] if len(row) > 7 else '',
                'client_count': len(advisory_clients_list),
                'clients': client_names
            })
    cursor.execute("""
        SELECT
            YEAR(sent_date) as year,
            MONTH(sent_date) as month,
            COUNT(*) as count
        FROM advisories
        WHERE sent_date IS NOT NULL
        GROUP BY YEAR(sent_date), MONTH(sent_date)
        ORDER BY year DESC, month DESC
    """)
    summary_rows = cursor.fetchall()
    month_year_stats = {}
    for row in summary_rows:
        if isinstance(row, dict):
            year = row.get('year')
            month = row.get('month')
            count = row.get('count', 0)
        else:
            year = row[0] if len(row) > 0 else None
            month = row[1] if len(row) > 1 else None
            count = row[2] if len(row) > 2 else 0
        if year and month:
            key = f"{year}-{month:02d}"
            month_year_stats[key] = count
    cursor.close()
    conn.close()
    return render_template('settings.html',
                         settings=current_settings,
                         sources=sources_by_category,
                         calendar_data=calendar_data,
                         month_year_stats=month_year_stats,
                         filter_month=filter_month,
                         filter_year=filter_year,
                         source_settings=source_settings,
                         source_overrides=source_overrides,
                         db_stats=db_stats,
                         clients=clients,
                         advisories=all_advisories,
                         category_stats=category_stats,
                         oldest_article=oldest_article,
                         custom_feeds=custom_feeds)
@app.route('/api/settings', methods=['POST'])
@settings_login_required
def api_settings():
    try:
        if request.is_json:
            data = request.json
            fetch_interval = data.get('fetch_interval', 30)
            historical_from = data.get('historical_from', '')
            historical_to = data.get('historical_to', '')
            auto_refresh = data.get('auto_refresh', '0')
        else:
            fetch_interval = request.form.get('fetch_interval', 30)
            historical_from = request.form.get('historical_from', '')
            historical_to = request.form.get('historical_to', '')
            auto_refresh = request.form.get('auto_refresh', '0')
        try:
            fetch_interval = int(fetch_interval) if fetch_interval else 30
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'Invalid interval values'}), 400
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        now = datetime.utcnow().isoformat()
        settings_to_save = {
            'fetch_interval': str(fetch_interval),
            'historical_from': historical_from,
            'historical_to': historical_to,
            'auto_refresh': str(auto_refresh)
        }
        for key, value in settings_to_save.items():
            cursor.execute(f"""
                INSERT INTO settings (setting_key, setting_value, updated_at)
                VALUES ({param}, {param}, {param})
                ON DUPLICATE KEY UPDATE
                setting_value = VALUES(setting_value),
                updated_at = VALUES(updated_at)
            """, (key, value, now))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Settings saved'})
    except Exception as e:
        logger.error(f"Error saving settings: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/settings/sources', methods=['POST'])
@settings_login_required
def api_settings_sources():
    try:
        data = request.json
        enabled_sources = data.get('sources', [])
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        now = datetime.utcnow().isoformat()
        cursor.execute("SELECT source_name, category FROM data_sources")
        db_sources = cursor.fetchall()
        for row in db_sources:
            if isinstance(row, dict):
                source_name = row['source_name']
                category = row['category']
            else:
                source_name = row[0]
                category = row[1]
            enabled = source_name in enabled_sources
            cursor.execute(f"""
                INSERT INTO source_settings (source_name, enabled, category, updated_at)
                VALUES ({param}, {param}, {param}, {param})
                ON DUPLICATE KEY UPDATE
                enabled = VALUES(enabled),
                updated_at = VALUES(updated_at)
            """, (source_name, enabled, category, now))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': f'Source settings saved for {len(db_sources)} sources'})
    except Exception as e:
        logger.error(f"Error saving source settings: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/settings/source/<source_name>', methods=['PUT'])
@settings_login_required
def api_update_source(source_name):
    """Update a source's custom name, URL, or type"""
    try:
        data = request.json
        custom_name = data.get('custom_name', '').strip() or None
        custom_url = data.get('custom_url', '').strip() or None
        custom_type = data.get('custom_type', '').strip() or None
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'source_settings'
            AND COLUMN_NAME IN ('custom_name', 'custom_url', 'custom_type')
        """)
        existing_columns = [row[0] if isinstance(row, (list, tuple)) else row.get('COLUMN_NAME', '') for row in cursor.fetchall()]
        has_custom_columns = 'custom_name' in existing_columns
        if not has_custom_columns:
            try:
                cursor.execute("ALTER TABLE source_settings ADD COLUMN custom_name VARCHAR(255) NULL")
                conn.commit()
            except Exception as e:
                if 'Duplicate column name' not in str(e):
                    logger.warning(f"Could not add custom_name column: {e}")
            try:
                cursor.execute("ALTER TABLE source_settings ADD COLUMN custom_url TEXT NULL")
                conn.commit()
            except Exception as e:
                if 'Duplicate column name' not in str(e):
                    logger.warning(f"Could not add custom_url column: {e}")
            try:
                cursor.execute("ALTER TABLE source_settings ADD COLUMN custom_type VARCHAR(50) NULL")
                conn.commit()
                has_custom_columns = True
            except Exception as e:
                if 'Duplicate column name' not in str(e):
                    logger.warning(f"Could not add custom_type column: {e}")
                    return jsonify({'success': False, 'error': 'Custom columns not available. Please run database migration.'}), 500
                has_custom_columns = True
        cursor.execute(f"""
            UPDATE source_settings
            SET custom_name = {param}, custom_url = {param}, custom_type = {param}
            WHERE source_name = {param}
        """, (custom_name, custom_url, custom_type, source_name))
        if cursor.rowcount == 0:
            cursor.execute(f"SELECT category FROM data_sources WHERE source_name = {param}", (source_name,))
            category_row = cursor.fetchone()
            category = 'news'
            if category_row:
                if isinstance(category_row, dict):
                    category = category_row.get('category', 'news')
                else:
                    category = category_row[0] if category_row else 'news'
            cursor.execute(f"""
                INSERT INTO source_settings (source_name, enabled, category, custom_name, custom_url, custom_type)
                VALUES ({param}, {param}, {param}, {param}, {param}, {param})
            """, (source_name, True, category, custom_name, custom_url, custom_type))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Source updated successfully'})
    except Exception as e:
        logger.error(f"Error updating source: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/fetch/cert-in', methods=['POST'])
def api_fetch_cert_in():
    """Trigger CERT-In advisories fetch (current year only to avoid duplicates)"""
    try:
        from fetchers import CERTInFetcher
        cert_fetcher = CERTInFetcher()
        items = cert_fetcher.safe_fetch(historical=False, current_year_only=True)
        inserted = 0
        updated = 0
        errors = []
        logger.info(f"Fetched {len(items)} CERT-In items, now storing in database...")
        for item in items:
            try:
                item['category'] = 'cert-in'
                result = db.insert_item(item)
                if result is True:
                    inserted += 1
                elif result is False:
                    updated += 1
            except Exception as e:
                errors.append(str(e))
                logger.warning(f"Error inserting CERT-In item: {e}")
        try:
            db.update_fetch_history(
                'CERT-In',
                fetch_type='incremental',
                items_fetched=len(items),
                items_inserted=inserted,
                items_updated=updated
            )
        except Exception as e:
            logger.warning(f"Error updating fetch history for CERT-In: {e}")
        if len(errors) > len(items) * 0.5:
            return jsonify({
                'success': False,
                'error': f'Too many errors: {len(errors)} out of {len(items)} items failed',
                'inserted': inserted,
                'updated': updated
            }), 500
        return jsonify({
            'success': True,
            'message': f'Successfully fetched {len(items)} CERT-In advisories',
            'inserted': inserted,
            'updated': updated,
            'fetched': len(items),
            'errors': len(errors) if errors else 0
        })
    except Exception as e:
        logger.error(f"Error fetching CERT-In: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/fetch/cert-in/hard', methods=['POST'])
def api_fetch_cert_in_hard():
    """Hard fetch CERT-In - fetch from current year to 2003 (earliest available)"""
    try:
        from fetchers import CERTInFetcher
        from datetime import datetime
        cert_fetcher = CERTInFetcher()
        current_year = datetime.utcnow().year
        start_year = 2003
        years_to_fetch = list(range(start_year, current_year + 1))
        items = []
        seen_urls = set()
        for year in reversed(years_to_fetch):
            try:
                year_items = cert_fetcher._fetch_year_advisories(year, seen_urls)
                items.extend(year_items)
                logger.info(f"Hard fetch: Fetched {len(year_items)} advisories for year {year}")
            except Exception as e:
                logger.warning(f"Error fetching CERT-In advisories for year {year}: {e}")
                continue
        inserted = 0
        updated = 0
        errors = []
        logger.info(f"Hard fetch: Fetched {len(items)} CERT-In items from years {years_to_fetch}, now storing in database...")
        for item in items:
            try:
                item['category'] = 'cert-in'
                result = db.insert_item(item)
                if result is True:
                    inserted += 1
                elif result is False:
                    updated += 1
            except Exception as e:
                errors.append(str(e))
                logger.warning(f"Error inserting CERT-In item: {e}")
        try:
            db.update_fetch_history(
                'CERT-In',
                fetch_type='historical',
                items_fetched=len(items),
                items_inserted=inserted,
                items_updated=updated
            )
        except Exception as e:
            logger.warning(f"Error updating fetch history for CERT-In: {e}")
        if len(errors) > len(items) * 0.5:
            return jsonify({
                'success': False,
                'error': f'Too many errors: {len(errors)} out of {len(items)} items failed',
                'inserted': inserted,
                'updated': updated
            }), 500
        return jsonify({
            'success': True,
            'message': f'Hard fetch completed: {len(items)} CERT-In advisories rechecked',
            'inserted': inserted,
            'updated': updated,
            'fetched': len(items),
            'errors': len(errors) if errors else 0
        })
    except Exception as e:
        logger.error(f"Error in hard fetch CERT-In: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/fetch/irdai', methods=['POST'])
def api_fetch_irdai():
    """Trigger IRDAI advisories fetch"""
    try:
        from fetchers import IRDAIFetcher
        irdai_fetcher = IRDAIFetcher()
        items = irdai_fetcher.safe_fetch()
        inserted = 0
        updated = 0
        errors = []
        logger.info(f"Fetched {len(items)} IRDAI items, now storing in database...")
        try:
            items_with_category = [dict(item, category='cert-in') for item in items]
            batch_inserted, batch_updated, batch_errors = db.batch_insert_items(items_with_category)
            inserted = batch_inserted
            updated = batch_updated
            if batch_errors > 0:
                logger.warning(f"Encountered {batch_errors} errors during batch insert")
        except Exception as e:
            logger.error(f"Batch insert failed, using individual inserts: {e}", exc_info=True)
            for item in items:
                try:
                    item['category'] = 'cert-in'
                    result = db.insert_item(item)
                    if result is True:
                        inserted += 1
                    elif result is False:
                        updated += 1
                except Exception as e2:
                    errors.append(str(e2))
                    logger.warning(f"Error inserting IRDAI item: {e2}")
        try:
            db.update_fetch_history(
                'IRDAI',
                fetch_type='incremental',
                items_fetched=len(items),
                items_inserted=inserted,
                items_updated=updated
            )
        except Exception as e:
            logger.warning(f"Error updating fetch history for IRDAI: {e}")
        if len(errors) > len(items) * 0.5:
            return jsonify({
                'success': False,
                'error': f'Too many errors: {len(errors)} out of {len(items)} items failed',
                'inserted': inserted,
                'updated': updated
            }), 500
        return jsonify({
            'success': True,
            'message': f'Successfully fetched {len(items)} IRDAI advisories',
            'inserted': inserted,
            'updated': updated,
            'fetched': len(items),
            'errors': len(errors) if errors else 0
        })
    except Exception as e:
        logger.error(f"Error fetching IRDAI: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/fetch/rbi', methods=['POST'])
def api_fetch_rbi():
    """Trigger RBI Master Directions fetch"""
    try:
        from fetchers import RBIFetcher
        rbi_fetcher = RBIFetcher()
        items = rbi_fetcher.safe_fetch()
        inserted = 0
        updated = 0
        errors = []
        logger.info(f"Fetched {len(items)} RBI items, now storing in database...")
        try:
            items_with_category = [dict(item, category='cert-in') for item in items]
            batch_inserted, batch_updated, batch_errors = db.batch_insert_items(items_with_category)
            inserted = batch_inserted
            updated = batch_updated
            if batch_errors > 0:
                logger.warning(f"Encountered {batch_errors} errors during batch insert")
        except Exception as e:
            logger.error(f"Batch insert failed, using individual inserts: {e}", exc_info=True)
            for item in items:
                try:
                    item['category'] = 'cert-in'
                    result = db.insert_item(item)
                    if result is True:
                        inserted += 1
                    elif result is False:
                        updated += 1
                except Exception as e2:
                    errors.append(str(e2))
                    logger.warning(f"Error inserting RBI item: {e2}")
        try:
            db.update_fetch_history(
                'RBI Directions',
                fetch_type='incremental',
                items_fetched=len(items),
                items_inserted=inserted,
                items_updated=updated
            )
        except Exception as e:
            logger.warning(f"Error updating fetch history for RBI: {e}")
        if len(errors) > len(items) * 0.5:
            return jsonify({
                'success': False,
                'error': f'Too many errors: {len(errors)} out of {len(items)} items failed',
                'inserted': inserted,
                'updated': updated
            }), 500
        return jsonify({
            'success': True,
            'message': f'Successfully fetched {len(items)} RBI Master Directions',
            'inserted': inserted,
            'updated': updated,
            'fetched': len(items),
            'errors': len(errors) if errors else 0
        })
    except Exception as e:
        logger.error(f"Error fetching RBI: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/fetch/historical', methods=['POST'])
def api_fetch_historical():
    """Trigger historical data fetch"""
    try:
        items = fetch_all_sources(historical=True)
        inserted = 0
        updated = 0
        errors = []
        logger.info(f"Fetched {len(items)} items, now storing in database...")
        try:
            batch_inserted, batch_updated, batch_errors = db.batch_insert_items(items)
            inserted = batch_inserted
            updated = batch_updated
            if batch_errors > 0:
                logger.warning(f"Encountered {batch_errors} errors during batch insert")
        except Exception as e:
            logger.error(f"Batch insert failed, using individual inserts: {e}", exc_info=True)
            for item in items:
                try:
                    result = db.insert_item(item)
                    if result:
                        inserted += 1
                    else:
                        updated += 1
                except Exception as e2:
                    error_msg = f"Error storing item '{item.get('title', 'Unknown')}': {str(e2)}"
                    logger.error(error_msg, exc_info=True)
                    errors.append(error_msg)
                    if len(errors) > 50:
                        break
        total_in_db = db.get_total_count()
        return jsonify({
            'success': True,
            'fetched': len(items),
            'inserted': inserted,
            'updated': updated,
            'total_in_db': total_in_db,
            'errors': len(errors),
            'error_samples': errors[:5] if errors else [],
            'message': f'Stored {inserted} new items, {updated} updated. Total in DB: {total_in_db}'
        })
    except Exception as e:
        logger.error(f"Error in historical fetch: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@app.route('/api/cache/clear', methods=['POST'])
def api_cache_clear():
    """Clear cache"""
    return jsonify({'success': True, 'message': 'Cache cleared'})
@app.route('/api/custom-feed', methods=['POST'])
@settings_login_required
def api_custom_feed_add():
    """Add a custom feed"""
    try:
        data = request.json
        name = data.get('name')
        url = data.get('url')
        category = data.get('category', 'news')
        feed_type = data.get('type', 'rss')
        if not name or not url:
            return jsonify({'success': False, 'error': 'Name and URL are required'}), 400
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"""
            INSERT INTO custom_feeds (name, url, category, feed_type)
            VALUES ({param}, {param}, {param}, {param})
        """, (name, url, category, feed_type))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Custom feed added'})
    except Exception as e:
        logger.error(f"Error adding custom feed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/custom-feeds', methods=['GET'])
def api_custom_feeds_list():
    """List all custom feeds"""
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        cursor.execute("SELECT id, name, url, category, feed_type, enabled FROM custom_feeds ORDER BY created_at DESC")
        rows = cursor.fetchall()
        feeds = []
        for row in rows:
            if isinstance(row, dict):
                feeds.append({
                    'id': row['id'],
                    'name': row['name'],
                    'url': row['url'],
                    'category': row['category'],
                    'type': row['feed_type'],
                    'enabled': row.get('enabled', True)
                })
            else:
                feeds.append({
                    'id': row[0],
                    'name': row[1],
                    'url': row[2],
                    'category': row[3],
                    'type': row[4],
                    'enabled': row[5] if len(row) > 5 else True
                })
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'feeds': feeds})
    except Exception as e:
        logger.error(f"Error listing custom feeds: {e}")
        return jsonify({'success': False, 'feeds': []})
@app.route('/api/custom-feed/<int:feed_id>', methods=['PUT'])
@settings_login_required
def api_custom_feed_update(feed_id):
    """Update a custom feed"""
    try:
        data = request.json
        name = data.get('name')
        url = data.get('url')
        category = data.get('category', 'news')
        feed_type = data.get('type', 'rss')
        enabled = data.get('enabled', True)
        if not name or not url:
            return jsonify({'success': False, 'error': 'Name and URL are required'}), 400
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"""
            UPDATE custom_feeds
            SET name = {param}, url = {param}, category = {param}, feed_type = {param}, enabled = {param}
            WHERE id = {param}
        """, (name, url, category, feed_type, enabled, feed_id))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Custom feed updated'})
    except Exception as e:
        logger.error(f"Error updating custom feed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/custom-feed/<int:feed_id>', methods=['DELETE'])
@settings_login_required
def api_custom_feed_delete(feed_id):
    """Delete a custom feed"""
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"DELETE FROM custom_feeds WHERE id = {param}", (feed_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Custom feed deleted'})
    except Exception as e:
        logger.error(f"Error deleting custom feed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Data Sources API endpoints
@app.route('/api/source', methods=['POST'])
@settings_login_required
def api_source_add():
    """Add a data source"""
    try:
        data = request.json
        source_name = data.get('name')
        feed_url = data.get('feed_url') or data.get('url')
        feed_type = data.get('feed_type') or data.get('type', 'rss')
        category = data.get('category', 'news')
        
        if not source_name or not feed_url:
            return jsonify({'success': False, 'error': 'Name and URL are required'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Check if source already exists
        cursor.execute(f"SELECT 1 FROM data_sources WHERE source_name = {param}", (source_name,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Source already exists'}), 400
        
        cursor.execute(f"""
            INSERT INTO data_sources (source_name, feed_url, feed_type, category, enabled)
            VALUES ({param}, {param}, {param}, {param}, TRUE)
        """, (source_name, feed_url, feed_type, category))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Source added'})
    except Exception as e:
        logger.error(f"Error adding source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/source/<path:source_name>', methods=['PUT'])
@settings_login_required
def api_source_update(source_name):
    """Update a data source"""
    try:
        from urllib.parse import unquote
        source_name = unquote(source_name)
        data = request.json
        new_name = data.get('name')
        feed_url = data.get('feed_url') or data.get('url')
        feed_type = data.get('feed_type') or data.get('type', 'rss')
        category = data.get('category', 'news')
        
        if not new_name or not feed_url:
            return jsonify({'success': False, 'error': 'Name and URL are required'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Check if source exists
        cursor.execute(f"SELECT 1 FROM data_sources WHERE source_name = {param}", (source_name,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Source not found'}), 404
        
        # Update source
        cursor.execute(f"""
            UPDATE data_sources
            SET source_name = {param}, feed_url = {param}, feed_type = {param}, category = {param}
            WHERE source_name = {param}
        """, (new_name, feed_url, feed_type, category, source_name))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Source updated'})
    except Exception as e:
        logger.error(f"Error updating source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/source/<path:source_name>', methods=['DELETE'])
@settings_login_required
def api_source_delete(source_name):
    """Delete a data source"""
    try:
        from urllib.parse import unquote
        source_name = unquote(source_name)
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Check if source exists
        cursor.execute(f"SELECT 1 FROM data_sources WHERE source_name = {param}", (source_name,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Source not found'}), 404
        
        cursor.execute(f"DELETE FROM data_sources WHERE source_name = {param}", (source_name,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Source deleted'})
    except Exception as e:
        logger.error(f"Error deleting source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/source/<path:source_name>/toggle', methods=['POST'])
@settings_login_required
def api_source_toggle(source_name):
    """Toggle source enabled status"""
    try:
        from urllib.parse import unquote
        source_name = unquote(source_name)
        data = request.json or {}
        enabled = data.get('enabled', True)
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Check if source exists in data_sources
        cursor.execute(f"SELECT 1 FROM data_sources WHERE source_name = {param}", (source_name,))
        if cursor.fetchone():
            # Update enabled status in data_sources
            cursor.execute(f"UPDATE data_sources SET enabled = {param} WHERE source_name = {param}", (enabled, source_name))
        else:
            # Update in source_settings for hardcoded sources
            cursor.execute(f"""
                INSERT INTO source_settings (source_name, enabled)
                VALUES ({param}, {param})
                ON DUPLICATE KEY UPDATE enabled = {param}
            """, (source_name, enabled, enabled))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': f'Source {"enabled" if enabled else "disabled"}'})
    except Exception as e:
        logger.error(f"Error toggling source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/source/<path:source_name>/test', methods=['POST'])
@settings_login_required
def api_source_test(source_name):
    """Test a data source"""
    try:
        from urllib.parse import unquote
        from feed_parsers import FeedParser
        import requests
        from datetime import datetime
        
        source_name = unquote(source_name)
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Get source details
        cursor.execute(f"""
            SELECT source_name, feed_url, feed_type, category
            FROM data_sources
            WHERE source_name = {param}
        """, (source_name,))
        source_row = cursor.fetchone()
        
        if not source_row:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Source not found'}), 404
        
        if isinstance(source_row, dict):
            url = source_row['feed_url']
            feed_type = source_row['feed_type']
            category = source_row['category']
        else:
            url = source_row[1]
            feed_type = source_row[2]
            category = source_row[3]
        
        cursor.close()
        conn.close()
        
        # Test the source
        test_results = {
            'url': url,
            'status': 'testing',
            'items_found': 0,
            'error': None,
            'response_time': None,
            'last_modified': None
        }
        
        start_time = datetime.utcnow()
        try:
            # Quick connectivity test
            response = requests.get(url, timeout=10, allow_redirects=True)
            test_results['status_code'] = response.status_code
            test_results['response_time'] = (datetime.utcnow() - start_time).total_seconds()
            
            if response.status_code == 200:
                # Try to parse a few items
                parser = FeedParser(timeout=10)
                items, status_code, parsed_type = parser.parse(url, feed_type, source_name, category, historical=False, limit=5)
                test_results['items_found'] = len(items)
                test_results['status'] = 'success'
                test_results['parsed_type'] = parsed_type
                if items:
                    test_results['sample_title'] = items[0].get('title', '')[:100]
            else:
                test_results['status'] = 'error'
                test_results['error'] = f'HTTP {response.status_code}'
        except requests.exceptions.Timeout:
            test_results['status'] = 'error'
            test_results['error'] = 'Connection timeout'
        except requests.exceptions.RequestException as e:
            test_results['status'] = 'error'
            test_results['error'] = str(e)[:200]
        except Exception as e:
            test_results['status'] = 'error'
            test_results['error'] = str(e)[:200]
        
        # Log test results
        if test_results['status'] == 'success':
            logger.info(f"[TEST] [{source_name}] ✓ SUCCESS - Found {test_results['items_found']} items in {test_results.get('response_time', 0):.2f}s")
        else:
            logger.warning(f"[TEST] [{source_name}] ✗ FAILED - {test_results.get('error', 'Unknown error')}")
        
        return jsonify({
            'success': test_results['status'] == 'success',
            'results': test_results
        })
    except Exception as e:
        logger.error(f"Error testing source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/article/<int:article_id>', methods=['DELETE'])
@settings_login_required
def api_delete_article(article_id):
    """Delete a news article"""
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"DELETE FROM news_articles WHERE id = {param}", (article_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Article deleted'})
    except Exception as e:
        logger.error(f"Error deleting article: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/article/<int:article_id>', methods=['PUT'])
@settings_login_required
def api_update_article(article_id):
    """Update a news article"""
    try:
        data = request.json
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        meta_description = data.get('meta_description', '').strip()
        source = data.get('source', '').strip()
        source_url = data.get('source_url', '').strip()
        published_date = data.get('published_date', '').strip()
        tags = data.get('tags', '').strip()
        
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Check if article exists
        cursor.execute(f"SELECT id FROM news_articles WHERE id = {param}", (article_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Article not found'}), 404
        
        # Build update query dynamically
        updates = []
        params = []
        if title:
            updates.append(f"title = {param}")
            params.append(title)
        if description is not None:
            updates.append(f"description = {param}")
            params.append(description)
        if meta_description is not None:
            updates.append(f"meta_description = {param}")
            params.append(meta_description)
        if source:
            updates.append(f"source = {param}")
            params.append(source)
        if source_url is not None:
            updates.append(f"source_url = {param}")
            params.append(source_url)
        if published_date:
            updates.append(f"published_date = {param}")
            params.append(published_date)
        if tags is not None:
            updates.append(f"tags = {param}")
            params.append(tags)
        
        updates.append("updated_at = NOW()")
        params.append(article_id)
        
        cursor.execute(f"""
            UPDATE news_articles
            SET {', '.join(updates)}
            WHERE id = {param}
        """, params)
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Article updated'})
    except Exception as e:
        logger.error(f"Error updating article: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/article', methods=['POST'])
@settings_login_required
def api_create_article():
    """Create a new news article"""
    try:
        data = request.json
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        meta_description = data.get('meta_description', '').strip()
        source = data.get('source', 'Manual').strip()
        source_url = data.get('source_url', '').strip()
        published_date = data.get('published_date', '').strip()
        tags = data.get('tags', '').strip()
        category = data.get('category', 'news').strip()
        
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        if not published_date:
            from datetime import datetime
            published_date = datetime.utcnow().isoformat()
        
        # Generate hash_id
        import hashlib
        hash_input = f"{source}:{source_url}:{title}"
        hash_id = hashlib.sha256(hash_input.encode()).hexdigest()
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        cursor.execute(f"""
            INSERT INTO news_articles 
            (hash_id, title, description, meta_description, source, source_url, published_date, tags)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param}, {param})
        """, (hash_id, title, description, meta_description, source, source_url, published_date, tags))
        conn.commit()
        article_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Article created', 'id': article_id})
    except Exception as e:
        logger.error(f"Error creating article: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/articles/bulk-delete', methods=['POST'])
@settings_login_required
def api_bulk_delete_articles():
    """Bulk delete articles"""
    try:
        data = request.json
        article_ids = data.get('ids', [])
        
        if not article_ids or not isinstance(article_ids, list):
            return jsonify({'success': False, 'error': 'Invalid article IDs'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        placeholders = ','.join([param] * len(article_ids))
        cursor.execute(f"DELETE FROM news_articles WHERE id IN ({placeholders})", article_ids)
        deleted_count = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': f'Deleted {deleted_count} article(s)'})
    except Exception as e:
        logger.error(f"Error bulk deleting articles: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/intelligence/bulk-delete', methods=['POST'])
@settings_login_required
def api_bulk_delete_intelligence():
    """Bulk delete intelligence items"""
    try:
        data = request.json
        item_ids = data.get('ids', [])
        
        if not item_ids or not isinstance(item_ids, list):
            return jsonify({'success': False, 'error': 'Invalid item IDs'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        placeholders = ','.join([param] * len(item_ids))
        cursor.execute(f"DELETE FROM intelligence_items WHERE id IN ({placeholders})", item_ids)
        deleted_count = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': f'Deleted {deleted_count} item(s)'})
    except Exception as e:
        logger.error(f"Error bulk deleting intelligence items: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/articles/by-source', methods=['GET'])
@settings_login_required
def api_get_articles_by_source():
    """Get article IDs by source name"""
    try:
        source = request.args.get('source', '').strip()
        if not source:
            return jsonify({'success': False, 'error': 'Source name required'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"SELECT id FROM news_articles WHERE source = {param}", (source,))
        rows = cursor.fetchall()
        ids = [row['id'] if isinstance(row, dict) else row[0] for row in rows]
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'ids': ids})
    except Exception as e:
        logger.error(f"Error getting articles by source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/intelligence/<int:item_id>', methods=['DELETE'])
@settings_login_required
def api_delete_intelligence(item_id):
    """Delete an intelligence item (CVE, ransomware, etc.)"""
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"DELETE FROM intelligence_items WHERE id = {param}", (item_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Item deleted'})
    except Exception as e:
        logger.error(f"Error deleting intelligence item: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/intelligence/<int:item_id>', methods=['PUT'])
@settings_login_required
def api_update_intelligence(item_id):
    """Update an intelligence item"""
    try:
        data = request.json
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        source = data.get('source', '').strip()
        source_url = data.get('source_url', '').strip()
        published_date = data.get('published_date', '').strip()
        
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # Check if item exists
        cursor.execute(f"SELECT id FROM intelligence_items WHERE id = {param}", (item_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Item not found'}), 404
        
        # Build update query dynamically
        updates = []
        params = []
        if title:
            updates.append(f"title = {param}")
            params.append(title)
        if description is not None:
            updates.append(f"description = {param}")
            params.append(description)
        if source:
            updates.append(f"source = {param}")
            params.append(source)
        if source_url is not None:
            updates.append(f"source_url = {param}")
            params.append(source_url)
        if published_date:
            updates.append(f"published_date = {param}")
            params.append(published_date)
        
        updates.append("updated_at = NOW()")
        params.append(item_id)
        
        cursor.execute(f"""
            UPDATE intelligence_items
            SET {', '.join(updates)}
            WHERE id = {param}
        """, params)
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Item updated'})
    except Exception as e:
        logger.error(f"Error updating intelligence item: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/intelligence', methods=['POST'])
@settings_login_required
def api_create_intelligence():
    """Create a new intelligence item"""
    try:
        data = request.json
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        source = data.get('source', 'Manual').strip()
        source_url = data.get('source_url', '').strip()
        published_date = data.get('published_date', '').strip()
        category = data.get('category', 'cve').strip()
        severity = data.get('severity', '')
        
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        if not published_date:
            from datetime import datetime
            published_date = datetime.utcnow().isoformat()
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        cursor.execute(f"""
            INSERT INTO intelligence_items 
            (title, description, source, source_url, published_date, category, severity)
            VALUES ({param}, {param}, {param}, {param}, {param}, {param}, {param})
        """, (title, description, source, source_url, published_date, category, severity))
        conn.commit()
        item_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'message': 'Item created', 'id': item_id})
    except Exception as e:
        logger.error(f"Error creating intelligence item: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/intelligence/by-source', methods=['GET'])
@settings_login_required
def api_get_intelligence_by_source():
    """Get intelligence item IDs by source name"""
    try:
        source = request.args.get('source', '').strip()
        if not source:
            return jsonify({'success': False, 'error': 'Source name required'}), 400
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"SELECT id FROM intelligence_items WHERE source = {param}", (source,))
        rows = cursor.fetchall()
        ids = [row['id'] if isinstance(row, dict) else row[0] for row in rows]
        cursor.close()
        conn.close()
        return jsonify({'success': True, 'ids': ids})
    except Exception as e:
        logger.error(f"Error getting intelligence items by source: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/article/<int:article_id>/detail', methods=['GET'])
def api_get_article_detail(article_id):
    """Get article details by ID (public endpoint)"""
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        cursor.execute(f"""
            SELECT id, title, description, meta_description, source, source_url, published_date, tags, image_url, created_at
            FROM news_articles
            WHERE id = {param}
        """, (article_id,))
        row = cursor.fetchone()
        if row:
            if isinstance(row, dict):
                item = {
                    'id': row['id'],
                    'title': row['title'],
                    'description': row.get('description', ''),
                    'meta_description': row.get('meta_description', ''),
                    'source': row.get('source', ''),
                    'source_url': row.get('source_url', ''),
                    'published_date': row.get('published_date', ''),
                    'tags': row.get('tags', ''),
                    'image_url': row.get('image_url', ''),
                    'created_at': str(row.get('created_at', ''))
                }
            else:
                item = {
                    'id': row[0],
                    'title': row[1],
                    'description': row[2] if len(row) > 2 else '',
                    'meta_description': row[3] if len(row) > 3 else '',
                    'source': row[4] if len(row) > 4 else '',
                    'source_url': row[5] if len(row) > 5 else '',
                    'published_date': row[6] if len(row) > 6 else '',
                    'tags': row[7] if len(row) > 7 else '',
                    'image_url': row[8] if len(row) > 8 else '',
                    'created_at': str(row[9] if len(row) > 9 else '')
                }
            cursor.close()
            conn.close()
            return jsonify({'success': True, 'item': item})
        else:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Article not found'}), 404
    except Exception as e:
        logger.error(f"Error fetching article detail: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/articles', methods=['GET'])
@settings_login_required
def api_get_articles():
    """Get paginated news articles for management"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search', '').strip()
        source_filter = request.args.get('source', '').strip()
        article_id = request.args.get('id', type=int)
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # If requesting single article by ID
        if article_id:
            cursor.execute(f"""
                SELECT id, title, description, meta_description, source, source_url, published_date, tags, image_url, created_at
                FROM news_articles
                WHERE id = {param}
            """, (article_id,))
            row = cursor.fetchone()
            if row:
                if isinstance(row, dict):
                    item = {
                        'id': row['id'],
                        'title': row['title'],
                        'description': row.get('description', ''),
                        'meta_description': row.get('meta_description', ''),
                        'source': row.get('source', ''),
                        'source_url': row.get('source_url', ''),
                        'published_date': row.get('published_date', ''),
                        'tags': row.get('tags', ''),
                        'image_url': row.get('image_url', ''),
                        'created_at': str(row.get('created_at', ''))
                    }
                else:
                    item = {
                        'id': row[0],
                        'title': row[1],
                        'description': row[2] if len(row) > 2 else '',
                        'meta_description': row[3] if len(row) > 3 else '',
                        'source': row[4] if len(row) > 4 else '',
                        'source_url': row[5] if len(row) > 5 else '',
                        'published_date': row[6] if len(row) > 6 else '',
                        'tags': row[7] if len(row) > 7 else '',
                        'image_url': row[8] if len(row) > 8 else '',
                        'created_at': str(row[9] if len(row) > 9 else '')
                    }
                cursor.close()
                conn.close()
                return jsonify({'success': True, 'item': item})
            else:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': 'Article not found'}), 404
        
        where_clause = "1=1"
        params = []
        
        if search:
            where_clause += f" AND (title LIKE {param} OR description LIKE {param} OR source LIKE {param})"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        
        if source_filter:
            where_clause += f" AND source = {param}"
            params.append(source_filter)
        
        # Get total count
        count_query = f"SELECT COUNT(*) as total FROM news_articles WHERE {where_clause}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()
        total_count = total['total'] if isinstance(total, dict) else total[0]
        
        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT id, title, description, source, source_url, published_date, created_at
            FROM news_articles
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT {param} OFFSET {param}
        """
        params.extend([per_page, offset])
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        items = []
        for row in rows:
            if isinstance(row, dict):
                items.append({
                    'id': row['id'],
                    'title': row['title'],
                    'description': row.get('description', ''),
                    'source': row.get('source', ''),
                    'source_url': row.get('source_url', ''),
                    'published_date': row.get('published_date', ''),
                    'created_at': row.get('created_at', '')
                })
            else:
                items.append({
                    'id': row[0],
                    'title': row[1],
                    'description': row[2] if len(row) > 2 else '',
                    'source': row[3] if len(row) > 3 else '',
                    'source_url': row[4] if len(row) > 4 else '',
                    'published_date': row[5] if len(row) > 5 else '',
                    'created_at': row[6] if len(row) > 6 else ''
                })
        
        cursor.close()
        conn.close()
        
        pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
        
        return jsonify({
            'success': True,
            'items': items,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': pages
            }
        })
    except Exception as e:
        logger.error(f"Error fetching articles: {e}")
        return jsonify({'success': False, 'error': str(e), 'items': []}), 500

@app.route('/api/intelligence', methods=['GET'])
@settings_login_required
def api_get_intelligence():
    """Get paginated intelligence items for management"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        category = request.args.get('category', '').strip()
        search = request.args.get('search', '').strip()
        source_filter = request.args.get('source', '').strip()
        item_id = request.args.get('id', type=int)
        
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        
        # If requesting single item by ID
        if item_id:
            cursor.execute(f"""
                SELECT id, title, description, source, source_url, published_date, category, created_at
                FROM intelligence_items
                WHERE id = {param}
            """, (item_id,))
            row = cursor.fetchone()
            if row:
                if isinstance(row, dict):
                    item = {
                        'id': row['id'],
                        'title': row['title'],
                        'description': row.get('description', ''),
                        'source': row.get('source', ''),
                        'source_url': row.get('source_url', ''),
                        'published_date': row.get('published_date', ''),
                        'category': row.get('category', ''),
                        'created_at': str(row.get('created_at', ''))
                    }
                else:
                    item = {
                        'id': row[0],
                        'title': row[1],
                        'description': row[2] if len(row) > 2 else '',
                        'source': row[3] if len(row) > 3 else '',
                        'source_url': row[4] if len(row) > 4 else '',
                        'published_date': row[5] if len(row) > 5 else '',
                        'category': row[6] if len(row) > 6 else '',
                        'created_at': str(row[7] if len(row) > 7 else '')
                    }
                cursor.close()
                conn.close()
                return jsonify({'success': True, 'item': item})
            else:
                cursor.close()
                conn.close()
                return jsonify({'success': False, 'error': 'Item not found'}), 404
        
        where_clause = "1=1"
        params = []
        
        if category:
            where_clause += f" AND category = {param}"
            params.append(category)
        
        if search:
            where_clause += f" AND (title LIKE {param} OR description LIKE {param} OR source LIKE {param})"
            search_param = f"%{search}%"
            params.extend([search_param, search_param, search_param])
        
        if source_filter:
            where_clause += f" AND source = {param}"
            params.append(source_filter)
        
        # Get total count
        count_query = f"SELECT COUNT(*) as total FROM intelligence_items WHERE {where_clause}"
        cursor.execute(count_query, params)
        total = cursor.fetchone()
        total_count = total['total'] if isinstance(total, dict) else total[0]
        
        # Get paginated results
        offset = (page - 1) * per_page
        query = f"""
            SELECT id, title, description, source, source_url, published_date, category, created_at
            FROM intelligence_items
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT {param} OFFSET {param}
        """
        params.extend([per_page, offset])
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        items = []
        for row in rows:
            if isinstance(row, dict):
                items.append({
                    'id': row['id'],
                    'title': row['title'],
                    'description': row.get('description', ''),
                    'source': row.get('source', ''),
                    'source_url': row.get('source_url', ''),
                    'published_date': row.get('published_date', ''),
                    'category': row.get('category', ''),
                    'created_at': row.get('created_at', '')
                })
            else:
                items.append({
                    'id': row[0],
                    'title': row[1],
                    'description': row[2] if len(row) > 2 else '',
                    'source': row[3] if len(row) > 3 else '',
                    'source_url': row[4] if len(row) > 4 else '',
                    'published_date': row[5] if len(row) > 5 else '',
                    'category': row[6] if len(row) > 6 else '',
                    'created_at': row[7] if len(row) > 7 else ''
                })
        
        cursor.close()
        conn.close()
        
        pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
        
        return jsonify({
            'success': True,
            'items': items,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': pages
            }
        })
    except Exception as e:
        logger.error(f"Error fetching intelligence items: {e}")
        return jsonify({'success': False, 'error': str(e), 'items': []}), 500
@app.route('/api/scheduler/start', methods=['POST'])
def api_scheduler_start():
    """Start the scheduler"""
    try:
        from scheduler import start_scheduler
        data = request.get_json() or {}
        auto_fetch = data.get('auto_fetch', True)
        start_scheduler(auto_fetch=auto_fetch)
        return jsonify({'success': True, 'message': 'Scheduler started'})
    except Exception as e:
        logger.error(f"Error starting scheduler: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/scheduler/stop', methods=['POST'])
def api_scheduler_stop():
    """Stop the scheduler"""
    try:
        from scheduler import scheduler
        scheduler.shutdown()
        return jsonify({'success': True, 'message': 'Scheduler stopped'})
    except Exception as e:
        logger.error(f"Error stopping scheduler: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/scheduler/status', methods=['GET'])
def api_scheduler_status():
    """Get scheduler status"""
    try:
        from scheduler import scheduler
        return jsonify({'success': True, 'running': scheduler.running})
    except:
        return jsonify({'success': True, 'running': False})
@app.route('/tasks')
def tasks():
    """Tasks/Advisory management page"""
    clients = db.get_clients()
    if len(clients) == 0:
        db.init_default_clients()
        clients = db.get_clients()
    all_advisories = db.get_advisories(sent_only=False)
    advisories_pending = []
    advisories_sent = []
    for adv in all_advisories:
        client_list = db.get_advisory_clients(adv['id'])
        adv['clients'] = client_list
        if isinstance(adv.get('sent_date'), date):
            adv['sent_date'] = adv['sent_date'].strftime('%Y-%m-%d')
        elif isinstance(adv.get('sent_date'), datetime):
            adv['sent_date'] = adv['sent_date'].strftime('%Y-%m-%d')
        elif adv.get('sent_date'):
            adv['sent_date'] = str(adv['sent_date'])[:10]
        for client in client_list:
            if isinstance(client.get('sent_date'), datetime):
                client['sent_date'] = client['sent_date'].strftime('%Y-%m-%d %H:%M')
            elif isinstance(client.get('sent_date'), date):
                client['sent_date'] = client['sent_date'].strftime('%Y-%m-%d')
            elif client.get('sent_date'):
                client['sent_date'] = str(client['sent_date'])[:10]
        if len(client_list) > 0:
            advisories_sent.append(adv)
        else:
            advisories_pending.append(adv)
    return render_template('tasks.html',
                         clients=clients,
                         advisories_pending=advisories_pending,
                         advisories_sent=advisories_sent)
@app.route('/api/job/status', methods=['GET'])
def api_job_status():
    """Get current job status"""
    job = job_tracker.get_current_job()
    is_running = job_tracker.is_job_running()
    if job:
        return jsonify({
            'success': True,
            'running': is_running,
            'status': job.get('status', 'unknown'),
            'progress': job.get('progress', 0),
            'message': job.get('message', ''),
            'type': job.get('type', ''),
            'description': job.get('description', ''),
            'started_at': job.get('started_at', ''),
            'completed_at': job.get('completed_at', '')
        })
    else:
        return jsonify({
            'success': True,
            'running': False,
            'status': 'idle',
            'progress': 0,
            'message': 'No job running',
            'type': '',
            'description': '',
            'started_at': None,
            'completed_at': None
        })
@app.route('/api/job/cancel', methods=['POST'])
def api_job_cancel():
    """Cancel current job"""
    job_tracker.cancel_job()
    return jsonify({'success': True, 'message': 'Job cancelled'})
@app.route('/api/fetch/parse', methods=['POST'])
def api_fetch_parse():
    """Parse a feed/URL without storing in database"""
    data = request.json
    url = data.get('url', '')
    feed_type = data.get('type', 'rss')
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'}), 400
    try:
        from feed_parsers import FeedParser
        parser = FeedParser()
        items = parser.parse(url, feed_type, 'test')
        return jsonify({
            'success': True,
            'items': items[:10],
            'total': len(items)
        })
    except Exception as e:
        logger.error(f"Error parsing feed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/advisory', methods=['POST'])
def api_advisory_add():
    """Add a new advisory"""
    data = request.json
    name = data.get('name', '')
    topic = data.get('topic', '')
    sent_date = data.get('sent_date', '')
    sent_by = data.get('sent_by', '')
    if not all([name, topic, sent_date, sent_by]):
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    try:
        advisory_id = db.add_advisory(name, topic, sent_date, sent_by)
        return jsonify({'success': True, 'advisory_id': advisory_id})
    except Exception as e:
        logger.error(f"Error adding advisory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/advisory/<int:advisory_id>/client', methods=['POST'])
def api_advisory_client(advisory_id):
    """Add client to advisory (legacy - kept for backward compatibility)"""
    data = request.json
    client_id = data.get('client_id')
    sent_date = data.get('sent_date', datetime.utcnow().isoformat())
    if not client_id:
        return jsonify({'success': False, 'error': 'Client ID is required'}), 400
    try:
        db.add_advisory_client(advisory_id, client_id, sent_date)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error adding client to advisory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/advisory/<int:advisory_id>/clients', methods=['POST'])
def api_advisory_clients_bulk(advisory_id):
    """Set multiple clients for advisory at once"""
    data = request.json
    client_ids = data.get('client_ids', [])
    if not isinstance(client_ids, list):
        return jsonify({'success': False, 'error': 'client_ids must be a list'}), 400
    try:
        current_clients = db.get_advisory_clients(advisory_id)
        current_client_ids = {c['id'] for c in current_clients}
        new_client_ids = set(client_ids)
        to_remove = current_client_ids - new_client_ids
        for client_id in to_remove:
            db.remove_advisory_client(advisory_id, client_id)
        sent_date = datetime.utcnow().isoformat()
        to_add = new_client_ids - current_client_ids
        for client_id in to_add:
            db.add_advisory_client(advisory_id, client_id, sent_date)
        return jsonify({'success': True, 'added': len(to_add), 'removed': len(to_remove)})
    except Exception as e:
        logger.error(f"Error updating clients for advisory: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/advisory/<int:advisory_id>/client/<int:client_id>', methods=['DELETE'])
def api_advisory_client_remove(advisory_id, client_id):
    """Remove client from advisory"""
    try:
        db.remove_advisory_client(advisory_id, client_id)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error removing client from advisory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/advisory/<int:advisory_id>', methods=['PUT'])
def api_advisory_update(advisory_id):
    """Update an advisory"""
    data = request.json
    name = data.get('name', '')
    topic = data.get('topic', '')
    sent_date = data.get('sent_date', '')
    sent_by = data.get('sent_by', '')
    client_ids = data.get('client_ids', None)
    if not all([name, topic, sent_date, sent_by]):
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    try:
        db.update_advisory(advisory_id, name, topic, sent_date, sent_by)
        if client_ids is not None and isinstance(client_ids, list):
            current_clients = db.get_advisory_clients(advisory_id)
            current_client_ids = {c['id'] for c in current_clients}
            new_client_ids = set(client_ids)
            to_remove = current_client_ids - new_client_ids
            for client_id in to_remove:
                db.remove_advisory_client(advisory_id, client_id)
            sent_date_iso = datetime.utcnow().isoformat()
            to_add = new_client_ids - current_client_ids
            for client_id in to_add:
                db.add_advisory_client(advisory_id, client_id, sent_date_iso)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating advisory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/advisory/<int:advisory_id>', methods=['DELETE'])
def api_advisory_delete(advisory_id):
    """Delete an advisory"""
    try:
        db.delete_advisory(advisory_id)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting advisory: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/client', methods=['POST'])
@settings_login_required
def api_client_add():
    """Add a new client"""
    data = request.json
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Client name is required'}), 400
    try:
        client_id = db.add_client(name)
        return jsonify({'success': True, 'client_id': client_id})
    except Exception as e:
        logger.error(f"Error adding client: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/client/<int:client_id>', methods=['PUT'])
@settings_login_required
def api_client_update(client_id):
    """Update client name"""
    data = request.json
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Client name is required'}), 400
    try:
        db.update_client(client_id, name)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating client: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/client/<int:client_id>', methods=['DELETE'])
@settings_login_required
def api_client_delete(client_id):
    """Delete a client"""
    try:
        db.delete_client(client_id)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting client: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/fetch', methods=['POST'])
def api_fetch():
    """Trigger manual data fetch with optional time period"""
    from scheduler import fetch_and_store
    from job_tracker import job_tracker
    import threading
    hours = request.args.get('hours', type=int) or (request.json.get('hours', type=int) if request.is_json else None)
    date_from = request.args.get('date_from', '').strip() or (request.json.get('date_from', '') if request.is_json else '')
    date_to = request.args.get('date_to', '').strip() or (request.json.get('date_to', '') if request.is_json else '')
    if job_tracker.is_job_running():
        return jsonify({
            'success': False,
            'error': 'A fetch job is already running. Please wait for it to complete.'
        }), 400
    historical = False
    if date_from and date_to:
        from datetime import datetime
        try:
            start = datetime.strptime(date_from, '%Y-%m-%d')
            end = datetime.strptime(date_to, '%Y-%m-%d')
            days_diff = (end - start).days
            historical = days_diff >= 30
        except:
            historical = False
    elif hours:
        historical = hours >= 720
    def run_fetch():
        try:
            if date_from and date_to:
                period_desc = f'{date_from} to {date_to}'
            elif hours:
                if hours == 48:
                    period_desc = 'Last 2 days'
                elif hours == 72:
                    period_desc = 'Last 3 days'
                elif hours < 24:
                    period_desc = f'Last {hours} hours'
                else:
                    period_desc = f'Last {hours // 24} days' if hours % 24 == 0 else f'Last {hours} hours'
            else:
                period_desc = 'Last 24 hours'
            if not job_tracker.start_job('fetch', f'Fetching data for {period_desc}...'):
                return
            job_tracker.update_job(progress=5, message=f'Initializing fetch for {period_desc}...')
            logger.info(f"Starting manual fetch: {period_desc}, historical={historical}, hours={hours}")
            fetch_and_store(historical=historical, hours=hours)
            job_tracker.complete_job(success=True, message=f'Data fetch completed successfully ({period_desc})')
        except Exception as e:
            logger.error(f"Error in manual fetch: {e}", exc_info=True)
            job_tracker.complete_job(success=False, message=f'Error: {str(e)}')
    thread = threading.Thread(target=run_fetch, daemon=True)
    thread.start()
    period_desc = f'Last {hours} hours' if hours else 'Last 24 hours'
    return jsonify({
        'success': True,
        'message': f'Data fetch started for {period_desc}. Check job status for progress.'
    })
@app.route('/api/fetch/news', methods=['POST'])
def api_fetch_news():
    """Refresh News feed"""
    hours = request.args.get('hours', type=int, default=24)
    return api_fetch_category_helper('news', hours=hours)

@app.route('/api/fetch/cve', methods=['POST'])
def api_fetch_cve():
    """Refresh CVE feed"""
    hours = request.args.get('hours', type=int, default=24)
    return api_fetch_category_helper('cve', hours=hours)

@app.route('/api/fetch/ransomware', methods=['POST'])
def api_fetch_ransomware():
    """Refresh Ransomware feed"""
    hours = request.args.get('hours', type=int, default=24)
    return api_fetch_category_helper('ransomware', hours=hours)

@app.route('/api/fetch/cert', methods=['POST'])
def api_fetch_cert():
    """Refresh CERT feed"""
    hours = request.args.get('hours', type=int, default=24)
    return api_fetch_category_helper('cert', hours=hours)

@app.route('/api/fetch/cert-in', methods=['POST'])
def api_fetch_cert_in_route():
    """Refresh CERT-In feed with time range"""
    hours = request.args.get('hours', type=int, default=24)
    return api_fetch_category_helper('cert-in', hours=hours)

def api_fetch_category_helper(category: str, hours: int = 24):
    """Helper function for category fetch"""
    from scheduler import fetch_and_store
    from job_tracker import job_tracker
    from fetchers import fetch_all_sources
    import threading
    
    if category not in ['news', 'cve', 'exploit', 'ransomware', 'cert', 'cert-in']:
        return jsonify({'success': False, 'error': 'Invalid category'}), 400
    
    if job_tracker.is_job_running():
        return jsonify({
            'success': False,
            'error': 'A fetch job is already running. Please wait for it to complete.'
        }), 400
    
    def run_category_fetch():
        try:
            category_display = {
                'news': 'News',
                'cve': 'CVE',
                'exploit': 'Exploit',
                'ransomware': 'Ransomware',
                'cert': 'CERT',
                'cert-in': 'CERT-In'
            }.get(category, category)
            
            time_desc = f'{hours}h' if hours < 24 else f'{hours//24}d'
            
            if not job_tracker.start_job('fetch', f'Fetching {category_display} data ({time_desc})...'):
                return
            
            job_tracker.update_job(progress=5, message=f'Fetching {category_display} data for last {time_desc}...')
            logger.info(f"Fetching {category} for last {hours} hours")
            
            items = fetch_all_sources(historical=False, category_filter=category, hours=hours)
            category_items = [item for item in items if item.get('category') == category]
            
            job_tracker.update_job(progress=50, message=f'Storing {len(category_items)} {category_display} items...')
            
            batch_inserted, batch_updated, batch_errors = db.batch_insert_items(category_items)
            inserted = batch_inserted
            updated = batch_updated
            
            if batch_errors > 0:
                logger.warning(f"Encountered {batch_errors} errors during batch insert")
            
            job_tracker.complete_job(success=True, message=f'{category_display} fetch completed: {len(category_items)} items ({inserted} new, {updated} updated)')
        except Exception as e:
            logger.error(f"Error in category fetch: {e}", exc_info=True)
            job_tracker.complete_job(success=False, message=f'Error: {str(e)}')
    
    thread = threading.Thread(target=run_category_fetch, daemon=True)
    thread.start()
    
    return jsonify({
        'success': True,
        'message': f'{category} fetch started. Check job status for progress.'
    })
@app.route('/api/fetch/category', methods=['POST'])
def api_fetch_category():
    """Fetch data for a specific category"""
    from scheduler import fetch_and_store
    from job_tracker import job_tracker
    from fetchers import fetch_all_sources
    import threading
    data = request.json
    category = data.get('category', '').strip().lower()
    if category not in ['news', 'cve', 'exploit', 'cert']:
        return jsonify({'success': False, 'error': 'Invalid category'}), 400
    if job_tracker.is_job_running():
        return jsonify({
            'success': False,
            'error': 'A fetch job is already running. Please wait for it to complete.'
        }), 400
    def run_category_fetch():
        try:
            category_display = {
                'news': 'News',
                'cve': 'CVE',
                'exploit': 'Exploit',
                'ransomware': 'Security Alerts',
                'cert': 'CERT'
            }.get(category, category)
            if not job_tracker.start_job('fetch', f'Fetching {category_display} data...'):
                return
            job_tracker.update_job(progress=0, message=f'Fetching {category_display} data...')
            items = fetch_all_sources(historical=False, category_filter=category)
            category_items = [item for item in items if item.get('category') == category]
            batch_inserted, batch_updated, batch_errors = db.batch_insert_items(category_items)
            inserted = batch_inserted
            updated = batch_updated
            if batch_errors > 0:
                logger.warning(f"Encountered {batch_errors} errors during batch insert")
            source_key = category.upper().replace('-', '_')
            db.update_fetch_history(
                source_key,
                fetch_type='incremental',
                items_fetched=len(category_items),
                items_inserted=inserted,
                items_updated=updated
            )
            job_tracker.complete_job(success=True, message=f'{category_display} fetch completed: {len(category_items)} items ({inserted} new, {updated} updated)')
        except Exception as e:
            logger.error(f"Error in category fetch: {e}", exc_info=True)
            job_tracker.complete_job(success=False, message=f'Error: {str(e)}')
    thread = threading.Thread(target=run_category_fetch, daemon=True)
    thread.start()
    return jsonify({
        'success': True,
        'message': f'{category} fetch started. Check job status for progress.'
    })
@app.route('/api/fetch/exploit-db/full', methods=['POST'])
@settings_login_required
def api_fetch_exploit_db_full():
    """Download full Exploit-DB database"""
    from fetchers import ExploitDBFetcher
    from job_tracker import job_tracker
    import threading
    if job_tracker.is_job_running():
        return jsonify({
            'success': False,
            'error': 'A fetch job is already running. Please wait for it to complete.'
        }), 400
    def run_full_fetch():
        try:
            if not job_tracker.start_job('fetch', 'Downloading full Exploit-DB database...'):
                return
            job_tracker.update_job(progress=5, message='Initializing Exploit-DB fetcher...')
            fetcher = ExploitDBFetcher()
            job_tracker.update_job(progress=10, message='Fetching Exploit-DB RSS feed...')
            items = fetcher.fetch_full_database()
            job_tracker.update_job(progress=20, message=f'Fetched {len(items)} exploits. Storing in database...')
            inserted = 0
            updated = 0
            total = len(items)
            for idx, item in enumerate(items):
                try:
                    if db.insert_item(item):
                        inserted += 1
                    else:
                        updated += 1
                except Exception as e:
                    logger.warning(f"Error inserting exploit item: {e}")
                    continue
                update_interval = max(1, min(total // 20, 100))
                if (idx + 1) % update_interval == 0 or idx == total - 1:
                    progress = 20 + int((idx + 1) / total * 70)
                    job_tracker.update_job(progress=progress, message=f'Storing exploits: {idx + 1}/{total} ({inserted} new, {updated} updated)...')
            db.update_fetch_history(
                'Exploit-DB',
                fetch_type='historical',
                items_fetched=len(items),
                items_inserted=inserted,
                items_updated=updated
            )
            job_tracker.complete_job(success=True, message=f'Exploit-DB download completed: {len(items)} exploits ({inserted} new, {updated} updated)')
        except Exception as e:
            logger.error(f"Error downloading Exploit-DB: {e}", exc_info=True)
            job_tracker.complete_job(success=False, message=f'Error: {str(e)}')
    thread = threading.Thread(target=run_full_fetch, daemon=True)
    thread.start()
    return jsonify({
        'success': True,
        'message': 'Full Exploit-DB download started. Check job status for progress.',
        'fetched': 0,
        'inserted': 0,
        'updated': 0
    })
@app.route('/api/fetch/exploit-db/refresh', methods=['POST'])
@settings_login_required
def api_fetch_exploit_db_refresh():
    """Refresh Exploit-DB (last 6 hours)"""
    from fetchers import ExploitDBFetcher
    from job_tracker import job_tracker
    import threading
    from datetime import datetime, timedelta
    if job_tracker.is_job_running():
        return jsonify({
            'success': False,
            'error': 'A fetch job is already running. Please wait for it to complete.'
        }), 400
    def run_refresh():
        try:
            if not job_tracker.start_job('fetch', 'Refreshing Exploit-DB (last 6 hours)...'):
                return
            job_tracker.update_job(progress=0, message='Refreshing Exploit-DB...')
            fetcher = ExploitDBFetcher()
            cutoff_time = datetime.utcnow() - timedelta(hours=6)
            items = fetcher.fetch_recent(cutoff_time)
            batch_inserted, batch_updated, batch_errors = db.batch_insert_items(items)
            inserted = batch_inserted
            updated = batch_updated
            if batch_errors > 0:
                logger.warning(f"Encountered {batch_errors} errors during batch insert")
            try:
                db.update_fetch_history(
                    'Exploit-DB',
                    fetch_type='incremental',
                    items_fetched=len(items),
                    items_inserted=inserted,
                    items_updated=updated
                )
            except Exception as e:
                logger.warning(f"Could not update fetch history for Exploit-DB: {e}")
            job_tracker.complete_job(success=True, message=f'Exploit-DB refreshed: {len(items)} exploits ({inserted} new, {updated} updated)')
        except Exception as e:
            logger.error(f"Error refreshing Exploit-DB: {e}", exc_info=True)
            job_tracker.complete_job(success=False, message=f'Error: {str(e)}')
    thread = threading.Thread(target=run_refresh, daemon=True)
    thread.start()
    return jsonify({
        'success': True,
        'message': 'Exploit-DB refresh started. Check job status for progress.',
        'fetched': 0,
        'inserted': 0,
        'updated': 0
    })
@app.route('/api/fetch/sitemap', methods=['POST'])
def api_fetch_sitemap():
    """Fetch a specific sitemap by URL"""
    from job_tracker import job_tracker
    from feed_parsers import FeedParser
    import threading
    data = request.json
    sitemap_url = data.get('url', '').strip()
    source_name = data.get('source_name', 'Sitemap').strip()
    limit = data.get('limit')
    if not sitemap_url:
        return jsonify({'success': False, 'error': 'Sitemap URL is required'}), 400
    if limit is not None:
        try:
            limit = int(limit)
            if limit < 1:
                limit = None
        except (ValueError, TypeError):
            limit = None
    if job_tracker.is_job_running():
        return jsonify({
            'success': False,
            'error': 'A fetch job is already running. Please wait for it to complete.'
        }), 400
    def run_sitemap_fetch():
        try:
            if not job_tracker.start_job('fetch', f'Fetching sitemap: {source_name}...'):
                return
            job_tracker.update_job(progress=0, message=f'Fetching sitemap: {source_name}...')
            feed_parser = FeedParser()
            result = feed_parser.parse(sitemap_url, 'sitemap', source_name, 'news', historical=False, link_archive=False, limit=limit)
            if isinstance(result, tuple):
                items, status_code, feed_type = result
            else:
                items = result
                status_code = 200
            job_tracker.update_job(progress=50, message=f'Parsed {len(items)} items from {source_name}. Storing...')
            inserted, updated, errors = db.batch_insert_items(items)
            if errors > 0:
                logger.warning(f"Encountered {errors} errors during batch insert for {source_name}")
            job_tracker.complete_job(success=True, message=f'Sitemap fetched: {len(items)} items ({inserted} new, {updated} updated)')
        except Exception as e:
            logger.error(f"Error fetching sitemap {sitemap_url}: {e}", exc_info=True)
            job_tracker.complete_job(success=False, message=f'Error: {str(e)}')
    thread = threading.Thread(target=run_sitemap_fetch, daemon=True)
    thread.start()
    return jsonify({
        'success': True,
        'message': f'Fetch started for {source_name}. Check job status for progress.'
    })
@app.route('/api/fetch/manual', methods=['POST'])
def api_fetch_manual():
    """Manually process a feed/sitemap"""
    data = request.json
    url = data.get('url', '').strip()
    feed_type = data.get('type', 'rss')
    category = data.get('category', 'news')
    store = data.get('store', True)
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'}), 400
    try:
        from feed_parsers import FeedParser
        from sitemap_parser import fetch_historical_from_sitemap
        items = []
        if feed_type == 'sitemap':
            from urllib.parse import urlparse
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            items = fetch_historical_from_sitemap(
                base_url, 'Manual Feed', category,
                filter_patterns=['article', 'post', 'news', 'blog', 'story'],
                max_urls=500,
                provided_sitemap=url
            )
        else:
            parser = FeedParser()
            items = parser.parse(url, feed_type, 'Manual Feed', category)
        stored = 0
        errors = []
        if store:
            try:
                batch_inserted, batch_updated, batch_errors = db.batch_insert_items(items)
                stored = batch_inserted + batch_updated
                if batch_errors > 0:
                    logger.warning(f"Encountered {batch_errors} errors during batch insert")
                    errors.append(f"{batch_errors} items failed during batch insert")
            except Exception as e:
                logger.error(f"Batch insert failed: {e}", exc_info=True)
                errors.append(f"Batch insert failed: {str(e)}")
                for item in items:
                    try:
                        if db.insert_item(item):
                            stored += 1
                    except Exception as e2:
                        error_msg = f"Error storing item '{item.get('title', 'Unknown')}': {str(e2)}"
                        logger.error(error_msg, exc_info=True)
                        errors.append(error_msg)
        return jsonify({
            'success': True,
            'total': len(items),
            'stored': stored,
            'errors': errors[:10] if errors else []
        })
    except Exception as e:
        logger.error(f"Error processing manual feed: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/feeds', methods=['GET'])
def api_feeds_list():
    """Get all feeds with pagination and filtering"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        category = request.args.get('category')
        search = request.args.get('search')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        items, total = db.get_items(
            category=category,
            search=search,
            page=page,
            per_page=per_page,
            date_from=date_from,
            date_to=date_to
        )
        return jsonify({
            'success': True,
            'data': items,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Error fetching feeds: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/feeds/<int:feed_id>', methods=['GET'])
def api_feed_get(feed_id):
    """Get a specific feed item by ID"""
    try:
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        cursor.execute(f"SELECT * FROM intelligence_items WHERE id = {param}", (feed_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        if row:
            item = dict(row) if isinstance(row, dict) else dict(row)
            item['tags'] = json.loads(item['tags']) if item['tags'] else []
            item['raw_data'] = json.loads(item['raw_data']) if item['raw_data'] else {}
            return jsonify({'success': True, 'data': item})
        else:
            return jsonify({'success': False, 'error': 'Feed not found'}), 404
    except Exception as e:
        logger.error(f"Error fetching feed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/news', methods=['GET'])
def api_news_list():
    """Get news items with filtering"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        search = request.args.get('search')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        items, total = db.get_items(
            category='news',
            search=search,
            page=page,
            per_page=per_page,
            date_from=date_from,
            date_to=date_to
        )
        return jsonify({
            'success': True,
            'data': items,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Error fetching news: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/cve', methods=['GET'])
def api_cve_list():
    """Get CVE items with filtering"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        search = request.args.get('search')
        severity = request.args.get('severity')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        items, total = db.get_items(
            category='cve',
            search=search,
            page=page,
            per_page=per_page,
            severity=severity,
            date_from=date_from,
            date_to=date_to
        )
        return jsonify({
            'success': True,
            'data': items,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        logger.error(f"Error fetching CVEs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/feeds/update', methods=['POST'])
def api_feeds_update():
    """Update feed items (bulk update)"""
    try:
        data = request.json
        feed_ids = data.get('ids', [])
        updates = data.get('updates', {})
        if not feed_ids:
            return jsonify({'success': False, 'error': 'No feed IDs provided'}), 400
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        update_fields = []
        update_values = []
        for key, value in updates.items():
            if key in ['title', 'description', 'severity', 'tags']:
                update_fields.append(f"{key} = {param}")
                if key == 'tags' and isinstance(value, list):
                    import json
                    update_values.append(json.dumps(value))
                else:
                    update_values.append(value)
        if not update_fields:
            return jsonify({'success': False, 'error': 'No valid fields to update'}), 400
        update_values.extend(feed_ids)
        placeholders = ', '.join([param] * len(feed_ids))
        query = f"""
            UPDATE intelligence_items
            SET {', '.join(update_fields)}, updated_at = NOW()
            WHERE id IN ({placeholders})
        """
        cursor.execute(query, update_values)
        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'updated': affected,
            'message': f'Updated {affected} feed(s)'
        })
    except Exception as e:
        logger.error(f"Error updating feeds: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/api/feeds/delete', methods=['POST'])
def api_feeds_delete():
    """Delete feed items (bulk delete)"""
    try:
        data = request.json
        feed_ids = data.get('ids', [])
        if not feed_ids:
            return jsonify({'success': False, 'error': 'No feed IDs provided'}), 400
        conn = db.get_connection()
        cursor = db.get_cursor(conn)
        param = db._get_param_placeholder()
        placeholders = ', '.join([param] * len(feed_ids))
        cursor.execute(f"DELETE FROM intelligence_items WHERE id IN ({placeholders})", feed_ids)
        conn.commit()
        deleted = cursor.rowcount
        cursor.close()
        conn.close()
        return jsonify({
            'success': True,
            'deleted': deleted,
            'message': f'Deleted {deleted} feed(s)'
        })
    except Exception as e:
        logger.error(f"Error deleting feeds: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    import config
    if config.DEBUG:
        app.run(host=config.HOST, port=config.PORT, debug=True)
    else:
        from waitress import serve
        serve(app, host=config.HOST, port=config.PORT, threads=4)