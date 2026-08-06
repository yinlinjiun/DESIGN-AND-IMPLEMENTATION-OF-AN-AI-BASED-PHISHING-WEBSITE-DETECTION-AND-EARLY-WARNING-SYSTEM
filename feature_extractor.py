"""
特征提取模块
从URL和网页内容中提取特征用于钓鱼网站检测
"""
import re
import os
import urllib.parse
import tldextract
import socket
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
import ssl
import urllib3
import ipaddress
import datetime
try:
    import whois as whois_lib
except Exception:
    whois_lib = None

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class URLFeatureExtractor:
    """URL特征提取器 - 支持URL语义分析"""
    
    def __init__(self):
        # 这些词表用于从URL文本中识别“登录、验证、紧急、品牌仿冒”等钓鱼常见语义。
        # 可疑关键词（用于语义分析）
        self.suspicious_keywords = [
            'secure', 'verify', 'account', 'update', 'confirm', 'suspend',
            'limited', 'expire', 'urgent', 'action', 'required', 'login',
            'bank', 'paypal', 'amazon', 'ebay', 'microsoft', 'apple'
        ]
        
        # 品牌关键词（用于检测品牌仿冒）
        self.brand_keywords = [
            'paypal', 'amazon', 'ebay', 'microsoft', 'apple', 'google',
            'facebook', 'twitter', 'linkedin', 'github', 'netflix',
            'alibaba', 'taobao', 'alipay', 'wechat', 'qq', 'baidu'
        ]
        
        # 威胁性词汇（用于语义分析）
        self.threat_keywords = [
            'suspend', 'expire', 'urgent', 'immediate', 'verify',
            'confirm', 'update', 'security', 'warning', 'alert'
        ]
    
    def extract_features(self, url):
        """
        从URL中提取特征
        返回特征字典
        """
        if not url or not isinstance(url, str):
            return self._get_default_features()
        
        try:
            # 确保URL有协议
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # urlparse 将URL拆成协议、域名、路径、查询参数，后续URL特征都基于这些部分计算。
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            # 提取TLD信息
            try:
                extracted = tldextract.extract(url)
                subdomain = extracted.subdomain
                domain_name = extracted.domain
                tld = extracted.suffix
            except:
                subdomain = ''
                domain_name = domain.split('.')[0] if '.' in domain else domain
                tld = domain.split('.')[-1] if '.' in domain else ''
            
            # 计算子域名级别
            subdomain_level = len(subdomain.split('.')) if subdomain else 0
            
            # 计算路径级别（深度）
            path_level = parsed.path.strip('/').count('/') if parsed.path.strip('/') else 0
            
            # 查询参数解析
            query_params = parse_qs(parsed.query)
            num_query_components = len(query_params)
            
            # 计算双斜杠
            double_slash_in_path = 1 if '//' in parsed.path else 0
            
            # 检查域名是否在子域名或路径中
            domain_in_subdomains = 1 if domain_name in subdomain else 0
            domain_in_paths = 1 if domain_name in parsed.path.lower() else 0
            
            # 检查HTTPS是否在主机名中（异常情况）
            https_in_hostname = 1 if 'https' in domain.lower() else 0
            
            # 检查随机字符串（URL中包含随机字符序列）
            random_string = 1 if self._has_random_string(url) else 0
            
            # 同时生成Kaggle/UCI字段和系统自定义字段，便于模型训练和在线检测共用一套特征。
            features = {
                # Kaggle数据集特征映射
                'NumDots': url.count('.'),
                'SubdomainLevel': subdomain_level,
                'PathLevel': path_level,
                'UrlLength': len(url),
                'NumDash': url.count('-'),
                'NumDashInHostname': domain.count('-'),
                'AtSymbol': 1 if '@' in url else 0,
                'TildeSymbol': 1 if '~' in url else 0,
                'NumUnderscore': url.count('_'),
                'NumPercent': url.count('%'),
                'NumQueryComponents': num_query_components,
                'NumAmpersand': url.count('&'),
                'NumHash': url.count('#'),
                'NumNumericChars': sum(1 for c in url if c.isdigit()),
                'NoHttps': 1 if parsed.scheme != 'https' else 0,
                'RandomString': random_string,
                'IpAddress': 1 if self._is_ip_address(domain) else 0,
                'DomainInSubdomains': domain_in_subdomains,
                'DomainInPaths': domain_in_paths,
                'HttpsInHostname': https_in_hostname,
                'HostnameLength': len(domain),
                'PathLength': len(parsed.path),
                'QueryLength': len(parsed.query),
                'DoubleSlashInPath': double_slash_in_path,
                'NumSensitiveWords': sum(1 for keyword in self.suspicious_keywords if keyword in url.lower()),
                'EmbeddedBrandName': 1 if any(brand in url.lower() for brand in self.brand_keywords) else 0,
                
                # UCI数据集特征映射（部分）
                'having_IP_Address': 1 if self._is_ip_address(domain) else -1,
                'URL_Length': 1 if len(url) > 75 else (0 if len(url) > 54 else -1),  # 1=长, 0=中, -1=短
                'Shortining_Service': 1 if any(short in url.lower() for short in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else -1,
                'having_At_Symbol': 1 if '@' in url else -1,
                'double_slash_redirecting': double_slash_in_path,
                'Prefix_Suffix': 1 if '-' in domain else -1,
                'having_Sub_Domain': 1 if subdomain_level > 1 else (0 if subdomain_level == 1 else -1),
                'port': 1 if ':' in domain and domain.split(':')[1].isdigit() else -1,
                'HTTPS_token': 1 if 'https' in parsed.path.lower() else -1,
                'Abnormal_URL': 1 if self._is_abnormal_url(url, domain) else -1,
                
                # 保留原有特征（用于兼容性）
                'url_length': len(url),
                'domain_length': len(domain),
                'path_length': len(parsed.path),
                'query_length': len(parsed.query),
                'fragment_length': len(parsed.fragment),
                'url_depth': path_level,
                'has_ip': 1 if self._is_ip_address(domain) else 0,
                'has_at_symbol': 1 if '@' in url else 0,
                'has_dash': 1 if '-' in domain else 0,
                'has_underscore': 1 if '_' in domain else 0,
                'has_redirect': 1 if any(x in url.lower() for x in ['redirect', 'url=', 'goto', 'link']) else 0,
                'has_port': 1 if ':' in domain and domain.split(':')[1].isdigit() else 0,
                'subdomain_count': subdomain_level,
                'tld_length': len(tld),
                'tld_type': self._get_tld_type(parsed.netloc),
                'https_used': 1 if parsed.scheme == 'https' else 0,
                'suspicious_keywords': sum(1 for keyword in self.suspicious_keywords if keyword in url.lower()),
                'brand_keywords': sum(1 for keyword in self.brand_keywords if keyword in url.lower()),
                'threat_keywords': sum(1 for keyword in self.threat_keywords if keyword in url.lower()),
                'domain_similarity_score': self._calculate_domain_similarity(domain),
                'has_typosquatting': 1 if self._detect_typosquatting(domain) else 0,
                'digit_count': sum(1 for c in url if c.isdigit()),
                'digit_ratio': sum(1 for c in url if c.isdigit()) / len(url) if url else 0,
                'special_char_count': sum(1 for c in url if c in '!@#$%^&*()_+-=[]{}|;:,.<>?'),
                'special_char_ratio': sum(1 for c in url if c in '!@#$%^&*()_+-=[]{}|;:,.<>?') / len(url) if url else 0,
                'has_encoding': 1 if '%' in url else 0,
                'encoding_ratio': url.count('%') / len(url) if url else 0,
            }
            
            return features
            
        except Exception as e:
            print(f"提取URL特征时出错: {e}")
            return self._get_default_features()
    
    def _is_ip_address(self, domain):
        """检查是否为IP地址"""
        try:
            socket.inet_aton(domain)
            return True
        except:
            return False
    
    def _get_tld_type(self, domain):
        """获取TLD类型编码"""
        if not domain:
            return 0
        tld = domain.split('.')[-1] if '.' in domain else ''
        common_tlds = ['com', 'org', 'net', 'edu', 'gov']
        if tld in common_tlds:
            return 0
        elif tld in ['info', 'biz', 'co']:
            return 1
        else:
            return 2
    
    def _calculate_domain_similarity(self, domain):
        """计算域名与知名品牌的相似度（语义分析）"""
        if not domain:
            return 0.0
        
        domain_lower = domain.lower()
        max_similarity = 0.0
        
        for brand in self.brand_keywords:
            if brand in domain_lower:
                # 如果域名包含品牌名，计算相似度
                similarity = len(brand) / max(len(domain_lower), len(brand))
                max_similarity = max(max_similarity, similarity)
        
        return max_similarity
    
    def _detect_typosquatting(self, domain):
        """检测域名拼写错误（typosquatting）"""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        # 检测常见的拼写错误模式
        typo_patterns = [
            r'[a-z]+\d+[a-z]+',  # 字母数字混合（如paypa1）
            r'[a-z]+-[a-z]+',    # 多个连字符
            r'www\d+',            # www后跟数字
        ]
        
        for pattern in typo_patterns:
            if re.search(pattern, domain_lower):
                return True
        
        # 检测字符替换（如paypal -> paypa1）
        for brand in self.brand_keywords:
            if brand in domain_lower:
                # 检查是否有字符被替换
                if len(domain_lower) == len(brand) + 1 or len(domain_lower) == len(brand):
                    # 简单的相似度检查
                    diff_count = sum(1 for a, b in zip(domain_lower, brand) if a != b)
                    if diff_count <= 2 and diff_count > 0:
                        return True
        
        return False
    
    def _has_random_string(self, url):
        """检测URL中是否包含随机字符串（如长随机字符序列）"""
        # 检测长随机字符序列（超过8个连续随机字符）
        pattern = r'[a-zA-Z0-9]{10,}'
        matches = re.findall(pattern, url)
        for match in matches:
            # 检查是否看起来像随机字符串（没有常见单词）
            if len(match) >= 10 and not any(word in match.lower() for word in ['www', 'http', 'https', 'com', 'org', 'net']):
                # 检查字符分布（随机字符串通常字符分布较均匀）
                char_counts = {}
                for char in match.lower():
                    char_counts[char] = char_counts.get(char, 0) + 1
                if len(char_counts) >= 6:  # 至少6种不同字符
                    return True
        return False
    
    def _is_abnormal_url(self, url, domain):
        """检测异常URL（如域名和路径不匹配等）"""
        parsed = urlparse(url)
        # 检查域名是否在路径中（异常情况）
        if domain and domain in parsed.path.lower():
            return True
        # 检查是否有异常长的路径
        if len(parsed.path) > 200:
            return True
        return False
    
    def _get_default_features(self):
        """返回默认特征值"""
        return {
            'url_length': 0,
            'domain_length': 0,
            'path_length': 0,
            'query_length': 0,
            'fragment_length': 0,
            'url_depth': 0,
            'has_ip': 0,
            'has_at_symbol': 0,
            'has_dash': 0,
            'has_underscore': 0,
            'has_redirect': 0,
            'has_port': 0,
            'subdomain_count': 0,
            'tld_length': 0,
            'tld_type': 0,
            'https_used': 0,
            'suspicious_keywords': 0,
            'brand_keywords': 0,
            'threat_keywords': 0,
            'domain_similarity_score': 0.0,
            'has_typosquatting': 0,
            'digit_count': 0,
            'digit_ratio': 0,
            'special_char_count': 0,
            'special_char_ratio': 0,
            'has_encoding': 0,
            'encoding_ratio': 0.0,
            
            # Kaggle数据集URL特征
            'NumDots': 0,
            'SubdomainLevel': 0,
            'PathLevel': 0,
            'UrlLength': 0,
            'NumDash': 0,
            'NumDashInHostname': 0,
            'AtSymbol': 0,
            'TildeSymbol': 0,
            'NumUnderscore': 0,
            'NumPercent': 0,
            'NumQueryComponents': 0,
            'NumAmpersand': 0,
            'NumHash': 0,
            'NumNumericChars': 0,
            'NoHttps': 0,
            'RandomString': 0,
            'IpAddress': 0,
            'DomainInSubdomains': 0,
            'DomainInPaths': 0,
            'HttpsInHostname': 0,
            'HostnameLength': 0,
            'PathLength': 0,
            'QueryLength': 0,
            'DoubleSlashInPath': 0,
            'NumSensitiveWords': 0,
            'EmbeddedBrandName': 0,
            
            # UCI数据集URL特征
            'having_IP_Address': -1,
            'URL_Length': -1,
            'Shortining_Service': -1,
            'having_At_Symbol': -1,
            'double_slash_redirecting': 0,
            'Prefix_Suffix': -1,
            'having_Sub_Domain': -1,
            'port': -1,
            'HTTPS_token': -1,
            'Abnormal_URL': -1,
        }


class WebPageFeatureExtractor:
    """网页特征提取器"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        # 使用常见浏览器UA，降低部分网站因默认Python请求头而拒绝访问的概率。
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def extract_features(self, url):
        """
        从网页内容中提取特征
        返回特征字典
        """
        if not url or not isinstance(url, str):
            return self._get_default_features()
        
        try:
            # 确保URL有协议
            original_url = url
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            
            # 对于 localhost，优先尝试从本地文件读取
            # 本地演示页面无法总是通过HTTP访问，所以对localhost额外支持直接读取HTML文件。
            if 'localhost' in parsed.netloc or '127.0.0.1' in parsed.netloc:
                file_path = parsed.path.lstrip('/')
                if file_path:
                    # 尝试多个可能的路径
                    current_dir = os.getcwd()
                    possible_paths = [
                        file_path,
                        os.path.join(current_dir, file_path),
                        os.path.abspath(file_path),
                    ]
                    
                    # 去重
                    possible_paths = list(dict.fromkeys(possible_paths))
                    
                    for path in possible_paths:
                        if path and os.path.exists(path) and os.path.isfile(path):
                            print(f"[OK] 从本地文件读取: {path}")
                            try:
                                with open(path, 'r', encoding='utf-8') as f:
                                    html_content = f.read()
                                soup = BeautifulSoup(html_content, 'html.parser')
                                # 创建模拟response对象
                                class MockResponse:
                                    status_code = 200
                                    content = html_content.encode('utf-8')
                                    class Elapsed:
                                        def total_seconds(self):
                                            return 0.1
                                    elapsed = Elapsed()
                                mock_response = MockResponse()
                                features = self._extract_features_from_soup(soup, url, mock_response)
                                print(f"[OK] 成功提取特征: iframe={features.get('iframe_count', 0)}, form={features.get('form_count', 0)}, popup={features.get('popup_count', 0)}")
                                return features
                            except Exception as e2:
                                print(f"✗ 本地文件读取失败: {e2}")
                                break
            
            # 尝试HTTP请求
            # 真实网址优先走HTTP请求，并在SSL异常时降级尝试，尽可能提取网页内容特征。
            response = None
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=True, allow_redirects=True)
            except requests.exceptions.SSLError:
                # SSL错误，使用不验证证书的方式
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            except requests.exceptions.RequestException as e:
                # 请求失败，尝试从本地文件读取（如果是localhost）
                print(f"网页特征提取请求失败: {e}")
                print(f"URL: {url}")
                
                # 尝试从本地文件读取（针对localhost:8000/test_phishing.html这种情况）
                parsed = urlparse(url)
                if 'localhost' in parsed.netloc or '127.0.0.1' in parsed.netloc:
                    file_path = parsed.path.lstrip('/')
                    # 尝试多个可能的路径
                    current_dir = os.getcwd()
                    possible_paths = [
                        file_path,  # 直接路径（相对于当前工作目录）
                        os.path.join(current_dir, file_path),  # 当前工作目录
                        os.path.abspath(file_path),  # 绝对路径
                    ]
                    
                    # 去重
                    possible_paths = list(dict.fromkeys(possible_paths))
                    
                    file_found = None
                    for path in possible_paths:
                        if path and os.path.exists(path) and os.path.isfile(path):
                            file_found = path
                            print(f"[OK] 找到本地文件: {file_found}")
                            break
                    
                    if file_found:
                        try:
                            with open(file_found, 'r', encoding='utf-8') as f:
                                html_content = f.read()
                            soup = BeautifulSoup(html_content, 'html.parser')
                            # 创建一个模拟的response对象
                            class MockResponse:
                                status_code = 200
                                content = html_content.encode('utf-8')
                                class Elapsed:
                                    def total_seconds(self):
                                        return 0.1
                                elapsed = Elapsed()
                            mock_response = MockResponse()
                            features = self._extract_features_from_soup(soup, url, mock_response)
                            print(f"[OK] 成功从本地文件提取特征:")
                            print(f"  - iframe_count: {features.get('iframe_count', 0)}")
                            print(f"  - form_count: {features.get('form_count', 0)}")
                            print(f"  - popup_count: {features.get('popup_count', 0)}")
                            print(f"  - suspicious_forms: {features.get('suspicious_forms', 0)}")
                            print(f"  - IframeOrFrame: {features.get('IframeOrFrame', 0)}")
                            print(f"  - PopUpWindow: {features.get('PopUpWindow', 0)}")
                            return features
                        except Exception as e2:
                            print(f"✗ 从本地文件读取失败: {e2}")
                            import traceback
                            traceback.print_exc()
                    else:
                        print(f"✗ 未找到本地文件")
                        print(f"  尝试的路径: {possible_paths}")
                        print(f"  当前工作目录: {current_dir}")
                        print(f"  URL路径: {file_path}")
                        # 列出当前目录的文件
                        try:
                            files_in_dir = [f for f in os.listdir(current_dir) if f.endswith('.html')]
                            if files_in_dir:
                                print(f"  当前目录中的HTML文件: {files_in_dir}")
                        except:
                            pass
                
                return self._get_default_features()
            
            if response is None:
                print(f"网页特征提取失败: 无法获取响应")
                return self._get_default_features()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            features = self._extract_features_from_soup(soup, url, response)
            
            return features
            
        except requests.exceptions.SSLError:
            # SSL错误，尝试不验证证书
            try:
                response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
                soup = BeautifulSoup(response.content, 'html.parser')
                features = self._extract_features_from_soup(soup, url, response)
                features['ssl_cert_valid'] = 0
                features['has_ssl'] = 1 if url.startswith('https://') else 0
                return features
            except Exception as e2:
                print(f"提取网页特征时出错（SSL错误后重试失败）: {e2}")
                return {**self._get_default_features(), 'ssl_cert_valid': 0, 'has_ssl': 1 if url.startswith('https://') else 0}
        except Exception as e:
            print(f"提取网页特征时出错: {e}")
            print(f"错误类型: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return self._get_default_features()
    
    def _extract_features_from_soup(self, soup, url, response):
        """从BeautifulSoup对象中提取特征"""
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # 从HTML结构中统计链接、资源、表单、脚本等行为特征，这些是钓鱼页面常见风险点。
        # 提取所有链接
        all_links = soup.find_all('a', href=True)
        external_links = [a for a in all_links if a['href'].startswith(('http://', 'https://'))]
        internal_links = [a for a in all_links if not a['href'].startswith(('http://', 'https://'))]
        total_links = len(all_links)
        
        # 提取所有资源URL（图片、CSS、JS等）
        img_tags = soup.find_all('img', src=True)
        link_tags = soup.find_all('link', href=True)
        script_tags = soup.find_all('script', src=True)
        all_resource_urls = [tag.get('src') or tag.get('href') for tag in img_tags + link_tags + script_tags if tag.get('src') or tag.get('href')]
        external_resources = [url for url in all_resource_urls if url and url.startswith(('http://', 'https://'))]
        total_resources = len(all_resource_urls)
        
        # 计算外部链接和资源百分比
        pct_ext_hyperlinks = len(external_links) / max(total_links, 1) if total_links > 0 else 0.0
        pct_ext_resource_urls = len(external_resources) / max(total_resources, 1) if total_resources > 0 else 0.0
        
        # 检查Favicon
        favicon_tags = soup.find_all('link', rel=re.compile('icon', re.I))
        ext_favicon = 1 if any(tag.get('href', '').startswith(('http://', 'https://')) for tag in favicon_tags) else 0
        
        # 检查表单
        forms = soup.find_all('form')
        insecure_forms = 0
        relative_form_action = 0
        ext_form_action = 0
        abnormal_form_action = 0
        
        for form in forms:
            action = form.get('action', '').strip()
            if not action or action == '':
                relative_form_action += 1
            elif action.startswith(('http://', 'https://')):
                ext_form_action += 1
                # 检查表单动作是否异常（提交到不同域名）
                if domain and domain not in action:
                    abnormal_form_action += 1
            # 检查表单是否不安全（没有HTTPS）
            if not url.startswith('https://'):
                insecure_forms += 1
        
        # 检查空的自重定向链接
        null_self_redirect_links = 0
        for link in all_links:
            href = link.get('href', '')
            if href in ['#', 'javascript:void(0)', 'javascript:;'] or not href:
                null_self_redirect_links += 1
        
        pct_null_self_redirect_hyperlinks = null_self_redirect_links / max(total_links, 1) if total_links > 0 else 0.0
        
        # 检查右键是否被禁用
        scripts_text = ' '.join([str(s) for s in soup.find_all('script')])
        right_click_disabled = 1 if 'contextmenu' in scripts_text.lower() or 'oncontextmenu' in scripts_text.lower() else 0
        
        # 检查弹窗
        popup_window = 1 if any('popup' in str(s).lower() or 'alert' in str(s).lower() or 'confirm' in str(s).lower() for s in soup.find_all('script')) else 0
        
        # 检查iframe
        iframe_or_frame = 1 if soup.find_all('iframe') or soup.find_all('frame') else 0
        
        # 检查标题
        missing_title = 1 if not soup.title or not soup.title.string or not soup.title.string.strip() else 0
        
        # 检查表单中是否只有图片
        forms_with_images = [f for f in forms if f.find_all('img') and not f.find_all('input')]
        images_only_in_form = 1 if forms_with_images else 0
        
        # 检查是否提交信息到邮箱
        submit_info_to_email = 1 if 'mailto:' in str(soup).lower() and any('submit' in str(f).lower() for f in forms) else 0
        
        # 检查重定向
        redirect = 1 if soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)}) else 0
        
        # 检查鼠标悬停事件
        on_mouseover = 1 if 'onmouseover' in str(soup).lower() else 0
        
        # 检查状态栏中的假链接
        fake_link_in_status_bar = 1 if 'status' in scripts_text.lower() and 'link' in scripts_text.lower() else 0
        
        # 检查域名不匹配（链接指向的域名与当前域名不一致）
        domain_mismatches = 0
        for link in external_links:
            try:
                link_domain = urlparse(link['href']).netloc
                if domain and link_domain and domain.lower() != link_domain.lower():
                    domain_mismatches += 1
            except:
                pass
        frequent_domain_name_mismatch = 1 if domain_mismatches > total_links * 0.5 else 0
        
        # 这里输出的字段会和URL特征合并，最终一起送入机器学习模型。
        features = {
            # Kaggle数据集网页特征
            'PctExtHyperlinks': pct_ext_hyperlinks,
            'PctExtResourceUrls': pct_ext_resource_urls,
            'ExtFavicon': ext_favicon,
            'InsecureForms': insecure_forms,
            'RelativeFormAction': relative_form_action,
            'ExtFormAction': ext_form_action,
            'AbnormalFormAction': abnormal_form_action,
            'PctNullSelfRedirectHyperlinks': pct_null_self_redirect_hyperlinks,
            'FrequentDomainNameMismatch': frequent_domain_name_mismatch,
            'FakeLinkInStatusBar': fake_link_in_status_bar,
            'RightClickDisabled': right_click_disabled,
            'PopUpWindow': popup_window,
            'SubmitInfoToEmail': submit_info_to_email,
            'IframeOrFrame': iframe_or_frame,
            'MissingTitle': missing_title,
            'ImagesOnlyInForm': images_only_in_form,
            
            # UCI数据集网页特征
            'Favicon': 1 if favicon_tags else -1,
            'Request_URL': 1 if len(external_links) > len(internal_links) else -1,
            'URL_of_Anchor': 1 if pct_ext_hyperlinks > 0.5 else (-1 if pct_ext_hyperlinks < 0.2 else 0),
            'Links_in_tags': 1 if len(soup.find_all(['link', 'script', 'meta'])) > 10 else (-1 if len(soup.find_all(['link', 'script', 'meta'])) < 3 else 0),
            'SFH': 1 if ext_form_action > 0 else (-1 if relative_form_action > 0 else 0),
            'Submitting_to_email': submit_info_to_email,
            'Abnormal_URL': 1 if abnormal_form_action > 0 else -1,
            'Redirect': redirect,
            'on_mouseover': on_mouseover,
            'RightClick': 1 if right_click_disabled else -1,
            'popUpWidnow': 1 if popup_window else -1,
            'Iframe': 1 if iframe_or_frame else -1,
            
            # 保留原有特征（用于兼容性）
            'status_code': response.status_code,
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds(),
            'title_length': len(soup.title.string) if soup.title and soup.title.string else 0,
            'meta_count': len(soup.find_all('meta')),
            'link_count': total_links,
            'image_count': len(img_tags),
            'script_count': len(script_tags),
            'iframe_count': len(soup.find_all('iframe')),
            'form_count': len(forms),
            'input_count': len(soup.find_all('input')),
            'external_links': len(external_links),
            'internal_links': len(internal_links),
            'empty_links': len([a for a in soup.find_all('a') if not a.get_text().strip()]),
            'body_text_length': len(soup.get_text()) if soup.get_text() else 0,
            'link_text_ratio': len(' '.join([a.get_text() for a in soup.find_all('a')])) / max(len(soup.get_text()), 1),
            'has_ssl': 1 if url.startswith('https://') else 0,
            'has_favicon': 1 if favicon_tags else 0,
            'meta_refresh': redirect,
            'popup_count': len([s for s in soup.find_all('script') if 'popup' in str(s).lower() or 'alert' in str(s).lower()]),
            'suspicious_forms': len([f for f in forms if any(keyword in str(f).lower() for keyword in ['password', 'credit', 'card', 'ssn'])]),
        }
        
        # SSL证书验证
        try:
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((parsed.netloc, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                        features['ssl_cert_valid'] = 1
            else:
                features['ssl_cert_valid'] = 0
        except:
            features['ssl_cert_valid'] = 0
        
        features['domain_age_days'] = _get_domain_age_days(url)
        
        return features
        
    def _get_default_features(self):
        """返回默认特征值"""
        return {
            # Kaggle数据集网页特征
            'PctExtHyperlinks': 0.0,
            'PctExtResourceUrls': 0.0,
            'ExtFavicon': 0,
            'InsecureForms': 0,
            'RelativeFormAction': 0,
            'ExtFormAction': 0,
            'AbnormalFormAction': 0,
            'PctNullSelfRedirectHyperlinks': 0.0,
            'FrequentDomainNameMismatch': 0,
            'FakeLinkInStatusBar': 0,
            'RightClickDisabled': 0,
            'PopUpWindow': 0,
            'SubmitInfoToEmail': 0,
            'IframeOrFrame': 0,
            'MissingTitle': 0,
            'ImagesOnlyInForm': 0,
            
            # UCI数据集网页特征
            'Favicon': -1,
            'Request_URL': -1,
            'URL_of_Anchor': 0,
            'Links_in_tags': 0,
            'SFH': 0,
            'Submitting_to_email': 0,
            'Abnormal_URL': -1,
            'Redirect': 0,
            'on_mouseover': -1,
            'RightClick': -1,
            'popUpWidnow': -1,
            'Iframe': -1,
            
            # 保留原有特征（用于兼容性）
            'status_code': 0,
            'content_length': 0,
            'response_time': 0,
            'title_length': 0,
            'meta_count': 0,
            'link_count': 0,
            'image_count': 0,
            'script_count': 0,
            'iframe_count': 0,
            'form_count': 0,
            'input_count': 0,
            'external_links': 0,
            'internal_links': 0,
            'empty_links': 0,
            'body_text_length': 0,
            'link_text_ratio': 0,
            'has_ssl': 0,
            'has_favicon': 0,
            'meta_refresh': 0,
            'popup_count': 0,
            'suspicious_forms': 0,
            'ssl_cert_valid': 0,
            'domain_age_days': 0,
        }


class CombinedFeatureExtractor:
    """
    组合特征提取器 - 多模态融合检测
    融合URL语义分析和网页特征分析
    """
    
    def __init__(self):
        self.url_extractor = URLFeatureExtractor()
        self.web_extractor = WebPageFeatureExtractor()
    
    def extract_all_features(self, url):
        """
        提取所有特征（多模态融合）
        - URL语义分析特征
        - 网页特征分析特征
        返回合并后的特征字典
        """
        # 在线检测时同时看URL本身和网页内容，减少单一特征来源带来的漏判。
        url_features = self.url_extractor.extract_features(url)
        web_features = self.web_extractor.extract_features(url)
        
        # 多模态融合：合并URL和网页特征
        all_features = {**url_features, **web_features}
        
        # 添加融合特征（交叉特征）
        all_features['url_web_risk_score'] = self._calculate_fusion_risk_score(
            url_features, web_features
        )
        
        return all_features
    
    def _calculate_fusion_risk_score(self, url_features, web_features):
        """
        计算多模态融合风险评分
        结合URL语义分析和网页特征分析
        """
        score = 0.0
        
        # URL风险因素
        if url_features.get('has_ip', 0) == 1:
            score += 0.2
        if url_features.get('has_at_symbol', 0) == 1:
            score += 0.15
        if url_features.get('suspicious_keywords', 0) > 1:
            score += 0.15
        if url_features.get('brand_keywords', 0) > 0:
            score += 0.1
        if url_features.get('has_typosquatting', 0) == 1:
            score += 0.2
        
        # 网页风险因素
        if web_features.get('https_used', 0) == 0:
            score += 0.1
        if web_features.get('ssl_cert_valid', 0) == 0:
            score += 0.1
        if web_features.get('iframe_count', 0) > 0:
            score += 0.1
        if web_features.get('suspicious_forms', 0) > 0:
            score += 0.15
        
        # 融合风险：URL可疑 + 网页可疑
        if (url_features.get('suspicious_keywords', 0) > 0 and 
            web_features.get('suspicious_forms', 0) > 0):
            score += 0.2
        
        return min(score, 1.0)


def calculate_phishing_score(features):
    # 规则评分是模型不可用或预测失败时的兜底方案，保证系统始终能给出风险判断。
    score = 0.0
    max_score = 0.0

    if features.get('has_ip', 0) == 1:
        score += 0.2
    max_score += 0.2

    if features.get('has_at_symbol', 0) == 1:
        score += 0.15
    max_score += 0.15

    if features.get('url_length', 0) > 100:
        score += 0.1
    max_score += 0.1

    suspicious_kw = features.get('suspicious_keywords', 0)
    if suspicious_kw > 1:
        score += 0.15
    max_score += 0.15

    if features.get('https_used', 0) == 0:
        score += 0.1
    max_score += 0.1

    if features.get('ssl_cert_valid', 0) == 0:
        score += 0.1
    max_score += 0.1

    iframe_count = features.get('iframe_count', 0)
    if iframe_count > 0:
        score += 0.15
    max_score += 0.15

    popup_count = features.get('popup_count', 0)
    if popup_count > 0:
        score += 0.15
    max_score += 0.15

    form_count = features.get('form_count', 0)
    if form_count > 0:
        score += 0.1
    max_score += 0.1

    suspicious_forms = features.get('suspicious_forms', 0)
    if suspicious_forms > 0:
        score += 0.15
    max_score += 0.15

    script_count = features.get('script_count', 0)
    if script_count > 3:
        score += 0.05
    max_score += 0.05

    if features.get('meta_refresh', 0) == 1:
        score += 0.1
    max_score += 0.1

    if score == 0 and (iframe_count > 0 or popup_count > 0 or form_count > 0):
        score = 0.3
        max_score = 1.0

    return min(score / max_score if max_score > 0 else 0, 1.0)


def _safe_parse_domain(url):
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'https://' + url)
        domain = parsed.netloc.split(':')[0].lower()
        return domain
    except Exception:
        return ''


def _parse_creation_date(raw):
    if raw is None:
        return None
    if isinstance(raw, list) and raw:
        raw = raw[0]
    if isinstance(raw, str):
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(raw, fmt)
            except Exception:
                pass
        return None
    return raw if isinstance(raw, datetime.datetime) else None


def _domain_age_days_from_whois(domain):
    if not whois_lib or not domain:
        return 0
    try:
        data = whois_lib.whois(domain)
        created = _parse_creation_date(getattr(data, 'creation_date', None))
        if not created:
            created = _parse_creation_date(data.get('creation_date') if isinstance(data, dict) else None)
        if not created:
            return 0
        delta = datetime.datetime.utcnow() - (created if created.tzinfo is None else created.astimezone(datetime.timezone.utc).replace(tzinfo=None))
        return max(int(delta.days), 0)
    except Exception:
        return 0


def _get_domain_age_days(url):
    domain = _safe_parse_domain(url)
    try:
        ipaddress.ip_address(domain)
        return 0
    except Exception:
        pass
    return _domain_age_days_from_whois(domain)
