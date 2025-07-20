"""
VirusTotal API integration service for IOC enrichment
"""
import os
import logging
import aiohttp
import base64
from typing import Dict, Any, Optional
import vt

logger = logging.getLogger(__name__)

class VirusTotalService:
    """Service class for VirusTotal API integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('VIRUSTOTAL_API_KEY', 'your-virustotal-api-key-here')
        self.client = None
        if self.api_key and self.api_key != 'your-virustotal-api-key-here':
            try:
                self.client = vt.Client(self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize VirusTotal client: {e}")
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.close()
    
    def is_configured(self) -> bool:
        """Check if VirusTotal API is properly configured"""
        return self.client is not None
    
    async def get_ip_report(self, ip_address: str) -> Dict[str, Any]:
        """Get IP address report from VirusTotal"""
        if not self.is_configured():
            return {
                'error': 'VirusTotal API key not configured',
                'source': 'virustotal',
                'ip': ip_address,
                'configured': False
            }
        
        try:
            ip_obj = await self.client.get_object_async(f"/ip_addresses/{ip_address}")
            
            # Extract analysis stats
            stats = ip_obj.get('last_analysis_stats', {})
            
            result = {
                'source': 'virustotal',
                'ip': ip_address,
                'configured': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'reputation': ip_obj.get('reputation', 0),
                'country': ip_obj.get('country'),
                'as_owner': ip_obj.get('as_owner'),
                'network': ip_obj.get('network'),
                'last_analysis_date': ip_obj.get('last_analysis_date'),
                'last_modification_date': ip_obj.get('last_modification_date'),
                'whois': ip_obj.get('whois'),
                'detected_urls': []
            }
            
            # Get detected URLs (limit to 5)
            detected_urls = ip_obj.get('detected_urls', [])
            for url_info in detected_urls[:5]:
                result['detected_urls'].append({
                    'url': url_info.get('url'),
                    'positives': url_info.get('positives', 0),
                    'total': url_info.get('total', 0),
                    'scan_date': url_info.get('scan_date')
                })
            
            return result
            
        except vt.APIError as e:
            logger.warning(f"VirusTotal API error for IP {ip_address}: {e}")
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'source': 'virustotal',
                'ip': ip_address,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error querying VirusTotal for IP {ip_address}: {e}")
            return {
                'error': f'VirusTotal IP query failed: {str(e)}',
                'source': 'virustotal',
                'ip': ip_address,
                'configured': True
            }
    
    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get domain report from VirusTotal"""
        if not self.is_configured():
            return {
                'error': 'VirusTotal API key not configured',
                'source': 'virustotal',
                'domain': domain,
                'configured': False
            }
        
        try:
            domain_obj = await self.client.get_object_async(f"/domains/{domain}")
            
            # Extract analysis stats
            stats = domain_obj.get('last_analysis_stats', {})
            
            result = {
                'source': 'virustotal',
                'domain': domain,
                'configured': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'reputation': domain_obj.get('reputation', 0),
                'creation_date': domain_obj.get('creation_date'),
                'last_update_date': domain_obj.get('last_update_date'),
                'registrar': domain_obj.get('registrar'),
                'whois': domain_obj.get('whois'),
                'categories': domain_obj.get('categories', {}),
                'detected_urls': []
            }
            
            # Get detected URLs (limit to 5)
            detected_urls = domain_obj.get('detected_urls', [])
            for url_info in detected_urls[:5]:
                result['detected_urls'].append({
                    'url': url_info.get('url'),
                    'positives': url_info.get('positives', 0),
                    'total': url_info.get('total', 0),
                    'scan_date': url_info.get('scan_date')
                })
            
            return result
            
        except vt.APIError as e:
            logger.warning(f"VirusTotal API error for domain {domain}: {e}")
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'source': 'virustotal',
                'domain': domain,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error querying VirusTotal for domain {domain}: {e}")
            return {
                'error': f'VirusTotal domain query failed: {str(e)}',
                'source': 'virustotal',
                'domain': domain,
                'configured': True
            }
    
    async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get file hash report from VirusTotal"""
        if not self.is_configured():
            return {
                'error': 'VirusTotal API key not configured',
                'source': 'virustotal',
                'hash': file_hash,
                'configured': False
            }
        
        try:
            file_obj = await self.client.get_object_async(f"/files/{file_hash}")
            
            # Extract analysis stats
            stats = file_obj.get('last_analysis_stats', {})
            
            result = {
                'source': 'virustotal',
                'hash': file_hash,
                'configured': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'type_unsupported': stats.get('type-unsupported', 0),
                'failure': stats.get('failure', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'md5': file_obj.get('md5'),
                'sha1': file_obj.get('sha1'),
                'sha256': file_obj.get('sha256'),
                'file_type': file_obj.get('type_description'),
                'file_size': file_obj.get('size'),
                'first_submission_date': file_obj.get('first_submission_date'),
                'last_analysis_date': file_obj.get('last_analysis_date'),
                'file_names': file_obj.get('names', [])[:5],  # Limit to 5 names
                'magic': file_obj.get('magic'),
                'signature_info': file_obj.get('signature_info', {}),
                'pe_info': file_obj.get('pe_info', {}),
                'detections': {}
            }
            
            # Extract detection results (limit to engines that detected it)
            last_analysis_results = file_obj.get('last_analysis_results', {})
            for engine, detection in last_analysis_results.items():
                if detection.get('result') and detection.get('category') in ['malicious', 'suspicious']:
                    result['detections'][engine] = {
                        'result': detection.get('result'),
                        'category': detection.get('category'),
                        'engine_version': detection.get('engine_version'),
                        'engine_update': detection.get('engine_update')
                    }
                    # Limit detections to prevent response from being too large
                    if len(result['detections']) >= 20:
                        break
            
            return result
            
        except vt.APIError as e:
            logger.warning(f"VirusTotal API error for hash {file_hash}: {e}")
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'source': 'virustotal',
                'hash': file_hash,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error querying VirusTotal for hash {file_hash}: {e}")
            return {
                'error': f'VirusTotal hash query failed: {str(e)}',
                'source': 'virustotal',
                'hash': file_hash,
                'configured': True
            }
    
    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL report from VirusTotal"""
        if not self.is_configured():
            return {
                'error': 'VirusTotal API key not configured',
                'source': 'virustotal',
                'url': url,
                'configured': False
            }
        
        try:
            # VirusTotal requires URL to be base64 encoded for the API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            url_obj = await self.client.get_object_async(f"/urls/{url_id}")
            
            # Extract analysis stats
            stats = url_obj.get('last_analysis_stats', {})
            
            result = {
                'source': 'virustotal',
                'url': url,
                'configured': True,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'total_vendors': sum(stats.values()) if stats else 0,
                'first_submission_date': url_obj.get('first_submission_date'),
                'last_analysis_date': url_obj.get('last_analysis_date'),
                'last_final_url': url_obj.get('last_final_url'),
                'redirect_chain': url_obj.get('redirection_chain', []),
                'categories': url_obj.get('categories', {}),
                'detections': {}
            }
            
            # Extract detection results (limit to engines that detected it)
            last_analysis_results = url_obj.get('last_analysis_results', {})
            for engine, detection in last_analysis_results.items():
                if detection.get('result') and detection.get('category') in ['malicious', 'suspicious']:
                    result['detections'][engine] = {
                        'result': detection.get('result'),
                        'category': detection.get('category'),
                        'engine_name': detection.get('engine_name'),
                        'method': detection.get('method')
                    }
                    # Limit detections to prevent response from being too large
                    if len(result['detections']) >= 20:
                        break
            
            return result
            
        except vt.APIError as e:
            logger.warning(f"VirusTotal API error for URL {url}: {e}")
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'source': 'virustotal',
                'url': url,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error querying VirusTotal for URL {url}: {e}")
            return {
                'error': f'VirusTotal URL query failed: {str(e)}',
                'source': 'virustotal',
                'url': url,
                'configured': True
            }
    
    async def get_ioc_report(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Get IOC report from VirusTotal based on IOC type"""
        if ioc_type == 'ip_address':
            return await self.get_ip_report(ioc_value)
        elif ioc_type == 'domain':
            return await self.get_domain_report(ioc_value)
        elif ioc_type == 'file_hash':
            return await self.get_file_report(ioc_value)
        elif ioc_type == 'url':
            return await self.get_url_report(ioc_value)
        else:
            return {
                'error': f'VirusTotal does not support IOC type: {ioc_type}',
                'source': 'virustotal',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'configured': self.is_configured()
            }