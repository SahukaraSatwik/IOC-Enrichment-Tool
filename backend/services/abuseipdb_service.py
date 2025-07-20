"""
AbuseIPDB API integration service for IOC enrichment
"""
import os
import logging
import aiohttp
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AbuseIPDBService:
    """Service class for AbuseIPDB API integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('ABUSEIPDB_API_KEY', 'your-abuseipdb-api-key-here')
        self.base_url = 'https://api.abuseipdb.com/api/v2'
        self.session = None
    
    async def __aenter__(self):
        if self.api_key and self.api_key != 'your-abuseipdb-api-key-here':
            self.session = aiohttp.ClientSession(
                headers={
                    'Key': self.api_key,
                    'Accept': 'application/json'
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def is_configured(self) -> bool:
        """Check if AbuseIPDB API is properly configured"""
        return self.api_key and self.api_key != 'your-abuseipdb-api-key-here'
    
    async def check_ip(self, ip_address: str, days: int = 90, verbose: bool = True) -> Dict[str, Any]:
        """Check an IP address in AbuseIPDB"""
        if not self.is_configured():
            return {
                'error': 'AbuseIPDB API key not configured',
                'source': 'abuseipdb',
                'ip': ip_address,
                'configured': False
            }
        
        if not self.session:
            return {
                'error': 'AbuseIPDB session not initialized',
                'source': 'abuseipdb',
                'ip': ip_address,
                'configured': True
            }
        
        try:
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': days,
                'verbose': verbose
            }
            
            async with self.session.get(f'{self.base_url}/check', params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._format_check_response(data.get('data', {}), ip_address)
                else:
                    error_text = await response.text()
                    logger.error(f"AbuseIPDB API error {response.status}: {error_text}")
                    return {
                        'error': f'AbuseIPDB API error {response.status}: {error_text}',
                        'source': 'abuseipdb',
                        'ip': ip_address,
                        'configured': True
                    }
                    
        except aiohttp.ClientError as e:
            logger.error(f"AbuseIPDB client error for {ip_address}: {e}")
            return {
                'error': f'AbuseIPDB client error: {str(e)}',
                'source': 'abuseipdb',
                'ip': ip_address,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB for {ip_address}: {e}")
            return {
                'error': f'AbuseIPDB query failed: {str(e)}',
                'source': 'abuseipdb',
                'ip': ip_address,
                'configured': True
            }
    
    def _format_check_response(self, data: Dict[str, Any], ip_address: str) -> Dict[str, Any]:
        """Format AbuseIPDB check response"""
        return {
            'source': 'abuseipdb',
            'ip': ip_address,
            'configured': True,
            'abuse_confidence': data.get('abuseConfidencePercentage', 0),
            'is_public': data.get('isPublic', False),
            'ip_version': data.get('ipVersion'),
            'is_whitelisted': data.get('isWhitelisted', False),
            'country_code': data.get('countryCode'),
            'country_name': data.get('countryName'),
            'usage_type': data.get('usageType'),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'total_reports': data.get('totalReports', 0),
            'distinct_users': data.get('numDistinctUsers', 0),
            'last_reported': data.get('lastReportedAt'),
            'reports': data.get('reports', [])[:5] if data.get('reports') else []  # Limit to 5 most recent
        }
    
    async def report_ip(self, ip_address: str, categories: list, comment: str) -> Dict[str, Any]:
        """Report an IP address to AbuseIPDB"""
        if not self.is_configured():
            return {
                'error': 'AbuseIPDB API key not configured',
                'source': 'abuseipdb',
                'configured': False
            }
        
        if not self.session:
            return {
                'error': 'AbuseIPDB session not initialized',
                'source': 'abuseipdb',
                'configured': True
            }
        
        try:
            data = {
                'ip': ip_address,
                'categories': ','.join(map(str, categories)),
                'comment': comment
            }
            
            async with self.session.post(f'{self.base_url}/report', data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        'source': 'abuseipdb',
                        'ip': ip_address,
                        'configured': True,
                        'success': True,
                        'message': 'IP reported successfully',
                        'abuse_confidence': result.get('data', {}).get('abuseConfidencePercentage', 0)
                    }
                else:
                    error_text = await response.text()
                    return {
                        'error': f'AbuseIPDB report error {response.status}: {error_text}',
                        'source': 'abuseipdb',
                        'ip': ip_address,
                        'configured': True
                    }
                    
        except Exception as e:
            logger.error(f"Error reporting IP {ip_address} to AbuseIPDB: {e}")
            return {
                'error': f'AbuseIPDB report failed: {str(e)}',
                'source': 'abuseipdb',
                'ip': ip_address,
                'configured': True
            }
    
    async def get_ioc_report(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Get IOC report from AbuseIPDB (primarily for IPs)"""
        if ioc_type == 'ip_address':
            return await self.check_ip(ioc_value)
        else:
            return {
                'error': f'AbuseIPDB does not support IOC type: {ioc_type}',
                'source': 'abuseipdb',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'configured': self.is_configured()
            }