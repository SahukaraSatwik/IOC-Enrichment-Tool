"""
URLhaus API integration service for IOC enrichment
"""
import os
import logging
import aiohttp
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class URLhausService:
    """Service class for URLhaus API integration"""
    
    def __init__(self):
        # URLhaus is a free service that doesn't require API key
        self.base_url = 'https://urlhaus-api.abuse.ch/v1'
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def is_configured(self) -> bool:
        """URLhaus is always available as it's a free service"""
        return True
    
    async def query_url(self, url: str) -> Dict[str, Any]:
        """Query URLhaus for URL information"""
        if not self.session:
            return {
                'error': 'URLhaus session not initialized',
                'source': 'urlhaus',
                'url': url,
                'configured': True
            }
        
        try:
            data = {'url': url}
            
            async with self.session.post(f'{self.base_url}/url/', data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    return self._format_url_response(result, url)
                else:
                    error_text = await response.text()
                    logger.warning(f"URLhaus API error {response.status}: {error_text}")
                    return {
                        'error': f'URLhaus API error {response.status}: {error_text}',
                        'source': 'urlhaus',
                        'url': url,
                        'configured': True
                    }
                    
        except Exception as e:
            logger.error(f"Error querying URLhaus for URL {url}: {e}")
            return {
                'error': f'URLhaus query failed: {str(e)}',
                'source': 'urlhaus',
                'url': url,
                'configured': True
            }
    
    def _format_url_response(self, data: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Format URLhaus URL response"""
        if data.get('query_status') == 'no_results':
            return {
                'source': 'urlhaus',
                'url': url,
                'configured': True,
                'found': False,
                'message': 'URL not found in URLhaus database'
            }
        
        urls = data.get('urls', [])
        if not urls:
            return {
                'source': 'urlhaus',
                'url': url,
                'configured': True,
                'found': False,
                'message': 'No URL data available'
            }
        
        # Get the first URL result
        url_data = urls[0]
        
        return {
            'source': 'urlhaus',
            'url': url,
            'configured': True,
            'found': True,
            'id': url_data.get('id'),
            'urlhaus_link': url_data.get('urlhaus_link'),
            'url_status': url_data.get('url_status'),
            'date_added': url_data.get('date_added'),
            'threat': url_data.get('threat'),
            'blacklists': url_data.get('blacklists', {}),
            'reporter': url_data.get('reporter'),
            'larted': url_data.get('larted'),
            'takedown_time_seconds': url_data.get('takedown_time_seconds'),
            'tags': url_data.get('tags', []),
            'payloads': []
        }
    
    async def query_host(self, host: str) -> Dict[str, Any]:
        """Query URLhaus for host information"""
        if not self.session:
            return {
                'error': 'URLhaus session not initialized',
                'source': 'urlhaus',
                'host': host,
                'configured': True
            }
        
        try:
            data = {'host': host}
            
            async with self.session.post(f'{self.base_url}/host/', data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    return self._format_host_response(result, host)
                else:
                    error_text = await response.text()
                    logger.warning(f"URLhaus host API error {response.status}: {error_text}")
                    return {
                        'error': f'URLhaus host API error {response.status}: {error_text}',
                        'source': 'urlhaus',
                        'host': host,
                        'configured': True
                    }
                    
        except Exception as e:
            logger.error(f"Error querying URLhaus for host {host}: {e}")
            return {
                'error': f'URLhaus host query failed: {str(e)}',
                'source': 'urlhaus',
                'host': host,
                'configured': True
            }
    
    def _format_host_response(self, data: Dict[str, Any], host: str) -> Dict[str, Any]:
        """Format URLhaus host response"""
        if data.get('query_status') == 'no_results':
            return {
                'source': 'urlhaus',
                'host': host,
                'configured': True,
                'found': False,
                'message': 'Host not found in URLhaus database'
            }
        
        return {
            'source': 'urlhaus',
            'host': host,
            'configured': True,
            'found': True,
            'firstseen': data.get('firstseen'),
            'url_count': data.get('url_count', 0),
            'blacklists': data.get('blacklists', {}),
            'urls': data.get('urls', [])[:10]  # Limit to 10 URLs
        }
    
    async def get_ioc_report(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Get IOC report from URLhaus based on IOC type"""
        if ioc_type == 'url':
            return await self.query_url(ioc_value)
        elif ioc_type == 'domain':
            return await self.query_host(ioc_value)
        else:
            return {
                'error': f'URLhaus does not support IOC type: {ioc_type}',
                'source': 'urlhaus',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'configured': self.is_configured()
            }