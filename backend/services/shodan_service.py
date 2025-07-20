"""
Shodan API integration service for IOC enrichment
"""
import os
import logging
import asyncio
from typing import Dict, Any, Optional
import shodan
import aiohttp

logger = logging.getLogger(__name__)

class ShodanService:
    """Service class for Shodan API integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('SHODAN_API_KEY', 'your-shodan-api-key-here')
        self.client = None
        if self.api_key and self.api_key != 'your-shodan-api-key-here':
            try:
                self.client = shodan.Shodan(self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize Shodan client: {e}")
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            # Shodan client doesn't need explicit cleanup
            pass
    
    def is_configured(self) -> bool:
        """Check if Shodan API is properly configured"""
        return self.client is not None
    
    async def get_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """Get information about an IP address from Shodan"""
        if not self.is_configured():
            return {
                'error': 'Shodan API key not configured',
                'source': 'shodan',
                'ip': ip_address,
                'configured': False
            }
        
        try:
            # Run synchronous Shodan API in thread pool
            loop = asyncio.get_event_loop()
            host_info = await loop.run_in_executor(None, self.client.host, ip_address)
            
            # Extract relevant information
            result = {
                'source': 'shodan',
                'ip': ip_address,
                'configured': True,
                'country': host_info.get('country_name'),
                'country_code': host_info.get('country_code'),
                'city': host_info.get('city'),
                'organization': host_info.get('org'),
                'isp': host_info.get('isp'),
                'ports': host_info.get('ports', []),
                'hostnames': host_info.get('hostnames', []),
                'operating_system': host_info.get('os'),
                'asn': host_info.get('asn'),
                'last_update': host_info.get('last_update'),
                'vulnerabilities': host_info.get('vulns', []),
                'services': []
            }
            
            # Extract service information
            for service in host_info.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'protocol': service.get('transport', 'tcp'),
                    'service': service.get('product'),
                    'version': service.get('version'),
                    'banner': service.get('banner', '')[:200] if service.get('banner') else None  # Truncate banner
                }
                result['services'].append(service_info)
            
            return result
            
        except shodan.APIError as e:
            logger.warning(f"Shodan API error for {ip_address}: {e}")
            return {
                'error': f'Shodan API error: {str(e)}',
                'source': 'shodan',
                'ip': ip_address,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error querying Shodan for {ip_address}: {e}")
            return {
                'error': f'Shodan query failed: {str(e)}',
                'source': 'shodan',
                'ip': ip_address,
                'configured': True
            }
    
    async def search_query(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """Search Shodan with a custom query"""
        if not self.is_configured():
            return {
                'error': 'Shodan API key not configured',
                'source': 'shodan',
                'query': query,
                'configured': False
            }
        
        try:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(None, lambda: self.client.search(query, limit=limit))
            
            return {
                'source': 'shodan',
                'query': query,
                'configured': True,
                'total': results['total'],
                'matches': len(results['matches']),
                'results': [
                    {
                        'ip': match.get('ip_str'),
                        'port': match.get('port'),
                        'organization': match.get('org'),
                        'country': match.get('location', {}).get('country_name'),
                        'city': match.get('location', {}).get('city'),
                        'service': match.get('product'),
                        'timestamp': match.get('timestamp')
                    }
                    for match in results['matches'][:10]  # Limit to first 10 for performance
                ]
            }
            
        except shodan.APIError as e:
            logger.warning(f"Shodan search API error for query '{query}': {e}")
            return {
                'error': f'Shodan search API error: {str(e)}',
                'source': 'shodan',
                'query': query,
                'configured': True
            }
        except Exception as e:
            logger.error(f"Error in Shodan search for query '{query}': {e}")
            return {
                'error': f'Shodan search failed: {str(e)}',
                'source': 'shodan',
                'query': query,
                'configured': True
            }
    
    async def get_ioc_report(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Get IOC report from Shodan (primarily for IPs)"""
        if ioc_type == 'ip_address':
            return await self.get_ip_info(ioc_value)
        elif ioc_type == 'domain':
            # Search for domain in Shodan
            return await self.search_query(f'hostname:{ioc_value}')
        else:
            return {
                'error': f'Shodan does not support IOC type: {ioc_type}',
                'source': 'shodan',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'configured': self.is_configured()
            }