"""
AlienVault OTX (Open Threat Exchange) API integration service for IOC enrichment
"""
import os
import logging
import asyncio
from typing import Dict, Any, Optional
from OTXv2 import OTXv2

logger = logging.getLogger(__name__)

class OTXService:
    """Service class for AlienVault OTX API integration"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('OTX_API_KEY', 'your-otx-api-key-here')
        self.client = None
        if self.api_key and self.api_key != 'your-otx-api-key-here':
            try:
                self.client = OTXv2(self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize OTX client: {e}")
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # OTX client doesn't need explicit cleanup
        pass
    
    def is_configured(self) -> bool:
        """Check if OTX API is properly configured"""
        return self.client is not None
    
    async def get_ip_info(self, ip_address: str) -> Dict[str, Any]:
        """Get information about an IP address from OTX"""
        if not self.is_configured():
            return {
                'error': 'OTX API key not configured',
                'source': 'otx',
                'ip': ip_address,
                'configured': False
            }
        
        try:
            # Run synchronous OTX API in thread pool
            loop = asyncio.get_event_loop()
            
            # Get various IP indicators
            general = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'IPv4', ip_address, 'general'
            ))
            
            reputation = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'IPv4', ip_address, 'reputation'
            ))
            
            geo = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'IPv4', ip_address, 'geo'
            ))
            
            malware = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'IPv4', ip_address, 'malware'
            ))
            
            # Format response
            result = {
                'source': 'otx',
                'ip': ip_address,
                'configured': True,
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'pulses': [],
                'reputation': {
                    'threat_score': reputation.get('reputation', {}).get('threat_score', 0),
                    'first_seen': reputation.get('reputation', {}).get('first_seen'),
                    'last_seen': reputation.get('reputation', {}).get('last_seen'),
                },
                'geolocation': {
                    'country': geo.get('country_name'),
                    'country_code': geo.get('country_code'),
                    'city': geo.get('city'),
                    'region': geo.get('region'),
                    'continent': geo.get('continent_code'),
                    'latitude': geo.get('latitude'),
                    'longitude': geo.get('longitude'),
                    'asn': geo.get('asn'),
                },
                'malware_families': []
            }
            
            # Extract pulse information
            for pulse in general.get('pulse_info', {}).get('pulses', [])[:5]:  # Limit to 5 most recent
                pulse_info = {
                    'id': pulse.get('id'),
                    'name': pulse.get('name'),
                    'description': pulse.get('description', '')[:200] if pulse.get('description') else None,
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'author_name': pulse.get('author_name'),
                    'tags': pulse.get('tags', []),
                    'malware_families': pulse.get('malware_families', []),
                    'targeted_countries': pulse.get('targeted_countries', [])
                }
                result['pulses'].append(pulse_info)
            
            # Extract malware families
            for malware_family in malware.get('data', []):
                result['malware_families'].append({
                    'family': malware_family.get('detections', {}).get('family'),
                    'first_seen': malware_family.get('datetime_int'),
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Error querying OTX for {ip_address}: {e}")
            return {
                'error': f'OTX query failed: {str(e)}',
                'source': 'otx',
                'ip': ip_address,
                'configured': True
            }
    
    async def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get information about a domain from OTX"""
        if not self.is_configured():
            return {
                'error': 'OTX API key not configured',
                'source': 'otx',
                'domain': domain,
                'configured': False
            }
        
        try:
            loop = asyncio.get_event_loop()
            
            # Get domain indicators
            general = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'domain', domain, 'general'
            ))
            
            whois = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'domain', domain, 'whois'
            ))
            
            # Format response
            result = {
                'source': 'otx',
                'domain': domain,
                'configured': True,
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'pulses': [],
                'whois': whois,
            }
            
            # Extract pulse information
            for pulse in general.get('pulse_info', {}).get('pulses', [])[:5]:  # Limit to 5 most recent
                pulse_info = {
                    'id': pulse.get('id'),
                    'name': pulse.get('name'),
                    'description': pulse.get('description', '')[:200] if pulse.get('description') else None,
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'author_name': pulse.get('author_name'),
                    'tags': pulse.get('tags', []),
                    'malware_families': pulse.get('malware_families', []),
                    'targeted_countries': pulse.get('targeted_countries', [])
                }
                result['pulses'].append(pulse_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error querying OTX for domain {domain}: {e}")
            return {
                'error': f'OTX domain query failed: {str(e)}',
                'source': 'otx',
                'domain': domain,
                'configured': True
            }
    
    async def get_hash_info(self, file_hash: str) -> Dict[str, Any]:
        """Get information about a file hash from OTX"""
        if not self.is_configured():
            return {
                'error': 'OTX API key not configured',
                'source': 'otx',
                'hash': file_hash,
                'configured': False
            }
        
        try:
            loop = asyncio.get_event_loop()
            
            # Determine hash type
            hash_type = 'file'
            if len(file_hash) == 32:
                hash_type = 'file'  # MD5
            elif len(file_hash) == 40:
                hash_type = 'file'  # SHA1
            elif len(file_hash) == 64:
                hash_type = 'file'  # SHA256
            
            # Get hash indicators
            general = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                hash_type, file_hash, 'general'
            ))
            
            analysis = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                hash_type, file_hash, 'analysis'
            ))
            
            # Format response
            result = {
                'source': 'otx',
                'hash': file_hash,
                'configured': True,
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'pulses': [],
                'analysis': analysis,
            }
            
            # Extract pulse information
            for pulse in general.get('pulse_info', {}).get('pulses', [])[:5]:  # Limit to 5 most recent
                pulse_info = {
                    'id': pulse.get('id'),
                    'name': pulse.get('name'),
                    'description': pulse.get('description', '')[:200] if pulse.get('description') else None,
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'author_name': pulse.get('author_name'),
                    'tags': pulse.get('tags', []),
                    'malware_families': pulse.get('malware_families', []),
                    'targeted_countries': pulse.get('targeted_countries', [])
                }
                result['pulses'].append(pulse_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error querying OTX for hash {file_hash}: {e}")
            return {
                'error': f'OTX hash query failed: {str(e)}',
                'source': 'otx',
                'hash': file_hash,
                'configured': True
            }
    
    async def get_url_info(self, url: str) -> Dict[str, Any]:
        """Get information about a URL from OTX"""
        if not self.is_configured():
            return {
                'error': 'OTX API key not configured',
                'source': 'otx',
                'url': url,
                'configured': False
            }
        
        try:
            loop = asyncio.get_event_loop()
            
            # Get URL indicators
            general = await loop.run_in_executor(None, lambda: self.client.get_indicator_details_by_section(
                'url', url, 'general'
            ))
            
            # Format response
            result = {
                'source': 'otx',
                'url': url,
                'configured': True,
                'pulse_count': general.get('pulse_info', {}).get('count', 0),
                'pulses': []
            }
            
            # Extract pulse information
            for pulse in general.get('pulse_info', {}).get('pulses', [])[:5]:  # Limit to 5 most recent
                pulse_info = {
                    'id': pulse.get('id'),
                    'name': pulse.get('name'),
                    'description': pulse.get('description', '')[:200] if pulse.get('description') else None,
                    'created': pulse.get('created'),
                    'modified': pulse.get('modified'),
                    'author_name': pulse.get('author_name'),
                    'tags': pulse.get('tags', []),
                    'malware_families': pulse.get('malware_families', []),
                    'targeted_countries': pulse.get('targeted_countries', [])
                }
                result['pulses'].append(pulse_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error querying OTX for URL {url}: {e}")
            return {
                'error': f'OTX URL query failed: {str(e)}',
                'source': 'otx',
                'url': url,
                'configured': True
            }
    
    async def get_ioc_report(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Get IOC report from OTX based on IOC type"""
        if ioc_type == 'ip_address':
            return await self.get_ip_info(ioc_value)
        elif ioc_type == 'domain':
            return await self.get_domain_info(ioc_value)
        elif ioc_type == 'file_hash':
            return await self.get_hash_info(ioc_value)
        elif ioc_type == 'url':
            return await self.get_url_info(ioc_value)
        else:
            return {
                'error': f'OTX does not support IOC type: {ioc_type}',
                'source': 'otx',
                'ioc_type': ioc_type,
                'ioc_value': ioc_value,
                'configured': self.is_configured()
            }