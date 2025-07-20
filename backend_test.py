#!/usr/bin/env python3
"""
Comprehensive Backend Test Suite for IOC Enrichment Tool
Tests multi-source threat intelligence integration functionality
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, List

import aiohttp
import pytest

# Add backend directory to path for imports
sys.path.append('/app/backend')

# Test configuration
BACKEND_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://88a496e0-ce9d-45b5-a6b3-d0612e4d976a.preview.emergentagent.com')
API_BASE = f"{BACKEND_URL}/api"

class IOCEnrichmentTester:
    """Comprehensive test suite for IOC Enrichment Tool backend"""
    
    def __init__(self):
        self.session = None
        self.auth_token = None
        self.test_user_id = None
        self.created_iocs = []
        self.test_results = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'test_details': []
        }
    
    async def __aenter__(self):
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup HTTP session"""
        if self.session:
            await self.session.close()
    
    def log_test_result(self, test_name: str, passed: bool, details: str = "", error: str = ""):
        """Log test result"""
        self.test_results['total_tests'] += 1
        if passed:
            self.test_results['passed_tests'] += 1
            status = "✅ PASS"
        else:
            self.test_results['failed_tests'] += 1
            status = "❌ FAIL"
        
        result = {
            'test_name': test_name,
            'status': status,
            'passed': passed,
            'details': details,
            'error': error,
            'timestamp': datetime.now().isoformat()
        }
        
        self.test_results['test_details'].append(result)
        print(f"{status}: {test_name}")
        if details:
            print(f"   Details: {details}")
        if error:
            print(f"   Error: {error}")
    
    async def test_api_root(self):
        """Test API root endpoint"""
        try:
            async with self.session.get(f"{API_BASE}/") as response:
                if response.status == 200:
                    data = await response.json()
                    expected_sources = ["OpenAI", "VirusTotal", "Shodan", "AbuseIPDB", "AlienVault OTX", "URLhaus"]
                    supported_sources = data.get('supported_sources', [])
                    
                    if all(source in supported_sources for source in expected_sources):
                        self.log_test_result(
                            "API Root Endpoint", 
                            True, 
                            f"All expected TI sources supported: {supported_sources}"
                        )
                    else:
                        self.log_test_result(
                            "API Root Endpoint", 
                            False, 
                            f"Missing TI sources. Expected: {expected_sources}, Got: {supported_sources}"
                        )
                else:
                    self.log_test_result("API Root Endpoint", False, f"HTTP {response.status}")
        except Exception as e:
            self.log_test_result("API Root Endpoint", False, error=str(e))
    
    async def test_threat_intel_status(self):
        """Test threat intelligence status endpoint"""
        try:
            async with self.session.get(f"{API_BASE}/threat-intel/status") as response:
                if response.status == 200:
                    data = await response.json()
                    services = data.get('services', {})
                    expected_services = ['openai', 'virustotal', 'shodan', 'abuseipdb', 'otx', 'urlhaus']
                    
                    missing_services = [svc for svc in expected_services if svc not in services]
                    if not missing_services:
                        configured_count = data.get('configured_services', 0)
                        total_count = data.get('total_services', 0)
                        
                        # URLhaus should always be configured (free service)
                        urlhaus_configured = services.get('urlhaus', {}).get('configured', False)
                        
                        self.log_test_result(
                            "Threat Intelligence Status", 
                            True, 
                            f"All services present. {configured_count}/{total_count} configured. URLhaus: {urlhaus_configured}"
                        )
                    else:
                        self.log_test_result(
                            "Threat Intelligence Status", 
                            False, 
                            f"Missing services: {missing_services}"
                        )
                else:
                    self.log_test_result("Threat Intelligence Status", False, f"HTTP {response.status}")
        except Exception as e:
            self.log_test_result("Threat Intelligence Status", False, error=str(e))
    
    async def test_user_registration(self):
        """Test user registration"""
        try:
            user_data = {
                "username": f"testuser_{int(time.time())}",
                "email": f"test_{int(time.time())}@example.com",
                "password": "SecurePassword123!",
                "role": "analyst"
            }
            
            async with self.session.post(f"{API_BASE}/register", json=user_data) as response:
                if response.status == 200:
                    data = await response.json()
                    self.test_user_id = data.get('id')
                    self.log_test_result(
                        "User Registration", 
                        True, 
                        f"User created with ID: {self.test_user_id}"
                    )
                    return user_data
                else:
                    error_text = await response.text()
                    self.log_test_result("User Registration", False, f"HTTP {response.status}: {error_text}")
                    return None
        except Exception as e:
            self.log_test_result("User Registration", False, error=str(e))
            return None
    
    async def test_user_login(self, user_data: Dict[str, str]):
        """Test user login"""
        if not user_data:
            self.log_test_result("User Login", False, "No user data available")
            return False
        
        try:
            login_data = {
                "username": user_data["username"],
                "password": user_data["password"]
            }
            
            async with self.session.post(f"{API_BASE}/login", json=login_data) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data.get('access_token')
                    self.log_test_result(
                        "User Login", 
                        True, 
                        f"Login successful, token received"
                    )
                    return True
                else:
                    error_text = await response.text()
                    self.log_test_result("User Login", False, f"HTTP {response.status}: {error_text}")
                    return False
        except Exception as e:
            self.log_test_result("User Login", False, error=str(e))
            return False
    
    async def test_protected_endpoint(self):
        """Test protected endpoint access"""
        if not self.auth_token:
            self.log_test_result("Protected Endpoint Access", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.get(f"{API_BASE}/me", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    self.log_test_result(
                        "Protected Endpoint Access", 
                        True, 
                        f"User info retrieved: {data.get('username')}"
                    )
                else:
                    error_text = await response.text()
                    self.log_test_result("Protected Endpoint Access", False, f"HTTP {response.status}: {error_text}")
        except Exception as e:
            self.log_test_result("Protected Endpoint Access", False, error=str(e))
    
    async def test_ioc_creation_ip(self):
        """Test IOC creation for IP address"""
        if not self.auth_token:
            self.log_test_result("IOC Creation (IP)", False, "No auth token available")
            return None
        
        try:
            ioc_data = {
                "ioc_type": "ip_address",
                "ioc_value": "8.8.8.8",
                "description": "Google DNS server for testing",
                "tags": ["dns", "google", "test"]
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(f"{API_BASE}/iocs", json=ioc_data, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    ioc_id = data.get('id')
                    self.created_iocs.append(ioc_id)
                    self.log_test_result(
                        "IOC Creation (IP)", 
                        True, 
                        f"IP IOC created with ID: {ioc_id}"
                    )
                    return ioc_id
                else:
                    error_text = await response.text()
                    self.log_test_result("IOC Creation (IP)", False, f"HTTP {response.status}: {error_text}")
                    return None
        except Exception as e:
            self.log_test_result("IOC Creation (IP)", False, error=str(e))
            return None
    
    async def test_ioc_creation_domain(self):
        """Test IOC creation for domain"""
        if not self.auth_token:
            self.log_test_result("IOC Creation (Domain)", False, "No auth token available")
            return None
        
        try:
            ioc_data = {
                "ioc_type": "domain",
                "ioc_value": "example.com",
                "description": "Example domain for testing",
                "tags": ["domain", "test"]
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(f"{API_BASE}/iocs", json=ioc_data, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    ioc_id = data.get('id')
                    self.created_iocs.append(ioc_id)
                    self.log_test_result(
                        "IOC Creation (Domain)", 
                        True, 
                        f"Domain IOC created with ID: {ioc_id}"
                    )
                    return ioc_id
                else:
                    error_text = await response.text()
                    self.log_test_result("IOC Creation (Domain)", False, f"HTTP {response.status}: {error_text}")
                    return None
        except Exception as e:
            self.log_test_result("IOC Creation (Domain)", False, error=str(e))
            return None
    
    async def test_ioc_creation_hash(self):
        """Test IOC creation for file hash"""
        if not self.auth_token:
            self.log_test_result("IOC Creation (Hash)", False, "No auth token available")
            return None
        
        try:
            ioc_data = {
                "ioc_type": "file_hash",
                "ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
                "hash_type": "md5",
                "description": "Empty file MD5 hash for testing",
                "tags": ["hash", "md5", "test"]
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(f"{API_BASE}/iocs", json=ioc_data, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    ioc_id = data.get('id')
                    self.created_iocs.append(ioc_id)
                    self.log_test_result(
                        "IOC Creation (Hash)", 
                        True, 
                        f"Hash IOC created with ID: {ioc_id}"
                    )
                    return ioc_id
                else:
                    error_text = await response.text()
                    self.log_test_result("IOC Creation (Hash)", False, f"HTTP {response.status}: {error_text}")
                    return None
        except Exception as e:
            self.log_test_result("IOC Creation (Hash)", False, error=str(e))
            return None
    
    async def test_ioc_creation_url(self):
        """Test IOC creation for URL"""
        if not self.auth_token:
            self.log_test_result("IOC Creation (URL)", False, "No auth token available")
            return None
        
        try:
            ioc_data = {
                "ioc_type": "url",
                "ioc_value": "https://example.com/test",
                "description": "Example URL for testing",
                "tags": ["url", "test"]
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(f"{API_BASE}/iocs", json=ioc_data, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    ioc_id = data.get('id')
                    self.created_iocs.append(ioc_id)
                    self.log_test_result(
                        "IOC Creation (URL)", 
                        True, 
                        f"URL IOC created with ID: {ioc_id}"
                    )
                    return ioc_id
                else:
                    error_text = await response.text()
                    self.log_test_result("IOC Creation (URL)", False, f"HTTP {response.status}: {error_text}")
                    return None
        except Exception as e:
            self.log_test_result("IOC Creation (URL)", False, error=str(e))
            return None
    
    async def test_batch_ioc_creation(self):
        """Test batch IOC creation"""
        if not self.auth_token:
            self.log_test_result("Batch IOC Creation", False, "No auth token available")
            return
        
        try:
            batch_data = {
                "iocs": [
                    {
                        "ioc_type": "ip_address",
                        "ioc_value": "1.1.1.1",
                        "description": "Cloudflare DNS",
                        "tags": ["dns", "cloudflare"]
                    },
                    {
                        "ioc_type": "domain",
                        "ioc_value": "cloudflare.com",
                        "description": "Cloudflare domain",
                        "tags": ["domain", "cloudflare"]
                    }
                ]
            }
            
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.post(f"{API_BASE}/iocs/batch", json=batch_data, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    batch_ids = [ioc.get('id') for ioc in data]
                    self.created_iocs.extend(batch_ids)
                    self.log_test_result(
                        "Batch IOC Creation", 
                        True, 
                        f"Batch created {len(batch_ids)} IOCs"
                    )
                else:
                    error_text = await response.text()
                    self.log_test_result("Batch IOC Creation", False, f"HTTP {response.status}: {error_text}")
        except Exception as e:
            self.log_test_result("Batch IOC Creation", False, error=str(e))
    
    async def test_ioc_analysis_workflow(self, ioc_id: str, ioc_type: str):
        """Test IOC analysis workflow with multi-source integration"""
        if not self.auth_token or not ioc_id:
            self.log_test_result(f"IOC Analysis Workflow ({ioc_type})", False, "No auth token or IOC ID")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            # Wait for analysis to complete (up to 60 seconds)
            max_attempts = 12
            attempt = 0
            analysis_completed = False
            
            while attempt < max_attempts and not analysis_completed:
                await asyncio.sleep(5)  # Wait 5 seconds between checks
                
                async with self.session.get(f"{API_BASE}/iocs/{ioc_id}", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        status = data.get('status')
                        
                        if status == 'completed':
                            analysis_completed = True
                            analysis_result = data.get('analysis_result')
                            
                            if analysis_result:
                                # Check for multi-source data
                                sources_used = analysis_result.get('analysis_sources', [])
                                has_multi_source = len(sources_used) > 1
                                
                                # Check for threat intelligence results
                                ti_results = {
                                    'virustotal': analysis_result.get('virustotal_results'),
                                    'shodan': analysis_result.get('shodan_results'),
                                    'abuseipdb': analysis_result.get('abuseipdb_results'),
                                    'otx': analysis_result.get('otx_results'),
                                    'urlhaus': analysis_result.get('urlhaus_results')
                                }
                                
                                ti_sources_with_data = [k for k, v in ti_results.items() if v and not v.get('error')]
                                
                                self.log_test_result(
                                    f"IOC Analysis Workflow ({ioc_type})", 
                                    True, 
                                    f"Analysis completed. Sources: {sources_used}. TI data from: {ti_sources_with_data}"
                                )
                            else:
                                self.log_test_result(f"IOC Analysis Workflow ({ioc_type})", False, "No analysis result")
                        elif status == 'failed':
                            self.log_test_result(f"IOC Analysis Workflow ({ioc_type})", False, "Analysis failed")
                            break
                        
                        attempt += 1
                    else:
                        self.log_test_result(f"IOC Analysis Workflow ({ioc_type})", False, f"HTTP {response.status}")
                        break
            
            if not analysis_completed and attempt >= max_attempts:
                self.log_test_result(f"IOC Analysis Workflow ({ioc_type})", False, "Analysis timeout")
                
        except Exception as e:
            self.log_test_result(f"IOC Analysis Workflow ({ioc_type})", False, error=str(e))
    
    async def test_ioc_retrieval(self):
        """Test IOC retrieval"""
        if not self.auth_token:
            self.log_test_result("IOC Retrieval", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.get(f"{API_BASE}/iocs", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    ioc_count = len(data)
                    self.log_test_result(
                        "IOC Retrieval", 
                        True, 
                        f"Retrieved {ioc_count} IOCs"
                    )
                else:
                    error_text = await response.text()
                    self.log_test_result("IOC Retrieval", False, f"HTTP {response.status}: {error_text}")
        except Exception as e:
            self.log_test_result("IOC Retrieval", False, error=str(e))
    
    async def test_statistics_endpoint(self):
        """Test enhanced statistics with multi-source tracking"""
        if not self.auth_token:
            self.log_test_result("Statistics Endpoint", False, "No auth token available")
            return
        
        try:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            async with self.session.get(f"{API_BASE}/stats", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Check for expected statistics fields
                    expected_fields = ['total_iocs', 'pending_analyses', 'processing_analyses', 
                                     'completed_analyses', 'failed_analyses', 'multi_source_enhanced']
                    
                    missing_fields = [field for field in expected_fields if field not in data]
                    
                    if not missing_fields:
                        multi_source_count = data.get('multi_source_enhanced', 0)
                        total_completed = data.get('completed_analyses', 0)
                        
                        self.log_test_result(
                            "Statistics Endpoint", 
                            True, 
                            f"All stats fields present. Multi-source enhanced: {multi_source_count}/{total_completed}"
                        )
                    else:
                        self.log_test_result(
                            "Statistics Endpoint", 
                            False, 
                            f"Missing fields: {missing_fields}"
                        )
                else:
                    error_text = await response.text()
                    self.log_test_result("Statistics Endpoint", False, f"HTTP {response.status}: {error_text}")
        except Exception as e:
            self.log_test_result("Statistics Endpoint", False, error=str(e))
    
    async def test_ioc_validation(self):
        """Test IOC validation for different types"""
        if not self.auth_token:
            self.log_test_result("IOC Validation", False, "No auth token available")
            return
        
        test_cases = [
            # Valid cases
            {"ioc_type": "ip_address", "ioc_value": "192.168.1.1", "should_pass": True},
            {"ioc_type": "domain", "ioc_value": "test.example.com", "should_pass": True},
            {"ioc_type": "email", "ioc_value": "test@example.com", "should_pass": True},
            {"ioc_type": "url", "ioc_value": "https://example.com/path", "should_pass": True},
            {"ioc_type": "file_hash", "ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "hash_type": "md5", "should_pass": True},
            
            # Invalid cases
            {"ioc_type": "ip_address", "ioc_value": "999.999.999.999", "should_pass": False},
            {"ioc_type": "domain", "ioc_value": "invalid..domain", "should_pass": False},
            {"ioc_type": "email", "ioc_value": "invalid-email", "should_pass": False},
            {"ioc_type": "url", "ioc_value": "not-a-url", "should_pass": False},
            {"ioc_type": "file_hash", "ioc_value": "invalid-hash", "hash_type": "md5", "should_pass": False}
        ]
        
        passed_validations = 0
        total_validations = len(test_cases)
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        for test_case in test_cases:
            try:
                ioc_data = {
                    "ioc_type": test_case["ioc_type"],
                    "ioc_value": test_case["ioc_value"],
                    "description": f"Validation test for {test_case['ioc_type']}"
                }
                
                if "hash_type" in test_case:
                    ioc_data["hash_type"] = test_case["hash_type"]
                
                async with self.session.post(f"{API_BASE}/iocs", json=ioc_data, headers=headers) as response:
                    success = response.status == 200
                    expected_success = test_case["should_pass"]
                    
                    if success == expected_success:
                        passed_validations += 1
                        if success:
                            # Clean up created IOC
                            data = await response.json()
                            self.created_iocs.append(data.get('id'))
                    
            except Exception:
                # Validation errors are expected for invalid cases
                if not test_case["should_pass"]:
                    passed_validations += 1
        
        self.log_test_result(
            "IOC Validation", 
            passed_validations == total_validations, 
            f"Passed {passed_validations}/{total_validations} validation tests"
        )
    
    async def cleanup_test_data(self):
        """Clean up created test data"""
        if not self.auth_token or not self.created_iocs:
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        cleaned_count = 0
        
        for ioc_id in self.created_iocs:
            try:
                async with self.session.delete(f"{API_BASE}/iocs/{ioc_id}", headers=headers) as response:
                    if response.status == 200:
                        cleaned_count += 1
            except Exception:
                pass  # Ignore cleanup errors
        
        print(f"Cleaned up {cleaned_count}/{len(self.created_iocs)} test IOCs")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("IOC ENRICHMENT TOOL - BACKEND TEST SUMMARY")
        print("="*80)
        print(f"Total Tests: {self.test_results['total_tests']}")
        print(f"Passed: {self.test_results['passed_tests']}")
        print(f"Failed: {self.test_results['failed_tests']}")
        print(f"Success Rate: {(self.test_results['passed_tests']/self.test_results['total_tests']*100):.1f}%")
        print("="*80)
        
        # Print failed tests
        failed_tests = [t for t in self.test_results['test_details'] if not t['passed']]
        if failed_tests:
            print("\nFAILED TESTS:")
            for test in failed_tests:
                print(f"❌ {test['test_name']}")
                if test['error']:
                    print(f"   Error: {test['error']}")
                if test['details']:
                    print(f"   Details: {test['details']}")
        
        print("\n" + "="*80)

async def run_comprehensive_tests():
    """Run comprehensive backend tests"""
    print("Starting IOC Enrichment Tool Backend Tests...")
    print(f"Testing against: {API_BASE}")
    print("="*80)
    
    async with IOCEnrichmentTester() as tester:
        # Core API tests
        await tester.test_api_root()
        await tester.test_threat_intel_status()
        
        # Authentication tests
        user_data = await tester.test_user_registration()
        login_success = await tester.test_user_login(user_data)
        
        if login_success:
            await tester.test_protected_endpoint()
            
            # IOC validation tests
            await tester.test_ioc_validation()
            
            # IOC creation tests
            ip_ioc_id = await tester.test_ioc_creation_ip()
            domain_ioc_id = await tester.test_ioc_creation_domain()
            hash_ioc_id = await tester.test_ioc_creation_hash()
            url_ioc_id = await tester.test_ioc_creation_url()
            
            # Batch creation test
            await tester.test_batch_ioc_creation()
            
            # IOC retrieval test
            await tester.test_ioc_retrieval()
            
            # Statistics test
            await tester.test_statistics_endpoint()
            
            # Analysis workflow tests (these take time)
            if ip_ioc_id:
                await tester.test_ioc_analysis_workflow(ip_ioc_id, "IP")
            if domain_ioc_id:
                await tester.test_ioc_analysis_workflow(domain_ioc_id, "Domain")
            if hash_ioc_id:
                await tester.test_ioc_analysis_workflow(hash_ioc_id, "Hash")
            if url_ioc_id:
                await tester.test_ioc_analysis_workflow(url_ioc_id, "URL")
            
            # Cleanup
            await tester.cleanup_test_data()
        
        # Print summary
        tester.print_summary()
        
        return tester.test_results

if __name__ == "__main__":
    # Run the tests
    results = asyncio.run(run_comprehensive_tests())
    
    # Exit with appropriate code
    if results['failed_tests'] > 0:
        sys.exit(1)
    else:
        sys.exit(0)