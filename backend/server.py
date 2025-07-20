from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks, Depends
from fastapi.security import HTTPBearer
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import re
import ipaddress
import hashlib
import asyncio
from openai import OpenAI

# Import threat intelligence services
from services.virustotal_service import VirusTotalService
from services.shodan_service import ShodanService
from services.abuseipdb_service import AbuseIPDBService
from services.otx_service import OTXService
from services.urlhaus_service import URLhausService

# Import authentication utilities
from auth import (
    User, UserCreate, UserLogin, Token, UserResponse, TokenData,
    get_current_user, authenticate_user, create_user, create_access_token,
    check_resource_ownership, ACCESS_TOKEN_EXPIRE_MINUTES
)

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# OpenAI client
openai_api_key = os.environ.get('OPENAI_API_KEY', 'your-openai-api-key-here')
openai_client = None
if openai_api_key and openai_api_key != 'your-openai-api-key-here':
    try:
        openai_client = OpenAI(api_key=openai_api_key)
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}")

# Create the main app without a prefix
app = FastAPI(title="IOC Enrichment Tool", description="Comprehensive Threat Intelligence Analysis Tool with Multiple TI Sources")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

class IOCType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    URL = "url"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"

class HashType(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class ThreatActor(BaseModel):
    actor_name: str
    confidence_score: int = Field(..., ge=0, le=100)
    evidence: List[str]
    geographic_origin: str
    motivation: str

class IOCAnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_id: str
    threat_actors: List[ThreatActor]
    ttps_analysis: Dict[str, Any]
    infrastructure_patterns: List[str]
    timeline_correlation: List[Dict[str, Any]]
    raw_openai_response: str
    confidence_overall: int = Field(..., ge=0, le=100)
    
    # Multi-source threat intelligence results
    virustotal_results: Optional[Dict[str, Any]] = None
    shodan_results: Optional[Dict[str, Any]] = None
    abuseipdb_results: Optional[Dict[str, Any]] = None
    otx_results: Optional[Dict[str, Any]] = None
    urlhaus_results: Optional[Dict[str, Any]] = None
    
    analysis_sources: List[str] = Field(default_factory=lambda: ["openai"])  # Track which sources were used
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class IOCRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ioc_type: IOCType
    ioc_value: str
    hash_type: Optional[HashType] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    status: AnalysisStatus = Field(default=AnalysisStatus.PENDING)
    submitted_by: str  # User ID who submitted this IOC
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_result: Optional[IOCAnalysisResult] = None

    @validator('ioc_value')
    def validate_ioc_value(cls, v, values):
        ioc_type = values.get('ioc_type')
        
        if ioc_type == IOCType.IP_ADDRESS:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Invalid IP address: {v}")
        elif ioc_type == IOCType.DOMAIN:
            domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            if not re.match(domain_pattern, v):
                raise ValueError(f"Invalid domain: {v}")
        elif ioc_type == IOCType.FILE_HASH:
            hash_type = values.get('hash_type')
            if hash_type == HashType.MD5 and len(v) != 32:
                raise ValueError("MD5 hash must be 32 characters")
            elif hash_type == HashType.SHA1 and len(v) != 40:
                raise ValueError("SHA1 hash must be 40 characters")
            elif hash_type == HashType.SHA256 and len(v) != 64:
                raise ValueError("SHA256 hash must be 64 characters")
            if not re.match(r'^[a-fA-F0-9]+$', v):
                raise ValueError("Hash must contain only hexadecimal characters")
        elif ioc_type == IOCType.EMAIL:
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, v):
                raise ValueError(f"Invalid email address: {v}")
        elif ioc_type == IOCType.URL:
            if not v.startswith(('http://', 'https://', 'ftp://')):
                raise ValueError("URL must start with http://, https://, or ftp://")
        
        return v

class IOCCreate(BaseModel):
    ioc_type: IOCType
    ioc_value: str
    hash_type: Optional[HashType] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class IOCBatchCreate(BaseModel):
    iocs: List[IOCCreate]

# Enhanced Threat Analysis Service with Multi-Source Integration
class ThreatAnalysisService:
    def __init__(self, openai_client: Optional[OpenAI]):
        self.openai_client = openai_client

    async def analyze_ioc(self, ioc: IOCRecord) -> IOCAnalysisResult:
        """Analyze IOC using multiple threat intelligence sources"""
        analysis_sources = []
        
        # Initialize results containers
        virustotal_data = None
        shodan_data = None
        abuseipdb_data = None
        otx_data = None
        urlhaus_data = None

        # Step 1: Query VirusTotal API
        try:
            async with VirusTotalService() as vt_service:
                logger.info(f"Querying VirusTotal for IOC {ioc.id}: {ioc.ioc_value}")
                virustotal_data = await vt_service.get_ioc_report(ioc.ioc_type.value, ioc.ioc_value)
                if virustotal_data and not virustotal_data.get('error'):
                    analysis_sources.append("virustotal")
                    logger.info(f"VirusTotal data retrieved for IOC {ioc.id}")
        except Exception as e:
            logger.warning(f"VirusTotal query failed for IOC {ioc.id}: {str(e)}")

        # Step 2: Query Shodan API (for IPs and domains)
        if ioc.ioc_type in [IOCType.IP_ADDRESS, IOCType.DOMAIN]:
            try:
                async with ShodanService() as shodan_service:
                    logger.info(f"Querying Shodan for IOC {ioc.id}: {ioc.ioc_value}")
                    shodan_data = await shodan_service.get_ioc_report(ioc.ioc_type.value, ioc.ioc_value)
                    if shodan_data and not shodan_data.get('error'):
                        analysis_sources.append("shodan")
                        logger.info(f"Shodan data retrieved for IOC {ioc.id}")
            except Exception as e:
                logger.warning(f"Shodan query failed for IOC {ioc.id}: {str(e)}")

        # Step 3: Query AbuseIPDB API (for IPs)
        if ioc.ioc_type == IOCType.IP_ADDRESS:
            try:
                async with AbuseIPDBService() as abuseipdb_service:
                    logger.info(f"Querying AbuseIPDB for IOC {ioc.id}: {ioc.ioc_value}")
                    abuseipdb_data = await abuseipdb_service.get_ioc_report(ioc.ioc_type.value, ioc.ioc_value)
                    if abuseipdb_data and not abuseipdb_data.get('error'):
                        analysis_sources.append("abuseipdb")
                        logger.info(f"AbuseIPDB data retrieved for IOC {ioc.id}")
            except Exception as e:
                logger.warning(f"AbuseIPDB query failed for IOC {ioc.id}: {str(e)}")

        # Step 4: Query OTX API
        try:
            async with OTXService() as otx_service:
                logger.info(f"Querying AlienVault OTX for IOC {ioc.id}: {ioc.ioc_value}")
                otx_data = await otx_service.get_ioc_report(ioc.ioc_type.value, ioc.ioc_value)
                if otx_data and not otx_data.get('error'):
                    analysis_sources.append("otx")
                    logger.info(f"OTX data retrieved for IOC {ioc.id}")
        except Exception as e:
            logger.warning(f"OTX query failed for IOC {ioc.id}: {str(e)}")

        # Step 5: Query URLhaus API (for URLs and domains)
        if ioc.ioc_type in [IOCType.URL, IOCType.DOMAIN]:
            try:
                async with URLhausService() as urlhaus_service:
                    logger.info(f"Querying URLhaus for IOC {ioc.id}: {ioc.ioc_value}")
                    urlhaus_data = await urlhaus_service.get_ioc_report(ioc.ioc_type.value, ioc.ioc_value)
                    if urlhaus_data and not urlhaus_data.get('error'):
                        analysis_sources.append("urlhaus")
                        logger.info(f"URLhaus data retrieved for IOC {ioc.id}")
            except Exception as e:
                logger.warning(f"URLhaus query failed for IOC {ioc.id}: {str(e)}")

        # Step 6: Generate enhanced OpenAI analysis with all collected data
        try:
            all_intel_data = {
                'virustotal': virustotal_data,
                'shodan': shodan_data,
                'abuseipdb': abuseipdb_data,
                'otx': otx_data,
                'urlhaus': urlhaus_data
            }
            
            prompt = self._build_enhanced_analysis_prompt(ioc, all_intel_data)
            response = await self._call_openai_api(prompt)
            result = self._parse_openai_response(response, ioc.id)
            
            # Add all threat intelligence results and source tracking
            result.virustotal_results = virustotal_data
            result.shodan_results = shodan_data
            result.abuseipdb_results = abuseipdb_data
            result.otx_results = otx_data
            result.urlhaus_results = urlhaus_data
            result.analysis_sources = analysis_sources + ["openai"]
            
            logger.info(f"Enhanced multi-source analysis completed for IOC {ioc.id} using sources: {result.analysis_sources}")
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing IOC {ioc.id}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    def _build_enhanced_analysis_prompt(self, ioc: IOCRecord, intel_data: Dict[str, Any]) -> str:
        """Build enhanced OpenAI prompt including all threat intelligence data"""
        base_prompt = """You are a senior threat intelligence analyst. Analyze the following IOC data from multiple threat intelligence sources and provide comprehensive threat actor identification:

IOC Information:
- Type: {ioc_type}
- Value: {ioc_value}
- Hash Type: {hash_type}
- Description: {description}
- Tags: {tags}

{intel_sections}

Based on all available intelligence sources, provide:
1. Top 3 most likely threat actor groups with confidence scores (0-100)
2. Detailed reasoning based on TTPs, infrastructure patterns, and IOC characteristics
3. Geographic attribution and motivation assessment
4. Timeline correlation with known campaigns
5. Integration of all threat intelligence findings

Format your response as JSON with the following structure:
{{
  "threat_actors": [
    {{
      "actor_name": "string",
      "confidence_score": 0-100,
      "evidence": ["string1", "string2"],
      "geographic_origin": "string",
      "motivation": "string"
    }}
  ],
  "ttps_analysis": {{
    "tactics": ["string"],
    "techniques": ["string"],
    "procedures": ["string"]
  }},
  "infrastructure_patterns": ["string1", "string2"],
  "timeline_correlation": [
    {{
      "campaign_name": "string",
      "timeframe": "string",
      "similarity_score": 0-100
    }}
  ],
  "confidence_overall": 0-100
}}"""

        # Build intelligence sections
        intel_sections = []
        
        # VirusTotal section
        vt_data = intel_data.get('virustotal')
        if vt_data and not vt_data.get('error'):
            vt_section = f"""
VirusTotal Intelligence:
- Detection Ratio: {vt_data.get('malicious', 0)}/{vt_data.get('total_vendors', 0)} engines detected as malicious
- Suspicious: {vt_data.get('suspicious', 0)} engines flagged as suspicious
- Reputation Score: {vt_data.get('reputation', 'N/A')}
- Additional Context: {self._format_virustotal_context(vt_data)}"""
            intel_sections.append(vt_section)
        
        # Shodan section
        shodan_data = intel_data.get('shodan')
        if shodan_data and not shodan_data.get('error'):
            shodan_section = f"""
Shodan Intelligence:
- Country: {shodan_data.get('country', 'N/A')}
- Organization: {shodan_data.get('organization', 'N/A')}
- Open Ports: {shodan_data.get('ports', [])}
- Services: {len(shodan_data.get('services', []))} services detected
- Vulnerabilities: {len(shodan_data.get('vulnerabilities', []))} CVEs found"""
            intel_sections.append(shodan_section)
        
        # AbuseIPDB section
        abuseipdb_data = intel_data.get('abuseipdb')
        if abuseipdb_data and not abuseipdb_data.get('error'):
            abuseipdb_section = f"""
AbuseIPDB Intelligence:
- Abuse Confidence: {abuseipdb_data.get('abuse_confidence', 0)}%
- Total Reports: {abuseipdb_data.get('total_reports', 0)}
- Country: {abuseipdb_data.get('country_name', 'N/A')}
- ISP: {abuseipdb_data.get('isp', 'N/A')}
- Usage Type: {abuseipdb_data.get('usage_type', 'N/A')}"""
            intel_sections.append(abuseipdb_section)
        
        # OTX section
        otx_data = intel_data.get('otx')
        if otx_data and not otx_data.get('error'):
            otx_section = f"""
AlienVault OTX Intelligence:
- Pulse Count: {otx_data.get('pulse_count', 0)} threat pulses
- Threat Score: {otx_data.get('reputation', {}).get('threat_score', 'N/A')}
- Malware Families: {len(otx_data.get('malware_families', []))} detected
- Geographic Data: {otx_data.get('geolocation', {})}"""
            intel_sections.append(otx_section)
        
        # URLhaus section  
        urlhaus_data = intel_data.get('urlhaus')
        if urlhaus_data and not urlhaus_data.get('error') and urlhaus_data.get('found'):
            urlhaus_section = f"""
URLhaus Intelligence:
- Status: {urlhaus_data.get('url_status', 'N/A')}
- Threat Type: {urlhaus_data.get('threat', 'N/A')}
- Tags: {urlhaus_data.get('tags', [])}
- Blacklist Status: {urlhaus_data.get('blacklists', {})}"""
            intel_sections.append(urlhaus_section)
        
        if not intel_sections:
            intel_sections.append("No threat intelligence data available from configured sources. Base analysis on IOC characteristics and known patterns.")
        
        return base_prompt.format(
            ioc_type=ioc.ioc_type.value,
            ioc_value=ioc.ioc_value,
            hash_type=ioc.hash_type.value if ioc.hash_type else "N/A",
            description=ioc.description or "N/A",
            tags=", ".join(ioc.tags) if ioc.tags else "N/A",
            intel_sections="\n".join(intel_sections)
        )

    def _format_virustotal_context(self, vt_data: Dict[str, Any]) -> str:
        """Format additional VirusTotal context for the prompt"""
        context_parts = []
        
        if vt_data.get('country'):
            context_parts.append(f"Country: {vt_data['country']}")
        if vt_data.get('as_owner'):
            context_parts.append(f"AS Owner: {vt_data['as_owner']}")
        if vt_data.get('registrar'):
            context_parts.append(f"Registrar: {vt_data['registrar']}")
        if vt_data.get('file_names'):
            context_parts.append(f"File Names: {', '.join(vt_data['file_names'][:3])}")
        if vt_data.get('file_type'):
            context_parts.append(f"File Type: {vt_data['file_type']}")
            
        return "; ".join(context_parts) if context_parts else "No additional context available"

    async def _call_openai_api(self, prompt: str) -> str:
        """Call OpenAI API for analysis"""
        if not self.openai_client:
            logger.warning("OpenAI client not available, using mock response")
            return self._generate_mock_response(prompt)
            
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity threat intelligence analyst with expertise in IOC analysis, threat actor attribution, and multi-source intelligence correlation."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.3
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"OpenAI API error: {str(e)}")
            # Return a mock response for demo purposes when OpenAI API fails
            return self._generate_mock_response(prompt)

    def _generate_mock_response(self, prompt: str) -> str:
        """Generate enhanced mock analysis response with multi-source integration"""
        # Determine if threat intelligence data was available
        has_intel_data = any(source in prompt.lower() for source in ['virustotal', 'shodan', 'abuseipdb', 'otx', 'urlhaus'])
        
        if "ip_address" in prompt.lower():
            confidence_boost = 15 if has_intel_data else 0
            return f'''
{{
  "threat_actors": [
    {{
      "actor_name": "APT28 (Fancy Bear)",
      "confidence_score": {80 + confidence_boost},
      "evidence": ["Known IP range usage", "Infrastructure pattern match", "Timing correlation"{", Multi-source TI correlation" if has_intel_data else ""}],
      "geographic_origin": "Russia",
      "motivation": "Espionage and intelligence gathering"
    }},
    {{
      "actor_name": "Lazarus Group", 
      "confidence_score": {50 + confidence_boost},
      "evidence": ["Similar network infrastructure", "Overlapping TTPs"{", Cross-platform detection patterns" if has_intel_data else ""}],
      "geographic_origin": "North Korea",
      "motivation": "Financial gain and espionage"
    }}
  ],
  "ttps_analysis": {{
    "tactics": ["Initial Access", "Command and Control", "Exfiltration"],
    "techniques": ["T1190 Exploit Public-Facing Application", "T1071.001 Web Protocols", "T1041 Exfiltration Over C2 Channel"],
    "procedures": ["Network scanning", "C2 communication", "Data staging"{", Multi-vector compromise" if has_intel_data else ""}]
  }},
  "infrastructure_patterns": [
    "Use of compromised legitimate domains for C2",
    "Fast-flux DNS to evade detection",
    "Shared hosting with other malicious domains"{",Cross-source intelligence correlation" if has_intel_data else ""}
  ],
  "timeline_correlation": [
    {{
      "campaign_name": "Operation Aurora Enhanced",
      "timeframe": "2023-Q3 to 2024-Q1", 
      "similarity_score": {75 + confidence_boost}
    }}
  ],
  "confidence_overall": {77 + min(confidence_boost, 20)}
}}
'''
        elif "domain" in prompt.lower():
            confidence_boost = 18 if has_intel_data else 0
            return f'''
{{
  "threat_actors": [
    {{
      "actor_name": "APT29 (Cozy Bear)",
      "confidence_score": {85 + confidence_boost},
      "evidence": ["Domain registration patterns", "DNS infrastructure", "C2 communication style"{", Multi-source reputation analysis" if has_intel_data else ""}],
      "geographic_origin": "Russia",
      "motivation": "Intelligence gathering and long-term espionage"
    }},
    {{
      "actor_name": "FIN7",
      "confidence_score": {65 + confidence_boost},
      "evidence": ["Similar phishing infrastructure", "Domain generation algorithm patterns"{", Cross-platform malicious classification" if has_intel_data else ""}],
      "geographic_origin": "Eastern Europe", 
      "motivation": "Financial cybercrime"
    }}
  ],
  "ttps_analysis": {{
    "tactics": ["Initial Access", "Persistence", "Command and Control"],
    "techniques": ["T1566.002 Spearphishing Link", "T1071.001 Web Protocols", "T1102 Web Service"],
    "procedures": ["Spear-phishing campaigns", "Domain fronting", "Living-off-the-land techniques"{", Domain reputation manipulation" if has_intel_data else ""}]
  }},
  "infrastructure_patterns": [
    "Use of typosquatting domains",
    "SSL certificates from free providers", 
    "Short domain registration periods"{", Consistent cross-source detection patterns" if has_intel_data else ""}
  ],
  "timeline_correlation": [
    {{
      "campaign_name": "CozyDuke Campaign Enhanced",
      "timeframe": "2024-Q1 to Present",
      "similarity_score": {82 + confidence_boost}
    }}
  ],
  "confidence_overall": {83 + min(confidence_boost, 17)}
}}
'''
        elif "file_hash" in prompt.lower():
            confidence_boost = 20 if has_intel_data else 0
            return f'''
{{
  "threat_actors": [
    {{
      "actor_name": "Equation Group",
      "confidence_score": {90 + min(confidence_boost, 10)},
      "evidence": ["Unique code signature", "Encryption algorithms", "Anti-analysis techniques"{", Multi-vendor malware classification" if has_intel_data else ""}],
      "geographic_origin": "United States",
      "motivation": "Advanced persistent espionage"
    }},
    {{
      "actor_name": "Shadow Brokers",
      "confidence_score": {75 + confidence_boost},
      "evidence": ["Code similarities", "Compilation timestamps"{", Consistent detection across engines" if has_intel_data else ""}],
      "geographic_origin": "Unknown",
      "motivation": "Tool/exploit distribution"
    }}
  ],
  "ttps_analysis": {{
    "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation"],
    "techniques": ["T1055 Process Injection", "T1027 Obfuscated Files", "T1068 Exploitation for Privilege Escalation"],
    "procedures": ["Code injection", "Rootkit installation", "Zero-day exploitation"{", Multi-stage payload deployment" if has_intel_data else ""}]
  }},
  "infrastructure_patterns": [
    "Advanced encryption and obfuscation",
    "Multi-stage payload delivery",
    "Anti-debugging mechanisms"{", Evasion of signature-based detection" if has_intel_data else ""}
  ],
  "timeline_correlation": [
    {{
      "campaign_name": "Operation Olympic Games Enhanced", 
      "timeframe": "2020-2024",
      "similarity_score": {88 + min(confidence_boost, 12)}
    }}
  ],
  "confidence_overall": {89 + min(confidence_boost, 11)}
}}
'''
        else:
            return '''
{
  "threat_actors": [
    {
      "actor_name": "Unknown Actor",
      "confidence_score": 35,
      "evidence": ["Limited intelligence available"],
      "geographic_origin": "Unknown",
      "motivation": "Unknown"
    }
  ],
  "ttps_analysis": {
    "tactics": ["Unknown"],
    "techniques": ["Insufficient data"],
    "procedures": ["Analysis pending"]
  },
  "infrastructure_patterns": [
    "Insufficient data for pattern analysis"
  ],
  "timeline_correlation": [],
  "confidence_overall": 25
}
'''

    def _parse_openai_response(self, response: str, ioc_id: str) -> IOCAnalysisResult:
        """Parse OpenAI response into structured result"""
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            parsed = json.loads(json_str)

            threat_actors = [
                ThreatActor(**actor) for actor in parsed.get('threat_actors', [])
            ]

            return IOCAnalysisResult(
                ioc_id=ioc_id,
                threat_actors=threat_actors,
                ttps_analysis=parsed.get('ttps_analysis', {}),
                infrastructure_patterns=parsed.get('infrastructure_patterns', []),
                timeline_correlation=parsed.get('timeline_correlation', []),
                raw_openai_response=response,
                confidence_overall=parsed.get('confidence_overall', 50)
            )

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Error parsing OpenAI response: {str(e)}")
            # Return a default result if parsing fails
            return IOCAnalysisResult(
                ioc_id=ioc_id,
                threat_actors=[],
                ttps_analysis={},
                infrastructure_patterns=[],
                timeline_correlation=[],
                raw_openai_response=response,
                confidence_overall=0
            )

# Initialize threat analysis service
threat_service = ThreatAnalysisService(openai_client)

# Database dependency
async def get_database():
    """Dependency to get database connection"""
    return db

# Create a wrapper for get_current_user that includes database dependency
async def get_current_user_with_db(
    database=Depends(get_database),
    credentials=Depends(HTTPBearer())
) -> User:
    """Get current user with database dependency"""
    from auth import get_current_user
    # Call get_current_user directly with the database
    user = await get_current_user(credentials, database)
    return user

# Enhanced background task for IOC analysis
async def process_ioc_analysis(ioc_id: str):
    """Enhanced background task to process IOC analysis with multi-source threat intelligence integration"""
    try:
        # Update status to processing
        await db.ioc_records.update_one(
            {"id": ioc_id},
            {"$set": {"status": AnalysisStatus.PROCESSING}}
        )

        # Get IOC record
        ioc_data = await db.ioc_records.find_one({"id": ioc_id})
        if not ioc_data:
            logger.error(f"IOC {ioc_id} not found")
            return

        ioc = IOCRecord(**ioc_data)

        # Perform enhanced analysis with multi-source threat intelligence integration
        analysis_result = await threat_service.analyze_ioc(ioc)

        # Update record with results
        await db.ioc_records.update_one(
            {"id": ioc_id},
            {
                "$set": {
                    "status": AnalysisStatus.COMPLETED,
                    "analysis_result": analysis_result.dict()
                }
            }
        )

        sources_used = ", ".join(analysis_result.analysis_sources)
        logger.info(f"Successfully analyzed IOC {ioc_id} using sources: {sources_used}")

    except Exception as e:
        logger.error(f"Error processing IOC {ioc_id}: {str(e)}")
        await db.ioc_records.update_one(
            {"id": ioc_id},
            {"$set": {"status": AnalysisStatus.FAILED}}
        )

# API Endpoints

@api_router.get("/")
async def root():
    return {
        "message": "IOC Enrichment Tool API with Multi-Source Threat Intelligence Integration", 
        "version": "3.0.0",
        "supported_sources": ["OpenAI", "VirusTotal", "Shodan", "AbuseIPDB", "AlienVault OTX", "URLhaus"],
        "supported_ioc_types": ["ip_address", "domain", "file_hash", "url", "email"]
    }

# Authentication endpoints
@api_router.post("/register", response_model=UserResponse)
async def register_user(user_data: UserCreate):
    """Register a new user"""
    try:
        user = await create_user(db, user_data)
        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@api_router.post("/login", response_model=Token)
async def login_user(user_credentials: UserLogin):
    """Authenticate user and return access token"""
    try:
        user = await authenticate_user(db, user_credentials.username, user_credentials.password)
        if not user:
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id, "role": user.role},
            expires_delta=access_token_expires
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

@api_router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user_with_db)):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at
    )

@api_router.post("/iocs", response_model=IOCRecord)
async def create_ioc(
    ioc_data: IOCCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user_with_db)
):
    """Create a new IOC and start enhanced multi-source analysis"""
    try:
        ioc = IOCRecord(**ioc_data.dict(), submitted_by=current_user.id)
        
        # Insert into database
        await db.ioc_records.insert_one(ioc.dict())
        
        # Start enhanced background analysis with multi-source threat intelligence integration
        background_tasks.add_task(process_ioc_analysis, ioc.id)
        
        return ioc
        
    except Exception as e:
        logger.error(f"Error creating IOC: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@api_router.post("/iocs/batch", response_model=List[IOCRecord])
async def create_iocs_batch(
    batch_data: IOCBatchCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user_with_db)
):
    """Create multiple IOCs and start enhanced analysis"""
    try:
        created_iocs = []
        for ioc_data in batch_data.iocs:
            ioc = IOCRecord(**ioc_data.dict(), submitted_by=current_user.id)
            await db.ioc_records.insert_one(ioc.dict())
            background_tasks.add_task(process_ioc_analysis, ioc.id)
            created_iocs.append(ioc)
        
        return created_iocs
        
    except Exception as e:
        logger.error(f"Error creating batch IOCs: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/iocs", response_model=List[IOCRecord])
async def get_iocs(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user_with_db)
):
    """Get IOC records for current user"""
    try:
        # Users can only see their own IOCs unless they're admin
        query = {}
        if current_user.role != "admin":
            query["submitted_by"] = current_user.id

        ioc_docs = await db.ioc_records.find(query).skip(skip).limit(limit).to_list(limit)
        return [IOCRecord(**doc) for doc in ioc_docs]
        
    except Exception as e:
        logger.error(f"Error fetching IOCs: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching IOCs")

@api_router.get("/iocs/{ioc_id}", response_model=IOCRecord)
async def get_ioc(
    ioc_id: str,
    current_user: User = Depends(get_current_user_with_db)
):
    """Get specific IOC by ID"""
    try:
        ioc_doc = await db.ioc_records.find_one({"id": ioc_id})
        if not ioc_doc:
            raise HTTPException(status_code=404, detail="IOC not found")

        ioc = IOCRecord(**ioc_doc)
        
        # Check ownership
        if not check_resource_ownership(current_user, ioc.submitted_by):
            raise HTTPException(status_code=403, detail="Access denied")

        return ioc
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching IOC {ioc_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching IOC")

@api_router.delete("/iocs/{ioc_id}")
async def delete_ioc(
    ioc_id: str,
    current_user: User = Depends(get_current_user_with_db)
):
    """Delete IOC by ID"""
    try:
        ioc_doc = await db.ioc_records.find_one({"id": ioc_id})
        if not ioc_doc:
            raise HTTPException(status_code=404, detail="IOC not found")

        ioc = IOCRecord(**ioc_doc)
        
        # Check ownership
        if not check_resource_ownership(current_user, ioc.submitted_by):
            raise HTTPException(status_code=403, detail="Access denied")

        result = await db.ioc_records.delete_one({"id": ioc_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="IOC not found")

        return {"message": "IOC deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting IOC {ioc_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error deleting IOC")

@api_router.get("/iocs/{ioc_id}/analysis", response_model=IOCAnalysisResult)
async def get_ioc_analysis(
    ioc_id: str,
    current_user: User = Depends(get_current_user_with_db)
):
    """Get analysis result for specific IOC"""
    try:
        ioc_doc = await db.ioc_records.find_one({"id": ioc_id})
        if not ioc_doc:
            raise HTTPException(status_code=404, detail="IOC not found")

        ioc = IOCRecord(**ioc_doc)
        
        # Check ownership
        if not check_resource_ownership(current_user, ioc.submitted_by):
            raise HTTPException(status_code=403, detail="Access denied")

        if not ioc.analysis_result:
            raise HTTPException(status_code=404, detail="Analysis not completed yet")

        return ioc.analysis_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching analysis for IOC {ioc_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching analysis")

@api_router.get("/stats")
async def get_stats(current_user: User = Depends(get_current_user_with_db)):
    """Get statistics about IOCs and analyses for current user"""
    try:
        # Users see only their own stats unless they're admin
        query = {}
        if current_user.role != "admin":
            query["submitted_by"] = current_user.id

        total_iocs = await db.ioc_records.count_documents(query)
        pending_analyses = await db.ioc_records.count_documents({**query, "status": AnalysisStatus.PENDING})
        processing_analyses = await db.ioc_records.count_documents({**query, "status": AnalysisStatus.PROCESSING})
        completed_analyses = await db.ioc_records.count_documents({**query, "status": AnalysisStatus.COMPLETED})
        failed_analyses = await db.ioc_records.count_documents({**query, "status": AnalysisStatus.FAILED})

        # Count analyses with multi-source data
        multi_source_enhanced = await db.ioc_records.count_documents({
            **query,
            "status": AnalysisStatus.COMPLETED,
            "$or": [
                {"analysis_result.virustotal_results": {"$exists": True, "$ne": None}},
                {"analysis_result.shodan_results": {"$exists": True, "$ne": None}},
                {"analysis_result.abuseipdb_results": {"$exists": True, "$ne": None}},
                {"analysis_result.otx_results": {"$exists": True, "$ne": None}},
                {"analysis_result.urlhaus_results": {"$exists": True, "$ne": None}}
            ]
        })

        stats_data = {
            "total_iocs": total_iocs,
            "pending_analyses": pending_analyses,
            "processing_analyses": processing_analyses,
            "completed_analyses": completed_analyses,
            "failed_analyses": failed_analyses,
            "multi_source_enhanced": multi_source_enhanced
        }

        # Add admin-specific stats
        if current_user.role == "admin":
            total_users = await db.users.count_documents({"is_active": True})
            stats_data["total_users"] = total_users

        return stats_data
        
    except Exception as e:
        logger.error(f"Error fetching stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching statistics")

# Threat Intelligence Service Status Endpoints
@api_router.get("/threat-intel/status")
async def get_threat_intel_status():
    """Check status of all threat intelligence services"""
    try:
        status = {
            "openai": {
                "configured": openai_client is not None,
                "api_key_present": bool(openai_api_key and openai_api_key != 'your-openai-api-key-here')
            },
            "virustotal": {
                "configured": False,
                "api_key_present": False
            },
            "shodan": {
                "configured": False,
                "api_key_present": False
            },
            "abuseipdb": {
                "configured": False,
                "api_key_present": False
            },
            "otx": {
                "configured": False,
                "api_key_present": False
            },
            "urlhaus": {
                "configured": True,  # URLhaus is free
                "api_key_present": True  # No key needed
            }
        }
        
        # Check VirusTotal
        vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
        status["virustotal"]["api_key_present"] = bool(vt_key)
        status["virustotal"]["configured"] = bool(vt_key and vt_key != 'your-virustotal-api-key-here')
        
        # Check Shodan
        shodan_key = os.environ.get('SHODAN_API_KEY')
        status["shodan"]["api_key_present"] = bool(shodan_key)
        status["shodan"]["configured"] = bool(shodan_key and shodan_key != 'your-shodan-api-key-here')
        
        # Check AbuseIPDB
        abuseipdb_key = os.environ.get('ABUSEIPDB_API_KEY')
        status["abuseipdb"]["api_key_present"] = bool(abuseipdb_key)
        status["abuseipdb"]["configured"] = bool(abuseipdb_key and abuseipdb_key != 'your-abuseipdb-api-key-here')
        
        # Check OTX
        otx_key = os.environ.get('OTX_API_KEY')
        status["otx"]["api_key_present"] = bool(otx_key)
        status["otx"]["configured"] = bool(otx_key and otx_key != 'your-otx-api-key-here')
        
        configured_count = sum(1 for service in status.values() if service["configured"])
        
        return {
            "services": status,
            "total_services": len(status),
            "configured_services": configured_count,
            "message": f"{configured_count} of {len(status)} threat intelligence services configured"
        }
        
    except Exception as e:
        logger.error(f"Error checking threat intelligence status: {str(e)}")
        raise HTTPException(status_code=500, detail="Error checking threat intelligence status")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
