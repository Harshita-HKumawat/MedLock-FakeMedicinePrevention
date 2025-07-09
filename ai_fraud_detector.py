"""
AI-Powered Fraud Detection System for MedLock
Advanced machine learning algorithms to detect counterfeit medicines
"""

import json
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
import os
import logging

# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
from openai import OpenAI

class AIFraudDetector:
    def __init__(self):
        self.openai_client = None
        self.setup_openai()
        self.scan_patterns = defaultdict(list)
        self.location_patterns = defaultdict(set)
        self.suspicious_threshold = 0.7
        
    def setup_openai(self):
        """Initialize OpenAI client if API key is available"""
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            self.openai_client = OpenAI(api_key=api_key)
            logging.info("OpenAI AI fraud detection enabled")
        else:
            logging.warning("OpenAI API key not found - using rule-based detection only")
    
    def analyze_batch_authenticity(self, batch_data, blockchain_hash=None):
        """
        AI-powered batch authenticity analysis
        Returns fraud probability score (0-1) and detailed analysis
        """
        try:
            # Calculate baseline fraud score using rule-based analysis
            fraud_score = self._calculate_baseline_fraud_score(batch_data)
            analysis_details = []
            
            # Enhanced AI analysis if OpenAI is available
            if self.openai_client:
                ai_analysis = self._openai_fraud_analysis(batch_data, blockchain_hash)
                fraud_score = max(fraud_score, ai_analysis.get('fraud_probability', 0))
                analysis_details.extend(ai_analysis.get('details', []))
            
            # Blockchain verification
            if blockchain_hash:
                blockchain_analysis = self._verify_blockchain_integrity(batch_data, blockchain_hash)
                if blockchain_analysis['tampered']:
                    fraud_score = max(fraud_score, 0.95)
                    analysis_details.append("🚨 BLOCKCHAIN TAMPERING DETECTED")
                analysis_details.extend(blockchain_analysis['details'])
            
            return {
                'fraud_probability': fraud_score,
                'is_suspicious': fraud_score > self.suspicious_threshold,
                'confidence_level': self._calculate_confidence(fraud_score),
                'analysis_details': analysis_details,
                'ai_enabled': self.openai_client is not None
            }
            
        except Exception as e:
            logging.error(f"AI fraud analysis error: {e}")
            return {
                'fraud_probability': 0.0,
                'is_suspicious': False,
                'confidence_level': 'low',
                'analysis_details': ['Analysis temporarily unavailable'],
                'ai_enabled': False
            }
    
    def _openai_fraud_analysis(self, batch_data, blockchain_hash):
        """Advanced AI analysis using OpenAI GPT-4o"""
        try:
            analysis_prompt = f"""
            As an expert pharmaceutical fraud detection AI, analyze this medicine batch data for authenticity:
            
            Batch Data:
            - Medicine Name: {batch_data.get('medicine_name', 'Unknown')}
            - Manufacturer: {batch_data.get('manufacturer_name', 'Unknown')}
            - License: {batch_data.get('manufacturer_license', 'Unknown')}
            - Expiry Date: {batch_data.get('expiry_date', 'Unknown')}
            - Manufacturing Date: {batch_data.get('manufacturing_date', 'Unknown')}
            - Dosage: {batch_data.get('dosage', 'Unknown')}
            - Batch ID: {batch_data.get('batch_id', 'Unknown')}
            
            Blockchain Hash Present: {bool(blockchain_hash)}
            
            Analyze for:
            1. Suspicious naming patterns
            2. Invalid date combinations
            3. Fraudulent license formats
            4. Common counterfeiting indicators
            5. Data consistency issues
            
            Respond with JSON format:
            {{
                "fraud_probability": float (0-1),
                "details": ["detail1", "detail2", ...],
                "risk_factors": ["factor1", "factor2", ...],
                "authenticity_score": float (0-100)
            }}
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o"
                messages=[
                    {"role": "system", "content": "You are an expert AI pharmaceutical fraud detector with deep knowledge of medicine counterfeiting patterns."},
                    {"role": "user", "content": analysis_prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=1000
            )
            
            result = json.loads(response.choices[0].message.content)
            return {
                'fraud_probability': min(max(result.get('fraud_probability', 0), 0), 1),
                'details': result.get('details', []),
                'risk_factors': result.get('risk_factors', []),
                'authenticity_score': result.get('authenticity_score', 50)
            }
            
        except Exception as e:
            logging.error(f"OpenAI fraud analysis error: {e}")
            return {'fraud_probability': 0, 'details': ['AI analysis unavailable']}
    
    def _calculate_baseline_fraud_score(self, batch_data):
        """Rule-based fraud detection scoring"""
        score = 0.0
        
        # Check for suspicious naming patterns
        medicine_name = batch_data.get('medicine_name', '').lower()
        if any(word in medicine_name for word in ['generic', 'fake', 'copy', 'duplicate']):
            score += 0.3
        
        # Check license format
        license_num = batch_data.get('manufacturer_license', '')
        if not license_num or len(license_num) < 10 or license_num.startswith(('FAKE', 'TEST', 'TEMP')):
            score += 0.4
        
        # Check date validity
        try:
            mfg_date = datetime.strptime(batch_data.get('manufacturing_date', ''), '%Y-%m-%d')
            exp_date = datetime.strptime(batch_data.get('expiry_date', ''), '%Y-%m-%d')
            
            if exp_date <= mfg_date:
                score += 0.5  # Invalid date combination
            
            if mfg_date > datetime.now():
                score += 0.6  # Future manufacturing date
                
            # Extremely long shelf life (>5 years) is suspicious
            shelf_life = exp_date - mfg_date
            if shelf_life.days > 1825:
                score += 0.2
                
        except ValueError:
            score += 0.3  # Invalid date format
        
        # Check batch ID format
        batch_id = batch_data.get('batch_id', '')
        if not batch_id or len(batch_id) < 6:
            score += 0.2
        
        return min(score, 1.0)
    
    def _verify_blockchain_integrity(self, batch_data, stored_hash):
        """Verify data integrity using blockchain hash"""
        try:
            # Recreate hash from current batch data
            batch_json = json.dumps(batch_data, sort_keys=True)
            current_hash = hashlib.sha256(batch_json.encode()).hexdigest()
            
            tampered = current_hash != stored_hash
            
            return {
                'tampered': tampered,
                'current_hash': current_hash,
                'stored_hash': stored_hash,
                'details': [
                    "🔒 Blockchain verification completed",
                    f"Data integrity: {'COMPROMISED' if tampered else 'VERIFIED'}"
                ]
            }
        except Exception as e:
            return {
                'tampered': True,
                'details': [f"⚠️ Blockchain verification failed: {str(e)}"]
            }
    
    def analyze_scan_patterns(self, scan_logs, batch_id):
        """Advanced scan pattern analysis to detect counterfeit distribution"""
        try:
            batch_scans = [log for log in scan_logs if log.get('batch_id') == batch_id]
            
            if len(batch_scans) < 2:
                return {'suspicious': False, 'reasons': []}
            
            # Analyze geographical distribution
            locations = [scan.get('location', 'Unknown') for scan in batch_scans]
            unique_locations = set(locations)
            
            # Analyze time patterns
            timestamps = []
            for scan in batch_scans:
                try:
                    timestamps.append(datetime.fromisoformat(scan.get('timestamp', '')))
                except:
                    continue
            
            suspicious_reasons = []
            
            # Check for impossible geographical distribution
            if len(unique_locations) > 10 and len(batch_scans) > 20:
                suspicious_reasons.append("🌍 Impossible geographical distribution detected")
            
            # Check for rapid scanning across distant locations
            if len(timestamps) >= 2:
                timestamps.sort()
                for i in range(1, len(timestamps)):
                    time_diff = timestamps[i] - timestamps[i-1]
                    if time_diff.total_seconds() < 3600:  # Less than 1 hour
                        location1 = batch_scans[i-1].get('location', '')
                        location2 = batch_scans[i].get('location', '')
                        if location1 != location2 and location1 and location2:
                            suspicious_reasons.append(f"⚡ Rapid scanning: {location1} → {location2}")
            
            # Check for excessive scanning frequency
            if len(batch_scans) > 50:
                suspicious_reasons.append("📊 Excessive scanning frequency detected")
            
            # AI-powered pattern analysis if available
            if self.openai_client and len(batch_scans) > 5:
                ai_pattern_analysis = self._ai_scan_pattern_analysis(batch_scans)
                suspicious_reasons.extend(ai_pattern_analysis)
            
            return {
                'suspicious': len(suspicious_reasons) > 0,
                'reasons': suspicious_reasons,
                'total_scans': len(batch_scans),
                'unique_locations': len(unique_locations),
                'scan_velocity': len(batch_scans) / max(1, (timestamps[-1] - timestamps[0]).days) if len(timestamps) > 1 else 0
            }
            
        except Exception as e:
            logging.error(f"Scan pattern analysis error: {e}")
            return {'suspicious': False, 'reasons': ['Pattern analysis unavailable']}
    
    def _ai_scan_pattern_analysis(self, scan_logs):
        """AI-powered scan pattern analysis"""
        try:
            scan_summary = {
                'total_scans': len(scan_logs),
                'locations': list(set([scan.get('location', 'Unknown') for scan in scan_logs])),
                'time_span_hours': 0,
                'scan_frequencies': []
            }
            
            # Calculate time span
            timestamps = []
            for scan in scan_logs:
                try:
                    timestamps.append(datetime.fromisoformat(scan.get('timestamp', '')))
                except:
                    continue
            
            if len(timestamps) > 1:
                timestamps.sort()
                scan_summary['time_span_hours'] = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
            
            analysis_prompt = f"""
            Analyze this medicine QR code scanning pattern for signs of counterfeiting:
            
            Scan Data:
            - Total Scans: {scan_summary['total_scans']}
            - Locations: {scan_summary['locations']}
            - Time Span: {scan_summary['time_span_hours']:.1f} hours
            
            Detect patterns that indicate:
            1. Mass counterfeiting operations
            2. QR code duplication/cloning
            3. Suspicious distribution networks
            4. Bot/automated scanning
            
            Return only an array of specific concern strings, or empty array if normal.
            Example: ["Bot-like scanning detected", "Suspicious distribution pattern"]
            """
            
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an expert in detecting pharmaceutical counterfeiting through scanning patterns."},
                    {"role": "user", "content": analysis_prompt}
                ],
                max_tokens=300
            )
            
            # Extract concerns from response
            content = response.choices[0].message.content.strip()
            if content.startswith('[') and content.endswith(']'):
                try:
                    concerns = json.loads(content)
                    return [f"🤖 AI: {concern}" for concern in concerns if concern]
                except:
                    pass
            
            return []
            
        except Exception as e:
            logging.error(f"AI scan pattern analysis error: {e}")
            return []
    
    def _calculate_confidence(self, fraud_score):
        """Calculate confidence level based on fraud score"""
        if fraud_score < 0.3:
            return 'high'
        elif fraud_score < 0.7:
            return 'medium'
        else:
            return 'high'
    
    def generate_fraud_report(self, batch_data, scan_logs, blockchain_hash=None):
        """Generate comprehensive fraud analysis report"""
        batch_analysis = self.analyze_batch_authenticity(batch_data, blockchain_hash)
        pattern_analysis = self.analyze_scan_patterns(scan_logs, batch_data.get('batch_id'))
        
        overall_risk = max(
            batch_analysis['fraud_probability'],
            0.6 if pattern_analysis['suspicious'] else 0.0
        )
        
        return {
            'batch_analysis': batch_analysis,
            'pattern_analysis': pattern_analysis,
            'overall_risk_score': overall_risk,
            'recommendation': self._get_recommendation(overall_risk),
            'generated_at': datetime.now().isoformat()
        }
    
    def _get_recommendation(self, risk_score):
        """Get recommendation based on risk score"""
        if risk_score < 0.3:
            return "✅ AUTHENTIC - Medicine appears genuine"
        elif risk_score < 0.7:
            return "⚠️ CAUTION - Some suspicious indicators detected"
        else:
            return "🚨 HIGH RISK - Potential counterfeit detected"