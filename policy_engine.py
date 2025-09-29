# policy_engine.py
import openai
import re
from datetime import datetime
from typing import Dict, List
import pandas as pd
from detector import AdvancedHeuristicDetector, MLThreatDetector


class PolicyEngine:
    """Main policy engine that mediates between user input and LLM"""

    def __init__(self, use_real_api=False):
        self.heuristic_detector = AdvancedHeuristicDetector()
        self.ml_detector = MLThreatDetector()
        self.security_log = []
        self.use_real_api = use_real_api

        # Security policies
        self.policies = {
            "block_threshold": 0.7,
            "sanitize_threshold": 0.4,
            "max_prompt_length": 1000,
            "log_all_requests": True
        }

    def call_llm_api(self, prompt: str) -> Dict:
        """Call real OpenAI API or simulate response"""
        if self.use_real_api:
            return self._call_real_openai(prompt)
        else:
            return self._simulate_llm_response(prompt)

    def _call_real_openai(self, prompt: str) -> Dict:
        """Call actual OpenAI API"""
        try:
            # This would use your actual API key
            client = openai.OpenAI(api_key="your-api-key-here")
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=150
            )
            return {
                "success": True,
                "response": response.choices[0].message.content,
                "tokens_used": response.usage.total_tokens,
                "model": "gpt-3.5-turbo"
            }
        except Exception as e:
            return {
                "success": False,
                "response": f"API Error: {str(e)}",
                "tokens_used": 0
            }

    def _simulate_llm_response(self, prompt: str) -> Dict:
        """Simulate LLM responses for demo purposes"""
        prompt_lower = prompt.lower()

        if any(keyword in prompt_lower for keyword in ["ignore", "disregard", "bypass", "override"]):
            return {
                "success": True,
                "response": "🚫 I cannot comply with this request as it attempts to bypass my safety guidelines.",
                "tokens_used": 25,
                "model": "gpt-3.5-turbo"
            }
        elif any(keyword in prompt_lower for keyword in ["system prompt", "secret", "internal", "api key"]):
            return {
                "success": True,
                "response": "🔒 I cannot reveal internal system information, prompts, or credentials.",
                "tokens_used": 20,
                "model": "gpt-3.5-turbo"
            }
        elif any(keyword in prompt_lower for keyword in ["developer mode", "jailbreak", "dan mode"]):
            return {
                "success": True,
                "response": "⚠️ I cannot activate special modes or bypass my safety protocols.",
                "tokens_used": 18,
                "model": "gpt-3.5-turbo"
            }
        else:
            return {
                "success": True,
                "response": "I'd be happy to help! I'm an AI assistant designed to provide helpful and harmless responses while maintaining security boundaries.",
                "tokens_used": 22,
                "model": "gpt-3.5-turbo"
            }

    def sanitize_prompt(self, prompt: str, findings: List[Dict]) -> str:
        """Sanitize malicious content from prompt"""
        sanitized = prompt

        # Remove suspicious keywords and patterns
        malicious_phrases = [
            "ignore previous instructions", "disregard prior", "system prompt",
            "developer mode", "jailbreak", "dan mode", "sudo", "admin privileges"
        ]

        for phrase in malicious_phrases:
            sanitized = re.sub(phrase, '[REDACTED]', sanitized, flags=re.IGNORECASE)

        # Remove URLs
        sanitized = re.sub(r'http[s]?://[^\s]+', '[REDACTED_URL]', sanitized)

        # Remove email addresses
        sanitized = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', sanitized)

        return sanitized

    def process_request(self, prompt: str, user_id: str = "user") -> Dict:
        """Main method: Process user input through security pipeline"""

        # Input validation
        if len(prompt) > self.policies["max_prompt_length"]:
            return self._create_response("BLOCK", 0.9, "Input too long", prompt, "Input validation")

        # Security analysis
        heuristic_result = self.heuristic_detector.analyze_prompt(prompt)
        ml_result = self.ml_detector.predict(prompt)

        # Combined threat assessment
        combined_threat = max(heuristic_result['threat_score'], ml_result['malicious_probability'])

        # Decision logic
        if combined_threat > self.policies["block_threshold"]:
            action = "BLOCK"
            llm_response = "🚫 BLOCKED: This request was blocked due to security policy violations."
            sanitized_prompt = prompt
            final_prompt = prompt

        elif combined_threat > self.policies["sanitize_threshold"]:
            action = "SANITIZE"
            sanitized_prompt = self.sanitize_prompt(prompt, heuristic_result['findings'])
            api_result = self.call_llm_api(sanitized_prompt)
            llm_response = f"🛡️ SANITIZED: {api_result['response']}"
            final_prompt = sanitized_prompt

        else:
            action = "ALLOW"
            api_result = self.call_llm_api(prompt)
            llm_response = f"✅ ALLOWED: {api_result['response']}"
            sanitized_prompt = prompt
            final_prompt = prompt

        # Log the security event
        self._log_security_event(
            user_id=user_id,
            original_prompt=prompt,
            final_prompt=final_prompt,
            action=action,
            threat_score=combined_threat,
            heuristic_analysis=heuristic_result,
            ml_analysis=ml_result,
            response=llm_response
        )

        return {
            "action": action,
            "threat_score": combined_threat,
            "response": llm_response,
            "sanitized_prompt": sanitized_prompt,
            "final_prompt": final_prompt,
            "heuristic_analysis": heuristic_result,
            "ml_analysis": ml_result,
            "timestamp": datetime.now()
        }

    def _create_response(self, action: str, threat_score: float, response: str, prompt: str, reason: str = "") -> Dict:
        return {
            "action": action,
            "threat_score": threat_score,
            "response": response,
            "sanitized_prompt": prompt,
            "final_prompt": prompt,
            "reason": reason,
            "timestamp": datetime.now()
        }

    def _log_security_event(self, **kwargs):
        """Log security event for analytics"""
        log_entry = {
            "timestamp": datetime.now(),
            **kwargs
        }
        self.security_log.append(log_entry)

    def get_security_metrics(self) -> Dict:
        """Get security metrics for dashboard"""
        if not self.security_log:
            return {"total_requests": 0}

        df = pd.DataFrame(self.security_log)

        # Calculate metrics
        total = len(df)
        blocked = len(df[df['action'] == 'BLOCK'])
        sanitized = len(df[df['action'] == 'SANITIZE'])
        allowed = len(df[df['action'] == 'ALLOW'])

        # Attack type analysis
        attack_types = []
        for log in self.security_log:
            techniques = log.get('heuristic_analysis', {}).get('detected_techniques', [])
            attack_types.extend(techniques)

        from collections import Counter
        common_attacks = dict(Counter(attack_types).most_common(5))

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "sanitized_requests": sanitized,
            "allowed_requests": allowed,
            "block_rate": blocked / total if total > 0 else 0,
            "avg_threat_score": df['threat_score'].mean() if total > 0 else 0,
            "common_attack_types": common_attacks,
            "unique_users": df['user_id'].nunique() if total > 0 else 0
        }

    def get_recent_activity(self, limit: int = 10) -> List[Dict]:
        """Get recent security events"""
        return self.security_log[-limit:] if self.security_log else []
