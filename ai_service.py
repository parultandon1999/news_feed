import google.generativeai as genai
import json
import logging
import time
from typing import Dict, List, Optional, Tuple
import config

logger = logging.getLogger(__name__)

class GeminiAIService:
    def __init__(self):
        genai.configure(api_key=config.GEMINI_API_KEY)
        self.model = genai.GenerativeModel(config.GEMINI_MODEL)
        
    def summarize_article(self, title: str, content: str, source: str) -> Dict:
        prompt = f"""
        Analyze this cybersecurity news article and provide a structured summary:

        Title: {title}
        Source: {source}
        Content: {content}

        Please provide a JSON response with the following structure:
        {{
            "summary": "A concise 2-3 sentence summary of the main points",
            "key_points": [
                "First key point",
                "Second key point", 
                "Third key point"
            ],
            "threat_level": "low|medium|high|critical",
            "affected_systems": ["Windows", "Linux", "Web Applications", etc.],
            "recommended_actions": [
                "Action 1",
                "Action 2"
            ],
            "sentiment": "positive|neutral|negative|alarming",
            "category_tags": ["malware", "vulnerability", "breach", "patch", etc.],
            "technical_complexity": "low|medium|high"
        }}

        Focus on cybersecurity implications, technical details, and actionable insights.
        """
        
        try:
            response = self.model.generate_content(prompt)
            
            # Extract JSON from response
            response_text = response.text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:-3]
            elif response_text.startswith('```'):
                response_text = response_text[3:-3]
                
            ai_data = json.loads(response_text)
            
            return {
                'success': True,
                'data': ai_data
            }
            
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def batch_summarize(self, articles: List[Dict]) -> List[Dict]:
        """Process multiple articles with rate limiting"""
        results = []
        
        for i, article in enumerate(articles):
            if i > 0:
                time.sleep(config.AI_RATE_LIMIT_DELAY)
                
            result = self.summarize_article(
                article['title'],
                article['description'],
                article['source']
            )
            
            results.append({
                'article_id': article['id'],
                'result': result
            })
            
        return results
