"""
Base Agent Class
"""

import logging
import json
import re
from abc import ABC
from typing import Any, Dict, Optional
from tools.core import LLMClient
from tools.core import get_prompt_manager


class BaseAgent(ABC):
    """Base class for all agents - simple and focused"""
    
    def __init__(self, llm_client: LLMClient, debug: bool = False):
        self.llm_client = llm_client
        self.debug = debug
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        self.prompt_manager = get_prompt_manager()
    
    def ask_json(self, user_prompt: str, system_prompt: str = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Ask LLM with JSON response format enforcement.

        Returns:
            Parsed JSON dict on success, None on any failure.
        """
        try:
            response = self.llm_client.ask_with_logging(
                prompt=user_prompt,
                system_prompt=system_prompt,
                response_format='json',
                **kwargs
            )

            if isinstance(response, dict):
                return response
            elif isinstance(response, str):
                return json.loads(response)
            else:
                self.logger.error(f"Unexpected response type: {type(response)}")
                return None

        except json.JSONDecodeError as e:
            self.logger.error(f"JSON parse failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"LLM call failed: {e}")
            return None
    
    def _extract_code_from_response(self, response: str, language: str = None) -> Optional[str]:
        """
        Extract code from LLM response - simple and robust
        
        Args:
            response: LLM response string
            language: Expected language (java, python, etc.) - optional
            
        Returns:
            Extracted code string or None if not found
        """
        if not response:
            return None
            
        response = response.strip()
        
        # Remove common markdown patterns
        response = response.replace("```json", "```").replace("```markdown", "```")
        
        # Pattern 1: Language-specific code blocks (original compatible)
        if language:
            pattern = rf"```{language}\s*(.*?)\s*```"
            match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Pattern 2: Generic code blocks (original compatible)
        pattern = r"```\s*(.*?)\s*```"
        match = re.search(pattern, response, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Pattern 3: Single backticks (inline code)
        pattern = r'`([^`]+)`'
        matches = re.findall(pattern, response)
        if matches:
            # Return the longest inline code
            longest = max(matches, key=len).strip()
            # Only return if it looks like substantial code (more than just a word)
            if len(longest) > 10 and ('(' in longest or '{' in longest or ';' in longest):
                return longest
        
        # Pattern 4: If no code blocks found, try to extract Java-like or Python-like content
        if language == "java":
            # Look for class or method definitions
            java_pattern = r'((?:public|private|protected)?\s*(?:class|interface|\w+\s+\w+\s*\([^)]*\)\s*\{).*?(?:\}|$))'
            match = re.search(java_pattern, response, re.DOTALL | re.MULTILINE)
            if match:
                return match.group(1).strip()
        elif language == "python":
            # Look for function or class definitions
            python_pattern = r'((?:def|class)\s+\w+.*?)(?=\n(?:def|class|\Z))'
            match = re.search(python_pattern, response, re.DOTALL | re.MULTILINE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def _extract_json_from_response(self, response: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON from LLM response - robust parsing
        
        Args:
            response: LLM response string
            
        Returns:
            Parsed JSON dictionary or None if parsing fails
        """
        if not response:
            return None
            
        response = response.strip()
        
        # Remove markdown code blocks
        response = response.replace("```json", "").replace("```", "")
        
        # Try to find JSON-like content
        json_pattern = r'\{.*\}'
        matches = re.findall(json_pattern, response, re.DOTALL)
        
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue
        
        # Fallback: try to parse the entire response
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return None