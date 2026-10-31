"""
Unified LLM client module supporting multiple providers.
"""
import os
import time
import openai
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from ..utils.api_usage_tracker import APIUsageTracker

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False


class LLMClient(ABC):
    """Base class for LLM clients."""

    def __init__(self, config: Dict[str, Any], usage_tracker: Optional[APIUsageTracker] = None):
        self.config = config
        self.usage_tracker = usage_tracker or APIUsageTracker()
        self.provider = config.get("type", "unknown")
        self.model = config.get("model", "unknown")  # Use "model" key as per config format

        # Log output directory (avoids global env var pollution)
        self.log_output_dir = "results"

        # Default LLM parameters
        self.default_params = {
            'temperature': 0.2,
            'n': 1,
        }
    
    @abstractmethod
    def _make_api_call(self, messages: list, **kwargs) -> Dict[str, Any]:
        """Make actual API call to the provider."""
        pass
    
    def _count_tokens(self, text: str) -> int:
        """Count tokens in text using tiktoken or simple estimation."""
        if not text:
            return 0
            
        if TIKTOKEN_AVAILABLE:
            try:
                # Choose encoder based on model
                if "gpt-4" in self.model:
                    encoding = tiktoken.encoding_for_model("gpt-4")
                elif "gpt-3.5" in self.model:
                    encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
                else:
                    encoding = tiktoken.get_encoding("cl100k_base")
                
                return len(encoding.encode(text))
            except Exception:
                pass
        
        # Fallback: estimate by character count
        return len(text) // 4
    
    def ask(self, prompt: str, system_prompt: Optional[str] = None, **llm_params):
        """Basic LLM call with usage tracking and multi-response support.
        
        Use this for:
        - POC generation where multiple responses are needed (n>1)
        - Simple calls without detailed logging
        
        Returns:
            str: Single response when n=1 (default)
            list: List of responses when n>1
        """
        start_time = time.time()
        
        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        # Count input tokens
        prompt_tokens = self._count_tokens(prompt)
        system_tokens = self._count_tokens(system_prompt) if system_prompt else 0
        total_input_tokens = prompt_tokens + system_tokens
        
        try:
            # Merge default params with custom parameters
            final_params = self.default_params.copy()
            final_params.update(llm_params)
            
            # Call API with merged parameters
            response = self._make_api_call(messages, **final_params)
            
            # Handle multiple responses or single response
            n = final_params.get('n', 1)
            if 'choices' in response and n > 1:
                # Multiple responses - return list
                response_texts = [choice['content'] for choice in response['choices']]
                is_multiple = True
            elif 'choices' in response:
                # Single response from choices format
                response_text = response['choices'][0]['content']
                is_multiple = False
            else:
                # Single response from content format
                response_text = response.get('content', '')
                is_multiple = False
            api_usage = response.get('usage', {})
            
            # Use API-provided token counts if available, otherwise use local estimation
            if api_usage and api_usage.get('prompt_tokens') and api_usage.get('completion_tokens'):
                prompt_tokens_actual = api_usage.get('prompt_tokens', 0)
                completion_tokens_actual = api_usage.get('completion_tokens', 0)
                total_tokens_actual = api_usage.get('total_tokens', 0) or (prompt_tokens_actual + completion_tokens_actual)
            else:
                # Fallback to local estimation
                if is_multiple:
                    completion_tokens_actual = sum(self._count_tokens(text) for text in response_texts)
                else:
                    completion_tokens_actual = self._count_tokens(response_text)
                prompt_tokens_actual = total_input_tokens
                total_tokens_actual = prompt_tokens_actual + completion_tokens_actual
            
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Record usage with actual API token counts
            self.usage_tracker.record_api_call(
                model=self.model,
                provider=self.provider,
                prompt_tokens=prompt_tokens_actual,
                completion_tokens=completion_tokens_actual,
                total_tokens=total_tokens_actual,
                success=True,
                duration_ms=duration_ms
            )
            
            # Return appropriate format based on n parameter
            return response_texts if is_multiple else response_text
        except Exception as e:
            # Record failed usage
            self.usage_tracker.record_api_call(
                model=self.model,
                provider=self.provider,
                prompt_tokens=total_input_tokens,
                completion_tokens=0,
                total_tokens=total_input_tokens,
                success=False,
                error_message=str(e),
                duration_ms=int((time.time() - start_time) * 1000)
            )
            raise
    

    def ask_with_logging(self, prompt: str, system_prompt: Optional[str] = None, 
                        log_file_prefix: Optional[str] = None, 
                        stage: Optional[str] = None,
                        chain_id: Optional[int] = None, **llm_params) -> str:
        """LLM call with comprehensive logging and single response guarantee.
        
        Use this for:
        - Analysis stages that need detailed logs
        - Cases where you need guaranteed single string response
        - Debugging and tracing LLM interactions
        
        Args:
            prompt: User prompt
            system_prompt: System prompt
            log_file_prefix: Custom log file prefix
            stage: Analysis stage (e.g., 'semantic_analysis', 'z3_generation')
            chain_id: Chain identifier for organizing logs
            
        Returns:
            str: Always returns a single response string
        """

        # Get or create run session ID
        run_session_id = os.environ.get('RUN_SESSION_ID')
        if not run_session_id:
            run_session_id = time.strftime("%Y%m%d_%H%M%S")
            os.environ['RUN_SESSION_ID'] = run_session_id

        # Create log directory structure using instance property (not env var)
        output_dir = self.log_output_dir
        final_log_dir = os.path.join(output_dir, "llm_logs")
        
        os.makedirs(final_log_dir, exist_ok=True)
        
        # Generate log file names
        base_name = log_file_prefix if log_file_prefix else (stage if stage else "unknown_stage")
        
        # Create full file paths
        prompt_file = os.path.join(final_log_dir, f"{base_name}_prompt.txt")
        reasoning_file = os.path.join(final_log_dir, f"{base_name}_reasoning.txt")
        response_file = os.path.join(final_log_dir, f"{base_name}_response.txt")
        full_log_file = os.path.join(final_log_dir, f"{base_name}_full_interaction.txt")
        
        # Save prompt to independent file
        with open(prompt_file, 'w', encoding='utf-8') as f:
            f.write(f"=== SYSTEM PROMPT ===\n")
            f.write(system_prompt or "None")
            f.write(f"\n\n=== USER PROMPT ===\n")
            f.write(prompt)
        
        # Set reasoning file path only for models that support reasoning
        reasoning_supported = self._supports_reasoning()
        if reasoning_supported and hasattr(self, 'set_reasoning_file'):
            self.set_reasoning_file(reasoning_file)
        
        # Call original ask method with custom parameters (force n=1 for logging)
        start_time = time.time()
        llm_params['n'] = 1  # Force single response for logging
        response = self.ask(prompt, system_prompt, **llm_params)
        duration = time.time() - start_time
        
        # Ensure response is always string (type safety)
        if isinstance(response, list):
            response = response[0] if response else ""
        
        # Save response to independent file
        with open(response_file, 'w', encoding='utf-8') as f:
            f.write(response)
        
        # Save complete interaction record
        with open(full_log_file, 'w', encoding='utf-8') as f:
            f.write(f"=== LLM INTERACTION LOG ===\n")
            f.write(f"Run Session: {run_session_id}\n")
            f.write(f"Stage: {stage or 'unknown'}\n")
            f.write(f"Chain ID: {chain_id or 'N/A'}\n")
            f.write(f"Model: {self.model}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {duration:.2f}s\n")
            f.write(f"Supports Reasoning: {reasoning_supported}\n")
            
            f.write(f"\n=== SYSTEM PROMPT ===\n")
            f.write(system_prompt or "None")
            f.write(f"\n\n=== USER PROMPT ===\n")
            f.write(prompt)
            
            # Include reasoning content only for supported models
            if reasoning_supported and os.path.exists(reasoning_file):
                try:
                    with open(reasoning_file, 'r', encoding='utf-8') as rf:
                        reasoning_content = rf.read()
                        if reasoning_content.strip():
                            f.write(f"\n\n=== REASONING ===\n")
                            f.write(reasoning_content)
                        else:
                            f.write(f"\n\n=== REASONING ===\n")
                            f.write("No reasoning content found")
                except Exception as e:
                    f.write(f"\n\n=== REASONING ===\n")
                    f.write(f"Error reading reasoning file: {e}")
            
            f.write(f"\n\n=== RESPONSE ===\n")
            f.write(response)
            f.write(f"\n\n=== END LOG ===\n")
        
        # Simple logging message
        stage_info = f"[{stage}]" if stage else "[unknown]"
        print(f"📝 Logged LLM interaction {stage_info} to: {full_log_file}")
        
        return response
    
    def _supports_reasoning(self) -> bool:
        """Check if the current model supports reasoning extraction."""
        # Only extract reasoning for specific models that support it
        reasoning_models = [
            'deepseek-reasoner',
        ]
        return self.model in reasoning_models
    
    def get_usage_summary(self):
        """Get usage summary."""
        return self.usage_tracker.get_session_summary()
    
    def print_usage_summary(self):
        """Print usage summary."""
        self.usage_tracker.print_session_summary()


class GPTClient(LLMClient):
    """OpenAI GPT client."""
    
    def __init__(self, config: Dict[str, Any], usage_tracker: Optional[APIUsageTracker] = None):
        super().__init__(config, usage_tracker)
        self.client = openai.OpenAI(api_key=config["api_key"], timeout=config.get("timeout", 60),
                                    max_retries=config.get("max_retries", 2))
        self.reasoning_file = None 
    
    def set_reasoning_file(self, reasoning_file: str):
        """Set reasoning content save file path"""
        self.reasoning_file = reasoning_file
    
    def _make_api_call(self, messages: list, **kwargs) -> Dict[str, Any]:
        client = self.client
        
        # Default parameters, can be overridden by kwargs
        params = {'model': self.model, 'messages': messages}
        params.update(kwargs)
        
        # Handle response_format parameter for JSON mode
        if 'response_format' in kwargs and kwargs['response_format'] == 'json':
            params['response_format'] = {'type': 'json_object'}
        
        response = client.chat.completions.create(**params)
        
        # Handle multiple responses if n > 1, otherwise single response
        n = kwargs.get('n', 1)
        if n > 1:
            choices = [{'content': choice.message.content, 'index': choice.index} for choice in response.choices]
            return {'choices': choices, 'usage': {'prompt_tokens': response.usage.prompt_tokens if response.usage else 0, 'completion_tokens': response.usage.completion_tokens if response.usage else 0, 'total_tokens': response.usage.total_tokens if response.usage else 0}}
        else:
            content = response.choices[0].message.content
            return {'content': content, 'usage': {'prompt_tokens': response.usage.prompt_tokens if response.usage else 0, 'completion_tokens': response.usage.completion_tokens if response.usage else 0, 'total_tokens': response.usage.total_tokens if response.usage else 0}}



class DeepSeekClient(LLMClient):
    """DeepSeek client."""
    
    def __init__(self, config: Dict[str, Any], usage_tracker: Optional[APIUsageTracker] = None):
        super().__init__(config, usage_tracker)
        self.api_key = config["api_key"]
        self.base_url = config["api_url"]
        self.client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url,
                                    timeout=config.get("timeout", 60), max_retries=config.get("max_retries", 2))
        self.reasoning_file = None 
    
    def set_reasoning_file(self, reasoning_file: str):
        """Set reasoning content save file path"""
        self.reasoning_file = reasoning_file
    
    def _make_api_call(self, messages: list, **kwargs) -> Dict[str, Any]:
        client = self.client
        
        # Default parameters, can be overridden by kwargs
        params = {'model': self.model, 'messages': messages}
        params.update(kwargs)
        
        # Handle response_format parameter for JSON mode
        if 'response_format' in kwargs and kwargs['response_format'] == 'json':
            params['response_format'] = {'type': 'json_object'}
        
        response = client.chat.completions.create(**params)
        
        # Handle multiple responses if n > 1, otherwise single response
        n = kwargs.get('n', 1)
        if n > 1:
            choices = [{'content': choice.message.content, 'index': choice.index} for choice in response.choices]
            # Extract reasoning only for first choice if supported
            if self._supports_reasoning():
                try:
                    reasoning_content = response.choices[0].message.reasoning_content
                    if self.reasoning_file and reasoning_content:
                        with open(self.reasoning_file, 'w', encoding='utf-8') as f:
                            f.write(reasoning_content)
                except Exception as e:
                    print(f"[DeepSeekClient] Failed to process reasoning: {e}")
            return {'choices': choices, 'usage': {'prompt_tokens': response.usage.prompt_tokens if response.usage else 0, 'completion_tokens': response.usage.completion_tokens if response.usage else 0, 'total_tokens': response.usage.total_tokens if response.usage else 0}}
        else:
            content = response.choices[0].message.content
            # Extract reasoning for supported models
            if self._supports_reasoning():
                try:
                    reasoning_content = response.choices[0].message.reasoning_content
                    if self.reasoning_file and reasoning_content:
                        with open(self.reasoning_file, 'w', encoding='utf-8') as f:
                            f.write(reasoning_content)
                except Exception as e:
                    print(f"[DeepSeekClient] Failed to process reasoning: {e}")
            return {'content': content, 'usage': {'prompt_tokens': response.usage.prompt_tokens if response.usage else 0, 'completion_tokens': response.usage.completion_tokens if response.usage else 0, 'total_tokens': response.usage.total_tokens if response.usage else 0}}


class QwenClient(LLMClient):
    """Alibaba Qwen client."""
    
    def __init__(self, config: Dict[str, Any], usage_tracker: Optional[APIUsageTracker] = None):
        super().__init__(config, usage_tracker)
        self.api_key = config["api_key"]
        self.api_url = config["api_url"]
    
    def _make_api_call(self, messages: list, **kwargs) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        
        # Default parameters, can be overridden by kwargs
        data = {"model": self.model, "messages": messages}
        data.update(kwargs)
        
        resp = requests.post(self.api_url, headers=headers, json=data)
        resp.raise_for_status()
        response_data = resp.json()
        
        # Handle multiple responses if n > 1, otherwise single response
        n = kwargs.get('n', 1)
        if n > 1:
            choices = [{'content': choice['message']['content'], 'index': choice.get('index', i)} for i, choice in enumerate(response_data['choices'])]
            return {'choices': choices, 'usage': response_data.get('usage', {})}
        else:
            return {'content': response_data['choices'][0]['message']['content'], 'usage': response_data.get('usage', {})}


class DummyLLMClient(LLMClient):
    """A dummy LLM client for testing/debugging without real API calls."""
    def __init__(self, config=None, usage_tracker=None):
        super().__init__(config or {"type": "dummy", "model": "dummy"}, usage_tracker)
    def _make_api_call(self, messages: list, **kwargs) -> dict:
        # Handle multiple responses if n > 1, otherwise single response
        n = kwargs.get('n', 1)
        if n > 1:
            choices = [{'content': f'Dummy response #{i+1}: {{"reachable": true, "probability": 1.0}}', 'index': i} for i in range(n)]
            return {'choices': choices, 'usage': {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        else:
            return {"content": '{"reachable": true, "probability": 1.0, "reasoning": "Dummy LLM: always reachable."}', "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def get_llm_client(config: Dict[str, Any], usage_tracker: Optional[APIUsageTracker] = None) -> LLMClient:
    """Factory function to create LLM client based on config."""
    if config["type"] == "gpt":
        return GPTClient(config, usage_tracker)
    elif config["type"] == "deepseek":
        return DeepSeekClient(config, usage_tracker)
    elif config["type"] == "qwen":
        return QwenClient(config, usage_tracker)
    elif config["type"] == "dummy":
        return DummyLLMClient(config, usage_tracker)
    else:
        raise ValueError(f"Unknown model type: {config['type']}") 