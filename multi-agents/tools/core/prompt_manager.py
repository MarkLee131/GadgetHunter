"""
Prompt Manager
Advanced prompt management with version control, templating, and better organization
"""

import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum


class PromptType(Enum):
    """Types of prompts"""
    SEMANTIC_ANALYSIS = "semantic_analysis"
    REACHABILITY_ANALYSIS = "reachability_analysis"
    CODE_SUMMARY = "code_summary"
    Z3_FIXING = "z3_fixing"
    Z3_GENERATION = "z3_generation"


@dataclass
class PromptTemplate:
    """Represents a prompt template"""
    name: str
    prompt_type: PromptType
    version: str
    system_prompt: str
    user_template: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def build_prompt(self, **kwargs) -> str:
        """Build prompt with placeholders"""
        prompt = self.user_template
        
        # Replace placeholders
        for key, value in kwargs.items():
            placeholder = f"{{{key}}}"
            prompt = prompt.replace(placeholder, str(value))
        
        return prompt


class PromptManager:
    """
    Unified prompt manager with version control and templating
    """
    
    def __init__(self, prompts_dir: str = None):
        """
        Initialize unified prompt manager
        
        Args:
            prompts_dir: Directory containing prompt templates
        """
        if prompts_dir is None:
            # prompts directory is at the same level as tools directory (in multi-agents root)
            current_dir = Path(__file__).parent.parent.parent  # Go up to multi-agents directory
            prompts_dir = current_dir / "prompts"
        
        self.prompts_dir = Path(prompts_dir)
        self.templates: Dict[str, PromptTemplate] = {}
        self.version_cache: Dict[str, str] = {}
        
        # Load all templates
        self._load_templates()
    
    def _load_templates(self):
        """Load all prompt templates"""
        # Define template mappings
        template_files = {
            "reachability_analyzer": {
                "file": "reachability_analyzer.txt", 
                "type": PromptType.REACHABILITY_ANALYSIS,
                "version": "1.0"
            },
            "code_summarizer": {
                "file": "code_summarizer.txt",
                "type": PromptType.CODE_SUMMARY,
                "version": "1.0"
            },
            "z3_fixer": {
                "file": "z3_fixer.txt",
                "type": PromptType.Z3_FIXING,
                "version": "1.0"
            },
            "z3_script_generator": {
                "file": "z3_script_generator.txt",
                "type": PromptType.Z3_GENERATION,
                "version": "1.0"
            },
            "deserialization_auditor": {
                "file": "deserialization_auditor.txt",
                "type": PromptType.CODE_SUMMARY,  # Reuse existing type
                "version": "1.0"
            },

        }
        
        for name, config in template_files.items():
            file_path = self.prompts_dir / config["file"]
            if file_path.exists():
                try:
                    template = self._load_template_from_file(name, file_path, config)
                    self.templates[name] = template
                    self.version_cache[name] = config["version"]
                    print(f"✅ Loaded template: {name} v{config['version']}")
                except Exception as e:
                    print(f"⚠️ Failed to load template {name}: {e}")
            else:
                print(f"⚠️ Template file not found: {file_path}")
    
    def _load_template_from_file(self, name: str, file_path: Path, config: Dict[str, Any]) -> PromptTemplate:
        """Load template from file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse content to extract system and user prompts
        system_prompt, user_template = self._parse_prompt_content(content)
        
        return PromptTemplate(
            name=name,
            prompt_type=config["type"],
            version=config["version"],
            system_prompt=system_prompt,
            user_template=user_template,
            description=f"Template for {name}",
            tags=[config["type"].value]
        )
    
    def _parse_prompt_content(self, content: str) -> tuple[str, str]:
        """Parse prompt content to extract system and user parts"""
        # Look for <SYSTEM> section
        system_match = re.search(r'<SYSTEM>\s*(.*?)\s*</SYSTEM>', content, re.DOTALL)
        system_prompt = system_match.group(1).strip() if system_match else "You are an expert Java code analyzer."
        
        # Extract user template (everything except <SYSTEM> section, but keep other XML tags)
        if system_match:
            # Remove only the <SYSTEM> section from content, keep all other XML tags
            user_template = content[:system_match.start()] + content[system_match.end():]
        else:
            user_template = content.strip()
        
        # Keep user template as-is, don't remove XML tags like <TASK>, <INPUT>, <OUTPUT_FORMAT>
        user_template = user_template.strip()
        
        return system_prompt, user_template
    
    def get_template(self, name: str) -> Optional[PromptTemplate]:
        """Get template by name"""
        return self.templates.get(name)
    
    def get_system_prompt(self, template_name: str) -> str:
        """Get system prompt for template"""
        template = self.get_template(template_name)
        return template.system_prompt if template else "You are an expert Java code analyzer."
    
    def build_prompt(self, template_name: str, **kwargs) -> str:
        """Build prompt with placeholders"""
        template = self.get_template(template_name)
        if not template:
            raise ValueError(f"Template not found: {template_name}")
        
        return template.build_prompt(**kwargs)
    
    def build_reachability_prompt(self,
                                from_code: str,
                                # to_code: str,
                                method_context: str = "Unknown method",
                                # call_info: str = "No call information",
                                **kwargs) -> str:
        """Build reachability analysis prompt"""
        return self.build_prompt("reachability_analyzer",
                               FROM_CODE=from_code,
                            #    TO_CODE=to_code,
                               METHOD_CONTEXT=method_context,
                            #    CALL_INFO=call_info, // deprecated, since this info was we constructed. e.g, "llm_required"
                               **kwargs)
    

    
    def build_z3_fixing_prompt(self,
                              z3_script: str,
                              error_message: str,
                              **kwargs) -> str:
        """Build Z3 fixing prompt"""
        return self.build_prompt("z3_fixer",
                               Z3_SCRIPT=z3_script,
                               ERROR_MESSAGE=error_message,
                               **kwargs)
    
    def build_z3_script_generator_prompt(self,
                                       constraints_details: str,
                                       **kwargs) -> str:
        """Build Z3 script generator prompt for template filling"""
        return self.build_prompt("z3_script_generator",
                               CONSTRAINTS_DETAILS=constraints_details,
                               **kwargs)
    
    def build_z3_fixer_prompt(self,
                             original_script: str,
                             execution_error: str,
                             stderr_output: str = "",
                             **kwargs) -> str:
        """Build Z3 fixer prompt (compatibility wrapper)"""
        # Map to the correct template parameters
        return self.build_prompt("z3_fixer",
                               ORIGINAL_SCRIPT=original_script,
                               EXECUTION_ERROR=execution_error,
                               STDERR_OUTPUT=stderr_output,
                               **kwargs)
    
    def build_validation_prompt(self, chain_text: str, reachable: str, 
                               detailed_analysis: str) -> str:
        """Build validation prompt"""
        return self.build_prompt("validation_analyzer", 
                               CHAIN_TEXT=chain_text,
                               REACHABLE=reachable,
                               DETAILED_ANALYSIS=detailed_analysis)
    

    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available templates"""
        return [
            {
                "name": name,
                "type": template.prompt_type.value,
                "version": template.version,
                "description": template.description,
                "tags": template.tags
            }
            for name, template in self.templates.items()
        ]
    
    def get_template_info(self, template_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed template information"""
        template = self.get_template(template_name)
        if not template:
            return None
        
        return {
            "name": template.name,
            "type": template.prompt_type.value,
            "version": template.version,
            "description": template.description,
            "tags": template.tags,
            "system_prompt": template.system_prompt,
            "user_template": template.user_template,
            "metadata": template.metadata
        }
    
    def validate_template(self, template_name: str) -> Dict[str, Any]:
        """Validate template structure and placeholders"""
        template = self.get_template(template_name)
        if not template:
            return {"valid": False, "error": "Template not found"}
        
        # Extract placeholders from user template
        placeholders = re.findall(r'\{(\w+)\}', template.user_template)
        
        return {
            "valid": True,
            "placeholders": placeholders,
            "template_type": template.prompt_type.value,
            "version": template.version
        }


# Global instance
_prompt_manager = None


def get_prompt_manager() -> PromptManager:
    """Get global unified prompt manager instance"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager(prompts_dir=Path(__file__).parent.parent.parent / "prompts")
    return _prompt_manager 