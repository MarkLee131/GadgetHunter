import os
import json
import logging

# Optional path to a JDK source tree (parent of jdk8u/jdk/src/share/classes).
# Used by file_locator to resolve JDK class sources; lookup is skipped when unset.
JDK_DIR = os.environ.get("GADGETHUNTER_JDK_DIR")

USE_EARLY_STOPPING = True


class Config:
    def __init__(self):
        self.project_path = None
        self.project_name = None
        self.llm_type = "gpt"
        self.llm_model = "gpt-4.1"
        self.llm_api_url = "https://api.openai.com/v1/chat/completions"
        self.max_chains = 10
        self.output_dir = "results"
        self.debug = os.environ.get("DEBUG", "0") == "1"
        self.extract_javadoc = os.environ.get("EXTRACT_JAVADOC", "1") == "1"
        # API keys from environment variables
        self.openai_api_key = os.environ.get("OPENAI_API_KEY")
        self.deepseek_api_key = os.environ.get("DEEPSEEK_API_KEY")
        self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
        # JDK home for analysed targets. Caller must set GADGETHUNTER_JAVA_HOME.
        self.java_home = os.environ.get("GADGETHUNTER_JAVA_HOME")

    def set_debug(self, debug_flag: bool):
        self.debug = debug_flag
    
    def set_project_info(self, project_path: str = None, project_name: str = None):
        """Set project path and name"""
        if project_path:
            self.project_path = project_path
            # If project name is not provided, extract it from the path
            if not project_name:
                self.project_name = os.path.basename(project_path.rstrip('/'))
            else:
                self.project_name = project_name
        elif project_name:
            self.project_name = project_name

    def configure_logging(self):
        if self.debug:
            logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
        else:
            logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    def get_llm_config(self):
        # Select api_key based on llm_type
        api_key = None
        if self.llm_type == "gpt":
            api_key = self.openai_api_key
            self.llm_api_url = "https://api.openai.com/v1/chat/completions"
        elif self.llm_type == "deepseek":
            api_key = self.deepseek_api_key
            self.llm_api_url = "https://api.deepseek.com"
        
        elif self.llm_type == "claude":
            api_key = self.anthropic_api_key
            self.llm_api_url = "https://api.anthropic.com/v1/messages"
        
        else:
            raise ValueError(f"Unsupported LLM type: {self.llm_type}")
        
        return {
            "api_key": api_key,
            "type": self.llm_type,
            "model": self.llm_model,
            "api_url": self.llm_api_url,
        }

    def get_joern_addr(self):
        return getattr(self, 'joern_addr', None)

def load_config(path):
    """Load config from a JSON file (optional, fallback to default Config)."""
    if not os.path.exists(path):
        return Config()
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    config = Config()
    for k, v in data.items():
        setattr(config, k, v)
    # Ensure extract_javadoc field exists
    if not hasattr(config, 'extract_javadoc'):
        config.extract_javadoc = True
    return config

def create_default_config(path):
    """Create a default config file."""
    config = Config()
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(config.__dict__, f, ensure_ascii=False, indent=2) 