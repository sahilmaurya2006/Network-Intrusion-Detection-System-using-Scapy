# nids/utils/config_loader.py
"""
Configuration loader module.
Handles YAML/JSON configuration parsing and validation.
Implements environment variable substitution and schema validation.
"""

import os
import json
import yaml
from typing import Any, Dict, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ConfigLoader:
    """
    Loads and parses NIDS configuration files.
    
    Supports:
    - YAML and JSON configuration files
    - Environment variable substitution (${ENV_VAR})
    - Configuration validation
    - Default value handling
    """
    
    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration loader.
        
        Args:
            config_path: Path to configuration file. If None, uses default path.
            
        Raises:
            FileNotFoundError: If configuration file doesn't exist.
            ValueError: If configuration file format is invalid.
        """
        self.config_path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """
        Load and parse configuration file.
        
        Raises:
            FileNotFoundError: If config file not found.
            ValueError: If config file format is invalid.
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                if self.config_path.suffix.lower() == '.yaml':
                    self.config = yaml.safe_load(f) or {}
                elif self.config_path.suffix.lower() == '.json':
                    self.config = json.load(f)
                else:
                    raise ValueError(f"Unsupported config format: {self.config_path.suffix}")
            
            # Substitute environment variables
            self._substitute_env_vars()
            logger.info(f"Configuration loaded from {self.config_path}")
            
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid configuration file format: {e}")
    
    def _substitute_env_vars(self) -> None:
        """
        Recursively substitute environment variables in configuration.
        Looks for ${VAR_NAME} patterns and replaces with environment values.
        """
        def substitute(obj: Any) -> Any:
            if isinstance(obj, str):
                # Pattern: ${ENV_VAR_NAME}
                import re
                pattern = r'\$\{([^}]+)\}'
                def replace_env(match):
                    env_var = match.group(1)
                    value = os.environ.get(env_var, "")
                    if not value:
                        logger.warning(f"Environment variable not set: {env_var}")
                    return value
                return re.sub(pattern, replace_env, obj)
            elif isinstance(obj, dict):
                return {k: substitute(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [substitute(item) for item in obj]
            return obj
        
        self.config = substitute(self.config)
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key.
        
        Args:
            key: Configuration key (e.g., "detection.icmp_flood.threshold")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
            
        Example:
            >>> config.get("detection.icmp_flood.threshold")
            100
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.
        
        Args:
            section: Section name (e.g., "detection", "alerting")
            
        Returns:
            Dictionary containing the section configuration
        """
        return self.config.get(section, {})
    
    def validate(self) -> bool:
        """
        Validate configuration completeness.
        
        Returns:
            True if configuration is valid, raises exception otherwise
        """
        required_sections = ['system', 'sniffer', 'detection', 'alerting', 'logging']
        
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Validate detection thresholds are positive integers
        detection = self.config.get('detection', {})
        for rule_name, rule_config in detection.items():
            if isinstance(rule_config, dict):
                if 'threshold' in rule_config and rule_config['threshold'] <= 0:
                    raise ValueError(
                        f"Invalid threshold for {rule_name}: must be positive integer"
                    )
                if 'time_window' in rule_config and rule_config['time_window'] <= 0:
                    raise ValueError(
                        f"Invalid time_window for {rule_name}: must be positive integer"
                    )
        
        return True
    
    def reload(self) -> None:
        """Reload configuration from file."""
        self._load_config()
    
    def to_dict(self) -> Dict[str, Any]:
        """Return entire configuration as dictionary."""
        return self.config.copy()
