"""Environment-based configuration for oh-red-agent."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Config:
    # vLLM / Gemma4 (abliterated)
    vllm_base_url: str = os.environ.get("VLLM_BASE_URL", "http://localhost:8000/v1")
    vllm_model: str = os.environ.get("VLLM_MODEL", "gemma4")
    vllm_api_key: str = os.environ.get("VLLM_API_KEY", "none")
    vllm_temperature: float = float(os.environ.get("VLLM_TEMPERATURE", "0.2"))
    vllm_verify_ssl: bool = os.environ.get("VLLM_VERIFY_SSL", "false").lower() in ("true", "1")

    # Kafka
    kafka_host: str = os.environ.get("KAFKA_HOST", "")
    kafka_port: int = int(os.environ.get("KAFKA_PORT", "9094"))
    kafka_username: str = os.environ.get("KAFKA_USERNAME", "")
    kafka_password: str = os.environ.get("KAFKA_PASSWORD", "")

    # Kali sandbox
    kali_api_url: str = os.environ.get("KALI_API_URL", "http://kali-server:48081")
    kali_api_token: str = os.environ.get("KALI_API_TOKEN", "")

    # FortiSOAR
    fortisoar_url: str = os.environ.get("FORTISOAR_URL", "")
    fortisoar_public_key_file: str = os.environ.get("FORTISOAR_PUBLIC_KEY_FILE", "")
    fortisoar_private_key_file: str = os.environ.get("FORTISOAR_PRIVATE_KEY_FILE", "")
    fortisoar_verify_ssl: bool = os.environ.get("FORTISOAR_VERIFY_SSL", "false").lower() in ("true", "1")

    # NetBox
    netbox_api_url: str = os.environ.get("NETBOX_API_URL", "")
    netbox_api_token: str = os.environ.get("NETBOX_API_TOKEN", "")
    netbox_verify_ssl: bool = os.environ.get("NETBOX_VERIFY_SSL", "false").lower() in ("true", "1")

    # Agent behaviour
    max_tool_rounds: int = int(os.environ.get("MAX_TOOL_ROUNDS", "12"))
    concurrent_ips: int = int(os.environ.get("CONCURRENT_IPS", "3"))
    enable_fortisoar: bool = os.environ.get("ENABLE_FORTISOAR", "false").lower() in ("true", "1")
    kafka_time_window_hours: int = int(os.environ.get("KAFKA_TIME_WINDOW_HOURS", "26"))


config = Config()
