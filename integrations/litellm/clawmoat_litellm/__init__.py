"""ClawMoat security integration for LiteLLM proxy.

Provides transparent security scanning for all models and providers
behind a LiteLLM proxy gateway without requiring application changes.

Usage:
    # In litellm_config.yaml
    litellm_settings:
      callbacks: ["clawmoat_litellm.ClawMoatCallback"]
      
    # Or programmatically
    from clawmoat_litellm import ClawMoatCallback
    import litellm
    litellm.callbacks = [ClawMoatCallback()]
"""

from clawmoat_litellm.callback import ClawMoatCallback
from clawmoat_litellm.proxy_middleware import ClawMoatProxyMiddleware

__all__ = ["ClawMoatCallback", "ClawMoatProxyMiddleware"]
__version__ = "0.1.0"