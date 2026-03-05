"""ClawMoat security integration for LangChain.

Provides callback handlers that scan prompts, tool calls, and outputs
for security threats in real-time.

Usage:
    from clawmoat_langchain import ClawMoatCallbackHandler

    handler = ClawMoatCallbackHandler(base_url="http://localhost:8080")
    chain = my_chain.with_config(callbacks=[handler])
"""

from clawmoat_langchain.callback import ClawMoatCallbackHandler
from clawmoat_langchain.callback import ClawMoatAsyncCallbackHandler

__all__ = ["ClawMoatCallbackHandler", "ClawMoatAsyncCallbackHandler"]
__version__ = "0.1.0"
