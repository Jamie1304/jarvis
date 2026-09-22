# R3H standard provider catalog

The catalog is defined by `jarvis.ai.providers.catalog.STANDARD_PROVIDER_MANIFESTS`.
It contains package manifests for the canonical direct, gateway, regional,
enterprise, decision, and OpenAI-compatible families:

| Family | Package IDs |
| --- | --- |
| Direct | `openai`, `anthropic`, `google-gemini`, `xai-grok`, `mistral`, `deepseek`, `cohere`, `ai21` |
| Decision | `typesafe-jev` |
| Gateways | `openrouter`, `groqcloud`, `together-ai`, `fireworks-ai`, `cerebras-cloud`, `sambanova-cloud`, `nvidia-nim`, `perplexity` |
| Regional/ecosystem | `alibaba-dashscope`, `moonshot-kimi`, `zhipu-glm`, `minimax`, `baidu-qianfan`, `tencent-hunyuan`, `bytedance-volcengine` |
| Enterprise | `azure-openai`, `amazon-bedrock`, `google-vertex` |
| Generic | `openai-compatible` |

OpenAI-shaped packages share `OpenAICompatibleProvider` where their official
protocol permits it; native packages retain their own adapter boundary.
Provider help, setup fields, authentication type, discovery capability, and
physical support status remain package metadata rather than Core UI constants.

The current catalog deliberately does not embed model IDs or prices. Those are
dynamic observations with provenance and freshness. Real credentials and
external network calls are outside the development test contract.
