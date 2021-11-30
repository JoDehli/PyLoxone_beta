# PyLoxone Beta only for development

## Config for Dev

```yaml
# Configure a default setup of Home Assistant (frontend, api, etc)
default_config:

# Text to speech
tts:
  - platform: google_translate

group: !include groups.yaml
automation: !include automations.yaml
script: !include scripts.yaml
scene: !include scenes.yaml

logger:
  default: critical
  logs:
    httpx: critical
    homeassistant: critical
    custom_components.loxone.pyloxone_api.api: debug
```
