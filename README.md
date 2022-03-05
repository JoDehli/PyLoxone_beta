# PyLoxone Beta only for development

# TODO
- [ ] Test if it is stable over a long time. Is reconnecting successful?
- [ ] Remove the numpy dependencies and interpolate with own function.
- [ ] Remove the httpx dependency and use aiohttp only
- [ ] Test if the gen2 is working

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
