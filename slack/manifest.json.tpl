{
  "display_information": {
    "name": "ATDR",
    "description": "AI Threat Detection and Response for EKS",
    "background_color": "#1a1a2e"
  },
  "features": {
    "bot_user": {
      "display_name": "ATDR Bot",
      "always_online": true
    },
    "slash_commands": [
      {
        "command": "/atdr",
        "url": "${SLACK_API_URL}/slack/commands",
        "description": "ATDR security operations",
        "usage_hint": "status | incidents [open|P1] | incident <id> | ack <id> | resolve <id> | oncall | report daily | ioc <id> | evidence <id> | help"
      }
    ]
  },
  "oauth_config": {
    "scopes": {
      "bot": [
        "app_mentions:read",
        "chat:write",
        "commands",
        "im:history",
        "im:read",
        "im:write",
        "incoming-webhook",
        "channels:history"
      ]
    }
  },
  "settings": {
    "event_subscriptions": {
      "request_url": "${SLACK_API_URL}/slack/events",
      "bot_events": [
        "app_mention",
        "message.channels",
        "message.im"
      ]
    },
    "interactivity": {
      "is_enabled": true,
      "request_url": "${SLACK_API_URL}/slack/interactions"
    },
    "org_deploy_enabled": false,
    "socket_mode_enabled": false
  }
}
