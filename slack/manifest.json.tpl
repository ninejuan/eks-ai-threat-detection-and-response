{
  "display_information": {
    "name": "ATDR",
    "description": "AI Threat Detection and Response for EKS",
    "background_color": "#1a1a2e"
  },
  "features": {
    "app_home": {
      "home_tab_enabled": true,
      "messages_tab_enabled": true,
      "messages_tab_read_only_enabled": false
    },
    "bot_user": {
      "display_name": "ATDR Bot",
      "always_online": true
    },
    "shortcuts": [
      {
        "name": "View ATDR Status",
        "type": "global",
        "callback_id": "atdr_view_status",
        "description": "Open the ATDR system status view"
      },
      {
        "name": "Acknowledge ATDR Incident",
        "type": "global",
        "callback_id": "atdr_ack_incident",
        "description": "Acknowledge an incident by ID"
      }
    ],
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
        "app_home_opened",
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
