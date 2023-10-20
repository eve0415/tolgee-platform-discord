package io.tolgee.configuration.tolgee

import io.tolgee.configuration.annotations.DocProperty
import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "tolgee.authentication.discord")
@DocProperty(
  description = ":::info\n" +
    "Discord authentication can be used in combination with native authentication.\n" +
    ":::",
  displayName = "Discord"
)
class DiscordAuthenticationProperties {
  @DocProperty(description = "OAuth Client ID, obtained in Discord Developer Portal.")
  var clientId: String? = null

  @DocProperty(description = "OAuth Client secret, obtained in Discord Developer Portal.")
  var clientSecret: String? = null

  @DocProperty(description = "URL to Discord `/token` API endpoint. This usually does not need to be changed.")
  var authorizationUrl: String = "https://discord.com/api/oauth2/token"

  @DocProperty(description = "URL to Discord `/user/@me` API endpoint. This usually does not need to be changed.")
  var userUrl: String = "https://discord.com/api/v10/users/@me"
}
