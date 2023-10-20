package io.tolgee.security.third_party

import io.tolgee.configuration.tolgee.DiscordAuthenticationProperties
import io.tolgee.configuration.tolgee.GithubAuthenticationProperties
import io.tolgee.configuration.tolgee.TolgeeProperties
import io.tolgee.constants.Message
import io.tolgee.exceptions.AuthenticationException
import io.tolgee.model.Invitation
import io.tolgee.model.UserAccount
import io.tolgee.security.authentication.JwtService
import io.tolgee.security.payload.JwtAuthenticationResponse
import io.tolgee.service.InvitationService
import io.tolgee.service.security.UserAccountService
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestTemplate

@Component
class DiscordOAuthDelegate(
  private val jwtService: JwtService,
  private val userAccountService: UserAccountService,
  private val restTemplate: RestTemplate,
  private val properties: TolgeeProperties,
  private val invitationService: InvitationService
) {
  private val discordConfigurationProperties: DiscordAuthenticationProperties = properties.authentication.discord

fun getTokenResponse(
    receivedCode: String?,
    invitationCode: String?,
    redirectUri: String?
  ): JwtAuthenticationResponse {
    try {
      val body: MultiValueMap<String, String> = LinkedMultiValueMap<String, String>()
      body["client_id"] = discordConfigurationProperties.clientId
      body["client_secret"] = discordConfigurationProperties.clientSecret
      body["code"] = receivedCode
      body["grant_type"] = "authorization_code"
      body["redirect_uri"] = redirectUri

      val requestHeaders = HttpHeaders()
      requestHeaders.contentType = MediaType.APPLICATION_FORM_URLENCODED

      // get token to authorize to discord api
      val response: MutableMap<*, *>? = restTemplate
          .postForObject(discordConfigurationProperties.authorizationUrl, HttpEntity(body, requestHeaders), MutableMap::class.java)
      if (response != null && response.containsKey("access_token")) {
        val headers = HttpHeaders()
        headers["Authorization"] = "Bearer " + response["access_token"]
        val entity = HttpEntity<String?>(null, headers)

        // get discord user data

        val exchange = restTemplate
          .exchange(discordConfigurationProperties.userUrl, HttpMethod.GET, entity, DiscordUserResponse::class.java)
        if (exchange.statusCode != HttpStatus.OK || exchange.body == null) {
          throw AuthenticationException(Message.THIRD_PARTY_UNAUTHORIZED)
        }
        val userResponse = exchange.body

        // ensure that only Google Workspace users can log in
//        if (!googleConfigurationProperties.workspaceDomain.isNullOrEmpty()) {
//          if (userResponse.hd != googleConfigurationProperties.workspaceDomain) {
//            throw AuthenticationException(Message.THIRD_PARTY_GOOGLE_WORKSPACE_MISMATCH)
//          }
//        }

        val discordEmail = userResponse?.email ?: throw AuthenticationException(Message.THIRD_PARTY_AUTH_NO_EMAIL)

        val userAccountOptional = userAccountService.findByThirdParty("discord", userResponse.id!!)
        val user = userAccountOptional.orElseGet {
          userAccountService.findActive(discordEmail)?.let {
            throw AuthenticationException(Message.USERNAME_ALREADY_EXISTS)
          }

          var invitation: Invitation? = null
          if (invitationCode == null) {
            if (!properties.authentication.registrationsAllowed) {
              throw AuthenticationException(Message.REGISTRATIONS_NOT_ALLOWED)
            }
          } else {
            invitation = invitationService.getInvitation(invitationCode)
          }

          val newUserAccount = UserAccount()
          newUserAccount.username = userResponse.email
            ?: throw AuthenticationException(Message.THIRD_PARTY_AUTH_NO_EMAIL)
          newUserAccount.name = userResponse.global_name ?: "${userResponse.username}${if (userResponse.discriminator != "0") "#${userResponse.discriminator}" else ""}"
          newUserAccount.thirdPartyAuthId = userResponse.id
          newUserAccount.thirdPartyAuthType = "discord"
          newUserAccount.accountType = UserAccount.AccountType.THIRD_PARTY
          userAccountService.createUser(newUserAccount)
          if (invitation != null) {
            invitationService.accept(invitation.code, newUserAccount)
          }

          newUserAccount
        }
        val jwt = jwtService.emitToken(user.id)
        return JwtAuthenticationResponse(jwt)
      }
      if (response == null) {
        throw AuthenticationException(Message.THIRD_PARTY_AUTH_UNKNOWN_ERROR)
      }

      if (response.containsKey("error")) {
        throw AuthenticationException(Message.THIRD_PARTY_AUTH_ERROR_MESSAGE)
      }
    println("Unknown error")
      throw AuthenticationException(Message.THIRD_PARTY_AUTH_UNKNOWN_ERROR)
    } catch (e: HttpClientErrorException) {
        println(e)
      throw AuthenticationException(Message.THIRD_PARTY_AUTH_UNKNOWN_ERROR)
    }
  }

  class DiscordUserResponse {
    var id: String? = null
    var username: String? = null
    var discriminator: String? = null
    var global_name: String? = null
    var locale: String? = null
    var email: String? = null
  }
}
