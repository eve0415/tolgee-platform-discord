package io.tolgee.dtos.cacheable

import io.tolgee.model.UserAccount
import java.io.Serializable
import java.util.Date

data class UserAccountDto(
  val name: String,
  val username: String,
  val role: UserAccount.Role?,
  val id: Long,
  val needsSuperJwt: Boolean,
  val avatarHash: String?,
  val deleted: Boolean,
  val tokensValidNotBefore: Date?,
) : Serializable {
  companion object {
    fun fromEntity(entity: UserAccount) = UserAccountDto(
      name = entity.name,
      username = entity.username,
      role = entity.role,
      id = entity.id,
      needsSuperJwt = entity.needsSuperJwt,
      avatarHash = entity.avatarHash,
      deleted = entity.deletedAt != null,
      tokensValidNotBefore = entity.tokensValidNotBefore,
    )
  }

  override fun toString(): String {
    return username
  }
}
