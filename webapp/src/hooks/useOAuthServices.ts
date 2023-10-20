import { useConfig } from 'tg.globalContext/helpers';
import {
  discordService,
  gitHubService,
  googleService,
  oauth2Service,
  OAuthService,
} from 'tg.component/security/OAuthService';

export const useOAuthServices = () => {
  const remoteConfig = useConfig();

  const oAuthServices: OAuthService[] = [];
  const githubConfig = remoteConfig.authMethods?.github;
  const googleConfig = remoteConfig.authMethods?.google;
  const discordConfig = remoteConfig.authMethods?.discord;
  const oauth2Config = remoteConfig.authMethods?.oauth2;
  if (githubConfig?.enabled && githubConfig.clientId) {
    oAuthServices.push(gitHubService(githubConfig.clientId));
  }
  if (googleConfig?.enabled && googleConfig.clientId) {
    oAuthServices.push(googleService(googleConfig.clientId));
  }
  if (discordConfig?.enabled && discordConfig.clientId) {
    oAuthServices.push(discordService(discordConfig.clientId, discordConfig.scopes));
  }
  if (
    oauth2Config?.enabled &&
    oauth2Config?.clientId &&
    oauth2Config.scopes &&
    oauth2Config?.authorizationUrl
  ) {
    oAuthServices.push(
      oauth2Service(
        oauth2Config.clientId,
        oauth2Config.authorizationUrl,
        oauth2Config.scopes
      )
    );
  }
  return oAuthServices;
};
