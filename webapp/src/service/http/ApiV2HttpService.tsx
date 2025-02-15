import { singleton } from 'tsyringe';

import { RedirectionActions } from 'tg.store/global/RedirectionActions';

import { TokenService } from '../TokenService';
import { ApiV1HttpService } from './ApiV1HttpService';

@singleton()
export class ApiV2HttpService extends ApiV1HttpService {
  constructor(
    tokenService: TokenService,
    redirectionActions: RedirectionActions
  ) {
    super(tokenService, redirectionActions);
  }

  apiUrl = process.env.REACT_APP_API_URL + '/v2/';
}
