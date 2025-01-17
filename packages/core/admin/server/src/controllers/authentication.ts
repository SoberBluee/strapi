import type { Context, Next } from 'koa';
import passport from 'koa-passport';
import compose from 'koa-compose';
import '@strapi/types';
import { errors } from '@strapi/utils';
import { getService } from '../utils';
import {
  validateRegistrationInput,
  validateAdminRegistrationInput,
  validateRegistrationInfoQuery,
  validateForgotPasswordInput,
  validateMultiFactorAuthenticationInput,
  validateResetPasswordInput,
  validateRenewTokenInput,
} from '../validation/authentication';

import type {
  ForgotPassword,
  Login,
  Register,
  RegistrationInfo,
  RenewToken,
  ResetPassword,
} from '../../../shared/contracts/authentication';
import { AdminUser } from '../../../shared/contracts/shared';

const { ApplicationError, ForbiddenError, ValidationError } = errors;

export default {
  login: compose([
    (ctx: Context, next: Next) => {
      const advanced = await strapi.store({type: 'plugin', name: 'users-permissions', key: 'advanced'}).get();
      return passport.authenticate('local', {session: false}, (err, user, info) => {
        if (err) {
          strapi.eventHub.emit('admin.auth.error', {error: err, provider: 'local'});
          // if this is a recognized error, allow it to bubble up to user
          if (err.details?.code === 'LOGIN_NOT_ALLOWED') {
            throw err;
          }

          // for all other errors throw a generic error to prevent leaking info
          return ctx.notImplemented();
        }

        if (!user) {
          strapi.eventHub.emit('admin.auth.error', {
            error: new Error(info.message),
            provider: 'local',
          });
          throw new ApplicationError(info.message);
        }

        const query = ctx.state as Login.Request['query'];
        query.user = user;

        const sanitizedUser = getService('user').sanitizeUser(user);
        // Multi factor authentication setting check
        if (advanced.multi_factor_authentication) {
          // Generate 6 digit code
          const verificationCode = getService('token').createVerificationToken();
          getService('auth').sendMultiFactorAuthenticationEmail({
            user: sanitizedUser,
            code: verificationCode
          });

          // Store the verification code and user information in the session for verification later
          ctx.session.verificationCode = verificationCode;
          ctx.session.user = user;
        } else {
          strapi.eventHub.emit('admin.auth.success', {user: sanitizedUser, provider: 'local'});
        }
        return next();
      })(ctx);
    },
    async (ctx) => {
      const advanced = await strapi.store({type: 'plugin', name: 'users-permissions', key: 'advanced'}).get();
      const {user} = ctx.state as { user: AdminUser };

      ctx.body = {
        data: {
          token: null,
          user: getService('user').sanitizeUser(user), // TODO: fetch more detailed info,
          mfa: advanced.multi_factor_authentication
        },
      } satisfies Login.Response;
      ctx.session.rememberMe = ctx.request?.body?.rememberMe
    },
  ]),

  async renewToken(ctx: Context) {
    await validateRenewTokenInput(ctx.request.body);

    const { token } = ctx.request.body as RenewToken.Request['body'];

    const { isValid, payload } = getService('token').decodeJwtToken(token);

    if (!isValid) {
      throw new ValidationError('Invalid token');
    }

    ctx.body = {
      data: {
        token: getService('token').createJwtToken({ id: payload.id }),
      },
    } satisfies RenewToken.Response;
  },

  async registrationInfo(ctx: Context) {
    await validateRegistrationInfoQuery(ctx.request.query);

    const { registrationToken } = ctx.request.query as RegistrationInfo.Request['query'];

    const registrationInfo = await getService('user').findRegistrationInfo(registrationToken);

    if (!registrationInfo) {
      throw new ValidationError('Invalid registrationToken');
    }

    ctx.body = { data: registrationInfo } satisfies RegistrationInfo.Response;
  },

  async register(ctx: Context) {
    const input = ctx.request.body as Register.Request['body'];

    await validateRegistrationInput(input);

    const user = await getService('user').register(input);

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    } satisfies Register.Response;
  },

  async registerAdmin(ctx: Context) {
    const input = ctx.request.body as Register.Request['body'];

    await validateAdminRegistrationInput(input);

    const hasAdmin = await getService('user').exists();

    if (hasAdmin) {
      throw new ApplicationError('You cannot register a new super admin');
    }

    const superAdminRole = await getService('role').getSuperAdmin();

    if (!superAdminRole) {
      throw new ApplicationError(
        "Cannot register the first admin because the super admin role doesn't exist."
      );
    }

    const user = await getService('user').create({
      ...input,
      registrationToken: null,
      isActive: true,
      roles: superAdminRole ? [superAdminRole.id] : [],
    });

    strapi.telemetry.send('didCreateFirstAdmin');

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    };
  },

  async forgotPassword(ctx: Context) {
    const input = ctx.request.body as ForgotPassword.Request['body'];

    await validateForgotPasswordInput(input);

    getService('auth').forgotPassword(input);

    ctx.status = 204;
  },

  async multiFactorAuthentication(ctx) {
    const input = ctx.request.body;
    await validateMultiFactorAuthenticationInput(input);
    if (input.code !== Number(ctx.session.verificationCode)) {
      // Throw forbidden error if verification code is incorrect
      throw new ForbiddenError("Verification code is incorrect");
    } else {
      // Set token if valid
      ctx.body = {
        data: {
          token: getService('token').createJwtToken(ctx.session.user),
          rememberMe: ctx.session.rememberMe
        },
      };
    }
  },

  async resetPassword(ctx: Context) {
    const input = ctx.request.body as ResetPassword.Request['body'];

    await validateResetPasswordInput(input);

    const user = await getService('auth').resetPassword(input);

    ctx.body = {
      data: {
        token: getService('token').createJwtToken(user),
        user: getService('user').sanitizeUser(user),
      },
    } satisfies ResetPassword.Response;
  },

  logout(ctx: Context) {
    const sanitizedUser = getService('user').sanitizeUser(ctx.state.user);
    strapi.eventHub.emit('admin.logout', { user: sanitizedUser });
    ctx.body = { data: {} };
  },
};
