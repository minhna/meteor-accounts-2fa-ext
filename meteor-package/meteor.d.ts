import { TwoFactorMethod, TwoFactorMethodData } from "./server";
import { Meteor } from "meteor/meteor";

declare module "meteor/meteor" {
  namespace Meteor {
    interface UserServices {
      twoFactorAuthentication?: {
        secret: string;
        type: string;
        methods?: TwoFactorMethod[];
      };
    }
  }
}

export type Send2FATokenHandler = {
  type: string;
  handler: ({
    user,
    token,
    method,
  }: {
    user: Meteor.User;
    token: string;
    method: TwoFactorMethodData;
  }) => Promise<boolean>;
};

declare module "meteor/accounts-base" {
  namespace Accounts {
    var _send2FATokenHandlers: Send2FATokenHandler[];
    function registerSend2FATokenHandler(
      type: string,
      handler: Send2FATokenHandler["handler"]
    ): void;
  }
}
