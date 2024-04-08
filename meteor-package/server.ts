import { Meteor } from "meteor/meteor";
import { Random } from "meteor/random";
import { Match, check } from "meteor/check";
import twofactor from "node-2fa";
import { Accounts } from "meteor/accounts-base";

export type TwoFactorMethodData = {
  type: string; // email | sms
  value: string;
};

export type TwoFactorMethod = TwoFactorMethodData & {
  _id: string;
  secret: string;
  enabled: boolean;
};

// register event listener on Accounts to handle sending 2fa tokens
Accounts._send2FATokenHandlers = [];
Accounts.registerSend2FATokenHandler = function (type, handler) {
  this._send2FATokenHandlers.push({ type, handler });
};

const getSecret = (user: Meteor.User, method: TwoFactorMethodData) => {
  if (!user.services?.twoFactorAuthentication) {
    return;
  }
  const foundMethod = user.services.twoFactorAuthentication.methods?.find(
    (m) => m.type === method.type && m.value === method.value
  );
  if (foundMethod) {
    return foundMethod.secret;
  }
};

const generateSecret = (methodData: TwoFactorMethodData, user: Meteor.User) => {
  const name = `${methodData.type}-${methodData.value}`;
  const { secret } = twofactor.generateSecret({
    name,
    account: user.username || user._id,
  });
  return secret;
};

const checkToken = ({
  token,
  user,
  methodId,
  minutes,
}: {
  token: string;
  user: Meteor.User;
  methodId: string;
  minutes?: number; // number of minutes
}) => {
  const method = user?.services?.twoFactorAuthentication?.methods?.find(
    (m) => m._id === methodId
  );
  if (!method) {
    throw new Error(`Method was not found`);
  }
  // validate token
  if (!method.secret) {
    throw new Error(`Method was not installed correctly`);
  }
  return twofactor.verifyToken(method.secret, token, minutes)?.delta === 0;
};

Meteor.methods({
  async "2fa.disableMethod"({
    methodId,
    removed,
  }: {
    methodId: string;
    removed?: boolean;
  }) {
    check(methodId, String);
    check(removed, Match.Maybe(Boolean));

    const user = Meteor.user();
    if (!user) {
      throw new Error(`User not logged in`);
    }

    if (!removed) {
      await Meteor.users.updateAsync(
        {
          _id: user._id,
          "services.twoFactorAuthentication.methods._id": methodId,
        },
        {
          $set: {
            "services.twoFactorAuthentication.methods.$.enabled": false,
          },
        }
      );
    } else {
      await Meteor.users.updateAsync(
        {
          _id: user._id,
        },
        {
          $pull: {
            "services.twoFactorAuthentication.methods": { _id: methodId },
          },
        }
      );
    }
  },
  async "2fa.enableMethod"({
    methodId,
    token,
  }: {
    methodId: string;
    token: string;
  }) {
    const user = Meteor.user();
    if (!user) {
      throw new Error(`User not logged in`);
    }

    if (!checkToken({ token, user, methodId })) {
      throw new Error(`Invalid token`);
    }

    await Meteor.users.updateAsync(
      {
        _id: user._id,
        "services.twoFactorAuthentication.methods._id": methodId,
      },
      {
        $set: {
          "services.twoFactorAuthentication.methods.$.enabled": true,
        },
      }
    );
  },
  async "2fa.addMethod"({
    method,
    sendToken = true,
  }: {
    method: TwoFactorMethodData;
    sendToken?: boolean;
  }) {
    // validate input
    check(sendToken, Boolean);
    check(method, Object);
    check(method.type, String);
    check(method.value, String);

    const user = Meteor.user();
    if (!user) {
      throw new Error(`User not logged in`);
    }

    // check if method already exists
    const existingMethod =
      user.services?.twoFactorAuthentication?.methods?.find(
        (m) => m.type === method.type && m.value === method.value
      );
    if (existingMethod) {
      throw new Error(`Method already exists`);
    }

    // generate secret
    const secret = generateSecret(method, user);

    const newMethod: TwoFactorMethod = {
      _id: Random.id(),
      ...method,
      secret,
      enabled: false,
    };

    // add method
    await Meteor.users.updateAsync(
      { _id: user._id },
      {
        $push: {
          "services.twoFactorAuthentication.methods": newMethod,
        },
      }
    );

    if (!sendToken) {
      return newMethod._id;
    }

    // generate token
    const token = twofactor.generateToken(secret);
    if (!token) {
      throw new Error(`Unable to generate token`);
    }

    // send token, go through Accounts._send2FATokenHandlers and find the one with type equals method.type
    const sendTokenHandler = Accounts._send2FATokenHandlers.find(
      (item) => item.type === method.type
    );
    if (!sendTokenHandler) {
      throw new Error(`Unable to send token, Handler was not found`);
    }
    await sendTokenHandler.handler({ user, token: token.token, method });

    return newMethod._id;
  },
});
