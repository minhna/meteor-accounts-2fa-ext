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
  lastUsedAt?: Date;
};

// register event listener on Accounts to handle sending 2fa tokens
Accounts._send2FATokenHandlers = [];
Accounts.registerSend2FATokenHandler = function (type, handler) {
  this._send2FATokenHandlers.push({ type, handler });
};

export const generateSecret = (
  methodData: TwoFactorMethodData,
  user: Meteor.User
) => {
  const name = `${methodData.type}-${methodData.value}`;
  const { secret } = twofactor.generateSecret({
    name,
    account: user.username || user._id,
  });
  return secret;
};

export const checkToken = ({
  token,
  user,
  methodId,
  windows = 2,
}: {
  token: string;
  user: Meteor.User;
  methodId: string;
  windows?: number; // number of windows to check. Each window is 30 seconds
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
  return twofactor.verifyToken(method.secret, token, windows) !== null;
};

export const sendToken = async ({
  user,
  method,
  token,
}: {
  user: Meteor.User;
  method: TwoFactorMethod;
  token: string;
}) => {
  // send token, go through Accounts._send2FATokenHandlers and find the one with type equals method.type
  const sendTokenHandler = Accounts._send2FATokenHandlers.find(
    (item) => item.type === method.type
  );
  if (!sendTokenHandler) {
    throw new Error(`Unable to send token, Handler was not found`);
  }
  const sent = await sendTokenHandler.handler({
    user,
    token,
    method,
  });
  if (sent) {
    // update method lastUsedAt
    await Meteor.users.updateAsync(
      {
        _id: user._id,
        "services.twoFactorAuthentication.methods._id": method._id,
      },
      {
        $set: {
          "services.twoFactorAuthentication.methods.$.lastUsedAt": new Date(),
        },
      }
    );
  }

  return sent;
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
    send = true,
  }: {
    method: TwoFactorMethodData;
    send?: boolean;
  }) {
    // validate input
    check(send, Boolean);
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

    if (!send) {
      return newMethod._id;
    }

    // generate token
    const token = twofactor.generateToken(secret);
    if (!token) {
      throw new Error(`Unable to generate token`);
    }

    await sendToken({ user, method: newMethod, token: token.token });

    return newMethod._id;
  },
  async "2fa.getEnabledMethods"() {
    const user = Meteor.user();
    if (!user) {
      throw new Error(`User not logged in`);
    }

    const enableMethods =
      user.services?.twoFactorAuthentication?.methods?.filter((m) => m.enabled);

    // only return _id, type, and partially value
    return enableMethods?.map((m) => ({
      _id: m._id,
      type: m.type,
      value: m.value.slice(0, 3) + "*".repeat(m.value.length - 3),
    }));
  },
  async "2fa.sendToken"({ methodId }: { methodId: string }) {
    check(methodId, String);

    const user = Meteor.user();
    if (!user) {
      throw new Error(`User not logged in`);
    }

    const method = user.services?.twoFactorAuthentication?.methods?.find(
      (m) => m._id === methodId && m.enabled
    );
    if (!method) {
      throw new Error(`Method not found`);
    }

    // TODO: check lastUsedAt, we may want to put a time limit between sending tokens
    const token = twofactor.generateToken(method.secret);
    if (!token) {
      throw new Error(`Unable to generate token`);
    }

    return sendToken({ user, method, token: token.token });
  },
});
