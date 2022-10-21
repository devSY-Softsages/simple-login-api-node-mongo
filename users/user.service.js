const config = require("config.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("_helpers/db");
const User = db.User;
const requestIP = require("request-ip");

module.exports = {
  authenticate,
  getAll,
  getById,
  create,
  update,
  delete: _delete,
  logout,
  audit,
};

async function authenticate(req) {
  const { username, password } = req.body;
  console.log(req.body);
  const ipAddress = requestIP.getClientIp(req);
  const user = await User.findOne({ username });
  const loginTime = Date.now();
  const options = { upsert: true };
  const update = {
    loginTime: loginTime,
    ipAddress: ipAddress,
  };
  const query = {
    username: username,
  };
  console.log(user);
  if (user && bcrypt.compareSync(password, user.hash)) {
    const { hash, ...userWithoutHash } = user.toObject();
    const token = jwt.sign({ sub: user.id }, config.secret);
    User.updateOne(query, update, options, function (err, affected, resp) {
      if (err) {
        throw err;
      }
    });
    if (user.role === "Auditor") {
      const role = user.role;
      return {
        role,
        ...userWithoutHash,
        token,
      };
    } else {
      return {
        ...userWithoutHash,
        token,
      };
    }
  }
}

async function getAll() {
  return await User.find().select("-hash");
}

async function getById(id) {
  return await User.findById(id).select("-hash");
}

async function create(userParam) {
  // validate
  if (await User.findOne({ username: userParam.username })) {
    throw 'Username "' + userParam.username + '" is already taken';
  }

  const user = new User(userParam);

  // hash password
  if (userParam.password) {
    user.hash = bcrypt.hashSync(userParam.password, 10);
  }

  // save user
  await user.save(); // ??
}

async function update(id, userParam) {
  const user = await User.findById(id);

  // validate
  if (!user) throw "User not found";
  if (
    user.username !== userParam.username &&
    (await User.findOne({ username: userParam.username }))
  ) {
    throw 'Username "' + userParam.username + '" is already taken';
  }

  // hash password if it was entered
  if (userParam.password) {
    userParam.hash = bcrypt.hashSync(userParam.password, 10);
  }

  // copy userParam properties to user
  Object.assign(user, userParam);

  await user.save();
}

async function _delete(id) {
  await User.findByIdAndRemove(id);
}

function logout(data) {
  const logoutTime = Date.now();
  const options = { upsert: true };
  const update = {
    logoutTime: logoutTime,
  };
  const query = {
    username: data.username,
  };
  return User.updateOne(query, update, options, function (err, affected, resp) {
    if (err) {
      throw err;
    }
  });
}

async function audit(req) {
  let userId = req.user.sub;
  const user = await User.findById(userId);
  if (user.role === "Auditor") {
    return await User.find(
      { role: { $ne: "Auditor" } },
      { _id: 1, ipAddress: 1, loginTime: 1, logoutTime: 1 }
    );
  } else {
    return { Error: "Your are not a auditor " };
  }
}
