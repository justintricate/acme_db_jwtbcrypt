const Sequelize = require("sequelize");
const jwt = require("jsonwebtoken");
const { STRING } = Sequelize;
require("dotenv").config();
const bcrypt = require("bcrypt");
const SALT_COUNT = 2;
const SECRET_KEY = process.env.jwt;
const config = {
  logging: false,
};

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || "postgres://localhost/acme_db",
  config
);

const User = conn.define("user", {
  username: STRING,
  password: STRING,
});

User.byToken = async (token) => {
  try {
    const verifyGood = jwt.verify(token, SECRET_KEY);
    if (verifyGood) {
      const user = await User.findOne({ where: { id: verifyGood.username } });
      return user;
    }
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
    },
  });

  const passIsCorrect = await bcrypt.compare(password, user.password);

  if (user && passIsCorrect) {
    return jwt.sign({ username: user.id }, SECRET_KEY);
  }
  const error = Error("bad credentials");
  error.status = 401;
  throw error;
};

User.beforeCreate(async (user, options) => {
  const hashedPW = await bcrypt.hash(user.password, SALT_COUNT);
  user.password = hashedPW;
});

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: "lucy", password: "lucy_pw" },
    { username: "moe", password: "moe_pw" },
    { username: "larry", password: "larry_pw" },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
  },
};
