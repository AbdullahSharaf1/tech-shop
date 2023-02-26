const mongoose = require("mongoose");

const connectDatabase = () => {
  mongoose.set("strictQuery", false);

  mongoose.connect(process.env.DB_URI).then((data) => {
    console.log(`Mongodb connected with server:`);
  });
};

module.exports = connectDatabase;
