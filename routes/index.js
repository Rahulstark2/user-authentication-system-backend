const express = require('express');
const authRouter = require("./auth");
const adminRouter = require("./admin");
const userRouter = require("./user");

const router = express.Router();

router.use("/auth", authRouter);
router.use("/admin", adminRouter);
router.use("/user", userRouter);

module.exports = router;