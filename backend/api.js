const express = require('express');
const router = express.Router();

const authRouter = require('./api-auth').router;
const chatRouter = require('./api-chat');
const threadsRouter = require('./api-threads');

router.use('/auth', authRouter);
router.use('/chat', chatRouter);
router.use('/', threadsRouter);

module.exports = router;
