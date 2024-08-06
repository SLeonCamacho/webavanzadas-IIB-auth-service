const express = require('express');
const { register, login, getUserByEmail, getUserNameByEmail, getUserIDByEmail, validateUser  } = require('../controllers/authController');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/user/email/:email', getUserByEmail);
router.get('/user/name/:email', getUserNameByEmail);
router.get('/user/id/:email', getUserIDByEmail);
router.get('/validate-user/:id', validateUser);

module.exports = router;
