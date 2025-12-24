const express = require('express')
const router = express.Router()
const validate = require('../middleware/validate');
const authMiddleware = require('../middleware/auth');
const { registerSchema, loginSchema } = require('../validations/authValidation');
const authController = require('../controller/auth')

router.post('/register', validate(registerSchema), authController.register)
router.post('/login', validate(loginSchema), authController.login)
router.post('/refreshToken', authController.refreshToken)
router.post('/logout', authMiddleware, authController.logout)



module.exports = router