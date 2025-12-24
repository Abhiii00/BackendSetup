module.exports = (schema, key = 'body') => (req, res, next) => {
    const { error, value } = schema.validate(req[key]);
    if (error) return res.status(400).json({ success: false, message: error.details[0].message.replace(/"/g, '') });
    req[key] = value;
    next();
};
